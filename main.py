import os
import io
import base64
import traceback
import asyncio
import secrets
import traceback
import base64
import certifi

from contextlib import asynccontextmanager
from email.utils import parseaddr
from pymongo import MongoClient 
from bson import ObjectId
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from google.auth.transport.requests import Request as GoogleAuthRequest
from email_functions import parse_email_details, get_sender_from_message , ALLOWED_MIME_TYPES
from GCS import upload_attachment_to_gcs
from config import SCOPES, TOKEN_FILE, CREDENTIALS_FILE


# IMPORTANT: This line MUST be before any google_auth_oauthlib imports.
# In production, you must use HTTPS.
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


load_dotenv()


# --- Global State (for simplicity in this single-user example) ---
creds: Credentials | None = None
gmail_poller_task: asyncio.Task | None = None
oauth_state: str | None = None
mongo_client: MongoClient | None = None


def save_token(current_creds: Credentials):
    with open(TOKEN_FILE, 'w') as token:
        token.write(current_creds.to_json())
    print("Token saved successfully.")

def load_token():

    global creds
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if creds and creds.expired and creds.refresh_token:
        print("Refreshing expired token...")
        try:
            creds.refresh(GoogleAuthRequest())
            save_token(creds)
        except Exception as e:
            print(f"Error refreshing token: {e}")
            creds = None # Invalidate credentials if refresh fails
            if os.path.exists(TOKEN_FILE):
                os.remove(TOKEN_FILE) # Remove bad token file


def get_allowed_senders_from_mongo():

    if not mongo_client:
        print("Skipping sender fetch: no active MongoDB connection.")
        return [] # Return an empty list, which is iterable

    print("Fetching active candidate records from MongoDB...")
    
    try:
        db, collection = get_db_collection()
        
        active_reply_statuses = [
            "Onboarding_Email_Sent",
            "Followup_Email1_Sent",
            "Followup_Email2_Sent",
            "Followup_Email3_Sent",
        ]
        
        query_filter = {
            "$or": [
                {"status": {"$regex": f"^{status}$", "$options": "i"}} for status in active_reply_statuses
            ]
        }
        
        # We need the full document to get _id, Email, created_at, etc.
        # The .find() method returns a cursor, which we convert to a list of dictionaries.
        active_candidates = list(collection.find(query_filter))

        print(f"Successfully fetched {len(active_candidates)} active candidate records.")
        return active_candidates
    except Exception as e:
        print(f"!!! CRITICAL: Could not fetch allowed senders from MongoDB: {e}")
        traceback.print_exc()
        return [] # Return an empty list on error

def process_candidate_followups():

    if not mongo_client:
        print("Skipping follow-up processing: no active MongoDB connection.")
        return

    print("Processing candidate follow-up logic...")
    
    followup_stages = [
        ("Onboarding_Email_Sent", "Followup_Email1_Sent", timedelta(minutes=2)),
        ("Followup_Email1_Sent", "Followup_Email2_Sent", timedelta(minutes=5)),
        ("Followup_Email2_Sent", "Followup_Email3_Sent", timedelta(minutes=7)),
    ]
    active_statuses = [stage[0] for stage in followup_stages]

    try:
        db, collection = get_db_collection()
        candidates_to_check = list(collection.find({"status": {"$in": active_statuses}}))
        
        if not candidates_to_check:
            print("No candidates in active follow-up states.")
            return

        print(f"Found {len(candidates_to_check)} candidates to check for follow-ups.")
        now = datetime.now(timezone.utc)

        for candidate in candidates_to_check:
            candidate_id = candidate["_id"]
            current_status = candidate.get("status")
            created_at_naive = candidate.get("created_at")

            if not created_at_naive:
                print(f"  -> Skipping candidate {candidate_id}: missing 'created_at' field.")
                continue

            created_at_aware = created_at_naive.replace(tzinfo=timezone.utc)
            
            for current_stage, next_stage, delay in followup_stages:
                if current_status == current_stage:
                    if now > (created_at_aware + delay):
                        print(f"  -> Triggering follow-up for candidate {candidate_id}...")
                        
                        # --- THIS IS THE INTEGRATION LOGIC ---
                        # Get candidate details for the email.
                        candidate_email = candidate.get("Email")
                        candidate_name = candidate.get("First Name", "Candidate") # Default to "Candidate" if no first name
                        
                        # Extract the number from the stage name (e.g., "Followup_Email1_Sent" -> "1")
                        follow_up_number = ''.join(filter(str.isdigit, next_stage)) or '1'
                        
                        if not candidate_email:
                            print(f"  -> Skipping candidate {candidate_id}: missing 'Email' field.")
                            break

                        # Attempt to send the email
                        email_sent_successfully = send_follow_up_email(
                            candidate_email,
                            candidate_name,
                            follow_up_number
                        )

                        # Only update the status in the database IF the email was sent successfully.
                        if email_sent_successfully:
                            collection.update_one(
                                {"_id": candidate_id},
                                {"$set": {"status": next_stage}}
                            )
                            print(f"  -> Status for {candidate_id} updated to '{next_stage}'.")
                        else:
                            print(f"  -> Status for {candidate_id} NOT updated due to email sending failure.")
                        
                    break

    except Exception as e:

        print(f"!!! CRITICAL: An error occurred during follow-up processing: {e}")
        traceback.print_exc()

def send_follow_up_email(candidate_email, candidate_name, follow_up_number):

    service = get_gmail_service()

    if not service:

        print("  -> Cannot send email: Gmail service is not available.")
        return False

    try:

        # 1. Define the email content
        subject = f"Follow-up ({follow_up_number}/3): Regarding Your Onboarding"

        body = f"""
Dear {candidate_name},

This is a friendly follow-up regarding the onboarding process.

We are waiting for you to reply to the previous onboarding email with the required documents. Please find the original email in your inbox and reply directly to it at your earliest convenience.

If you have any questions or have already sent the documents, please let us know by replying to this email.

Best regards,
NextLeap Onboarding Team
                """

        # 2. Create the email message object
        message = MIMEText(body)
        message['to'] = candidate_email
        message['from'] = 'me'  # The authenticated user's email address
        message['subject'] = subject

        # 3. Encode the message in the format required by the Gmail API
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        message_payload = {'raw': raw_message}

        # 4. Send the email
        sent_message = service.users().messages().send(
            userId='me',
            body=message_payload
        ).execute()

        print(f"  -> Successfully sent follow-up email to {candidate_email}. Message ID: {sent_message['id']}")
        return True

    except Exception as e:
        print(f"  -> !!! FAILED to send email to {candidate_email}: {e}")
        traceback.print_exc()
        return False
    


def get_gmail_service():
    """Returns an authenticated Gmail service client."""
    if not (creds and creds.valid):
        return None
    return build('gmail', 'v1', credentials=creds)

def _find_or_create_folder(drive_service, folder_name, parent_id='root'):

    # The query now correctly uses the parent_id, which defaults to 'root'.
    query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false and '{parent_id}' in parents"
    
    response = drive_service.files().list(q=query, spaces='drive', fields='files(id)').execute()
    files = response.get('files', [])
    
    if files:
        # Folder found, return its ID
        return files[0].get('id')
    else:
        # Folder not found, create it
        file_metadata = {
            'name': folder_name,
            'mimeType': 'application/vnd.google-apps.folder',
            'parents': [parent_id] # Explicitly set the parent
        }
            
        folder = drive_service.files().create(body=file_metadata, fields='id').execute()
        print(f"  -> Created Drive folder '{folder_name}' with ID: {folder.get('id')}")
        return folder.get('id')

def upload_attachment_to_drive(creds, file_data, original_filename, candidate_name):

    # Check credentials
    if not (creds and creds.valid):
        print("  -> Cannot upload to Drive: Invalid credentials provided.")
        return None

    try:
        # Build Drive service
        drive_service = build('drive', 'v3', credentials=creds)

        # Find or create root folder for attachments
        parent_folder_id = _find_or_create_folder(drive_service, "candidate_attachments")

        # Sanitize candidate folder name
        sanitized_name = "".join(c for c in candidate_name if c.isalnum() or c in (' ',)).replace(' ', '_')
        candidate_folder_id = _find_or_create_folder(drive_service, sanitized_name, parent_id=parent_folder_id)

        # Use exact original filename (no timestamp) for duplicate checking
        name_part, extension = os.path.splitext(original_filename)
        final_filename = f"{name_part}{extension}"

        # --- DUPLICATE CHECK ---
        query = f"'{candidate_folder_id}' in parents and name = '{final_filename}' and trashed = false"
        results = drive_service.files().list(q=query, fields="files(id, webViewLink)").execute()
        files = results.get('files', [])

        if files:
            print(f"  -> !!! File '{final_filename}' already exists for {candidate_name} in Drive. Skipping upload.")
            return None  # Prevents duplicate DB entries

        # Prepare metadata & upload
        file_metadata = {'name': final_filename, 'parents': [candidate_folder_id]}
        media = MediaIoBaseUpload(io.BytesIO(file_data), mimetype='application/octet-stream', resumable=True)

        print(f"  -> Uploading '{original_filename}' as '{final_filename}' to Google Drive...")
        file = drive_service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id, webViewLink'
        ).execute()

        print(f"  -> Drive upload successful. Link: {file.get('webViewLink')}")
        return file.get('webViewLink')

    except Exception as e:
        print(f"  -> !!! FAILED to upload {original_filename} to Drive: {e}")
        traceback.print_exc()
        return None

async def poll_inbox():
    """Periodically checks for unread emails AND processes candidate follow-ups."""
    print("Starting inbox poller. Will fetch allowed senders from MongoDB each cycle.")
    service = get_gmail_service()
    if not service:
        print("Cannot start poller: Gmail service not available.")
        return

    processed_message_ids = set()
    while True:

        try:
            # 1. Process time-based follow-ups first.
            
            
            # 2. Get the list of candidates we need to check for replies.
            senders_to_check = get_allowed_senders_from_mongo()
            if not senders_to_check:
                print("No active candidates to check for email replies in this cycle.")
            else:
                # --- START OF NEW PER-CANDIDATE POLLING LOGIC ---
                print(f"Checking for replies from {len(senders_to_check)} active candidates...")
                
                # Loop through each candidate and build a specific query for them.
                for candidate in senders_to_check:

                    candidate_id = candidate["_id"]
                    email = candidate.get("Email")
                    created_at = candidate.get("created_at")

                    first_name = candidate.get("First Name", "")
                    last_name = candidate.get("Last Name", "")
                    candidate_name = f"{first_name} {last_name}".strip() or "Unknown_Candidate"

                    if not all([email, created_at,candidate_id]):
                        continue
                    # Convert the created_at datetime to a Unix timestamp for the Gmail API query.
                    after_timestamp = int(created_at.timestamp())
                    
                    # Build a specific query for this sender after their creation time.
                    gmail_query = f"is:unread from:{email} after:{after_timestamp}"
                    print(f"  -> Querying Gmail with: '{gmail_query}'")

                    # Execute the API call for this single candidate.
                    response = service.users().messages().list(userId='me', q=gmail_query).execute()
                    messages = response.get('messages', [])

                    if not messages:
                        # No new replies from this specific person.
                        continue

                    # If we found messages, process them.
                    for msg_summary in messages:
                        msg_id = msg_summary['id']
                        if msg_id in processed_message_ids:
                            continue

                        # We already know the sender, but we can confirm it.
                        print(f"Found new reply from '{email}' (message ID: {msg_id})")
                        
                        msg_detail = service.users().messages().get(userId='me', id=msg_id).execute()
                        email_data = parse_email_details(msg_detail)
                        
                        # Log the content
                        print("----------------- EMAIL START -----------------")
                        print(f"Subject: {email_data['subject'] or '[No Subject Found]'}")
                        print("---")
                        print(email_data['body'] or "[No Body Content Found]")
                        print("------------------ EMAIL END ------------------")
                        
                        if email_data['attachments']:
                            print("---")
                            print(f"Found {len(email_data['attachments'])} attachment(s):")

                            for attachment_info in email_data['attachments']:

                                if attachment_info['mime_type'] not in ALLOWED_MIME_TYPES:
                                    print(f"  -> SKIPPING attachment '{attachment_info['filename']}'. "
                                          f"MIME type '{attachment_info['mime_type']}' is not allowed.")
                                    
                                    continue 

                                # 1. Download attachment data from Gmail
                                attachment_response = service.users().messages().attachments().get(
                                    userId='me', messageId=msg_id, id=attachment_info['attachment_id']
                                ).execute()
                                file_data_b64 = attachment_response.get('data')

                                if file_data_b64:
                                    file_data = base64.urlsafe_b64decode(file_data_b64.encode('UTF-8'))
                                    
                                    # 2. Upload to GCS and get the public URL
                                    gcs_url = upload_attachment_to_gcs(
                                        file_data,
                                        attachment_info['filename'],
                                        candidate_id,
                                        candidate_name 
                                    )

                                    #upload to drive

                                    drive_url = upload_attachment_to_drive(
                                        creds,
                                        file_data,
                                        attachment_info['filename'],
                                        candidate_name
                                    )

                                    # 3. If upload was successful, link the URL in MongoDB
                                    if (gcs_url or drive_url) and mongo_client:
                                        attachment_record = {
                                            "gcs_url": gcs_url,
                                            "drive_url": drive_url,
                                            "filename": attachment_info['filename'],
                                            "size_bytes": attachment_info['size'],
                                            "received_at": datetime.now(timezone.utc)
                                        }
                                        _, collection = get_db_collection()
                                        #change status to Documents_Received
                                        # and push the attachment record to the candidate's attachments array.
                                        collection.update_one(
                                            {"_id": ObjectId(candidate_id)},
                                            {
                                                "$set": {"status": "Documents_Received"},
                                                "$push": {"attachments": attachment_record}
                                            }
                                        )
                                        print(f"  -> Successfully linked GCS and drive attachment to candidate {candidate_id}")

                        # Update the candidate's status in the database to stop follow-ups.
                        if mongo_client:
                            _, collection = get_db_collection()

                            # dont change the status if it is Documents_Received
                            result = collection.update_one(
                                {
                                    "Email": {"$regex": f"^{email}$", "$options": "i"},
                                    "status": {"$ne": "Documents_Received"}  # only update if status is NOT Documents_Received
                                },
                                {
                                    "$set": {"status": "Reply_received_from_candidate"}
                                }
                            )

                            if result.modified_count > 0:
                                print(f"  -> Status for {email} updated to 'Reply_received_from_candidate'.")

                        # Add the message ID to our processed set.
                        processed_message_ids.add(msg_id)
                # --- END OF NEW PER-CANDIDATE POLLING LOGIC --
            process_candidate_followups()

        except Exception as e:
            print(f"!!! An unhandled error occurred in the polling loop: {e}")
            traceback.print_exc()
            if 'invalid_grant' in str(e).lower() or 'credentials has been revoked' in str(e).lower():
                print("!!! Authentication error. Token is invalid. Stopping poller.")
                break
            print("--- Continuing to next polling cycle after error. ---")

        print("...Polling cycle finished. Waiting for 60 seconds...")
        await asyncio.sleep(60)


async def start_gmail_poller():
    """Starts the background polling task if not already running."""
    global gmail_poller_task
    if gmail_poller_task and not gmail_poller_task.done():
        print("Poller is already running.")
        return
    gmail_poller_task = asyncio.create_task(poll_inbox())

async def stop_gmail_poller():
    """Stops the background polling task."""
    global gmail_poller_task
    if gmail_poller_task:
        gmail_poller_task.cancel()
        try:
            await gmail_poller_task
        except asyncio.CancelledError:
            print("Inbox poller stopped successfully.")
        gmail_poller_task = None

# --- FastAPI Lifespan and App ---
def get_db_collection():

    if not mongo_client:
        return None, None
    
    db_name = os.getenv("MONGO_DB_NAME")
    collection_name = os.getenv("MONGO_COLLECTION_NAME")
    
    if not db_name or not collection_name:
        print("!!! CRITICAL: MONGO_DB_NAME or MONGO_COLLECTION_NAME not set in .env file.")
        return None, None
        
    db = mongo_client[db_name]
    collection = db[collection_name]
    return db, collection

@asynccontextmanager
async def lifespan(app: FastAPI):

    global mongo_client
    print("Application startup...")

    mongo_uri = os.getenv("MONGO_URI")
    if mongo_uri:
        try:
            print("Connecting to MongoDB...")
            mongo_client = MongoClient(mongo_uri,tlsCAFile=certifi.where(), serverSelectionTimeoutMS=5000)
            # The ismaster command is cheap and does not require auth.
            mongo_client.admin.command('ismaster')
            print("MongoDB connection successful.")
        except Exception as e:
            print(f"!!! CRITICAL: Could not connect to MongoDB on startup: {e}")
            mongo_client = None
    else:
        print("!!! CRITICAL: MONGO_URI not set. Database functions will be disabled.")

    # Load Google token and start poller
    load_token()
    if creds and creds.valid:
        await start_gmail_poller()
    else:
        print("No valid token found. Please authenticate via the /auth endpoint.")
    
    yield
    
    print("Application shutdown...")
    if mongo_client:
        print("Closing MongoDB connection.")
        mongo_client.close()
    
    await stop_gmail_poller()

app = FastAPI(lifespan=lifespan)

@app.get("/", response_class=HTMLResponse)
async def home():
    """Serves the home page."""
    if creds and creds.valid:
        return """
        <html><body>
        <h2>Gmail Poller is Running</h2>
        <p>Check your console for output. The poller is checking for new mail every 60 seconds.</p>
        </body></html>
        """
    else:
        return """
        <html><body>
        <h2>Gmail Poller</h2>
        <p>You need to <a href="/auth">authenticate with Google</a> to start the poller.</p>
        </body></html>
        """

@app.get("/auth")
async def authorize():
    """Redirects the user to Google's OAuth consent screen."""
    global oauth_state
    
    flow = Flow.from_client_secrets_file(
        CREDENTIALS_FILE,
        scopes=SCOPES,
        redirect_uri='http://localhost:8080/callback'
    )
    
    oauth_state = secrets.token_urlsafe(16)
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        prompt='consent',
        state=oauth_state
    )

    return RedirectResponse(authorization_url)

@app.get("/callback")
async def callback(request: Request, state: str | None = None):
    """Handles the redirect back from Google after user consent."""
    global creds, oauth_state
    
    if not state or state != oauth_state:
        return HTMLResponse("<h1>State token does not match. Possible CSRF attack.</h1>", status_code=400)
    oauth_state = None

    flow = Flow.from_client_secrets_file(
        CREDENTIALS_FILE,
        scopes=SCOPES,
        redirect_uri='http://localhost:8080/callback'
    )
    
    flow.fetch_token(authorization_response=str(request.url))
    
    creds = flow.credentials
    save_token(creds)
    await start_gmail_poller()
    
    return RedirectResponse(url='/')