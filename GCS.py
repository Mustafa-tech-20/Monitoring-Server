from google.cloud import storage
import traceback
import os
from dotenv import load_dotenv

load_dotenv()

def upload_attachment_to_gcs(file_data, filename, candidate_id, candidate_name):
    """
    Uploads a file's binary data to Google Cloud Storage under a folder
    named after the candidate, and returns its public URL.
    """
    bucket_name = os.getenv("GCS_BUCKET_NAME")
    if not bucket_name:
        print("  -> !!! GCS_BUCKET_NAME environment variable not set. Cannot upload.")
        return None

    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        
        # --- THIS IS THE NEW PATH LOGIC ---
        # 1. Sanitize the candidate's name to be a valid path segment.
        #    Replace spaces with underscores and remove other invalid characters.
        sanitized_name = "".join(c for c in candidate_name if c.isalnum() or c in (' ',)).replace(' ', '_')
        
        # 2. Sanitize the filename itself.
        sanitized_filename = "".join(c for c in filename if c.isalnum() or c in ('.', '_', '-')).rstrip()
        
        # 3. Construct the new, more readable path.
        #    e.g., "candidate_attachments/Mustafa_Mohammed/Invoice-4R64HE4W-0007.pdf"
        blob_name = f"candidate_attachments/{sanitized_name}/{sanitized_filename}"
        
        blob = bucket.blob(blob_name)

        print(f"  -> Uploading {filename} to GCS bucket '{bucket_name}' at '{blob_name}'...")
        
        blob.upload_from_string(file_data)
        
        print(f"  -> Upload successful. Public URL: {blob.public_url}")
        return blob.public_url

    except Exception as e:
        print(f"  -> !!! FAILED to upload {filename} to GCS: {e}")
        traceback.print_exc()
        return None