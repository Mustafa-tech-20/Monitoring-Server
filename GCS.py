from google.cloud import storage
import traceback
import os
from dotenv import load_dotenv
from datetime import datetime, timezone

load_dotenv()

def upload_attachment_to_gcs(file_data, original_filename, candidate_id, candidate_name):
    """
    Uploads a file's binary data to Google Cloud Storage.
    Prevents duplicate filenames for the same candidate.
    """
    bucket_name = os.getenv("GCS_BUCKET_NAME")
    if not bucket_name:
        print("  -> !!! GCS_BUCKET_NAME environment variable not set. Cannot upload.")
        return None

    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        
        # Sanitize the candidate name for the folder path first
        sanitized_name = "".join(c for c in candidate_name if c.isalnum() or c in (' ',)).replace(' ', '_')

        # Extract name and extension
        name_part, extension = os.path.splitext(original_filename)
        versioned_filename = f"{name_part}{extension}"  # no timestamp, exact match check

        # Full path in GCS
        blob_name = f"candidate_attachments/{sanitized_name}/{versioned_filename}"

        # --- DUPLICATE CHECK ---
        existing_blob = bucket.blob(blob_name)
        if existing_blob.exists():
            print(f"  -> !!! File '{versioned_filename}' already exists for {candidate_name}. Skipping upload.")
            return None  
        
        # Upload file
        blob = bucket.blob(blob_name)
        print(f"  -> Uploading '{original_filename}' as '{versioned_filename}' to GCS...")
        blob.upload_from_string(file_data)

        print(f"  -> Upload successful. Public URL: {blob.public_url}")
        return blob.public_url

    except Exception as e:
        print(f"  -> !!! FAILED to upload {original_filename} to GCS: {e}")
        traceback.print_exc()
        return None
