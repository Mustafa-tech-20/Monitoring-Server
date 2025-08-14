#import all required
import base64
from email.utils import parseaddr


ALLOWED_MIME_TYPES = {
    # Documents
    'application/pdf',  # .pdf
    'application/msword',  # .doc
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',  # .docx

    # Images
    'image/jpeg', # .jpg, .jpeg
    'image/png',   # .png
}

def get_sender_from_message(msg_detail):
    """Parses the 'From' header to get the sender's email address."""
    try:
        headers = msg_detail['payload']['headers']
        from_header = next(h['value'] for h in headers if h['name'].lower() == 'from')
        sender_email = parseaddr(from_header)[1]
        return sender_email
    except (KeyError, StopIteration):
        return None
    


def parse_email_details(msg_detail):
    """
    Extracts the subject, body, and attachment info from an email message.
    It recursively searches through email parts to handle complex structures.
    Returns a dictionary {'subject': str, 'body': str, 'attachments': list}.
    """
    details = {'subject': None, 'body': None, 'attachments': []}
    payload = msg_detail.get('payload', {})
    headers = payload.get('headers', [])

    # 1. Extract Subject from top-level headers
    try:
        details['subject'] = next((h['value'] for h in headers if h['name'].lower() == 'subject'), None)
    except Exception as e:
        print(f"  -> Error finding subject: {e}")

    # 2. Start the recursive search for body and attachments
    plain_text, html_text = _find_body_and_attachments(payload, details['attachments'])
    
    # 3. Prioritize plain text, but fallback to HTML
    details['body'] = plain_text or html_text
    
    return details

def _find_body_and_attachments(payload, attachments_list):
    """A recursive helper to dive into multipart messages."""
    plain_text_body = None
    html_body = None
    
    try:
        # If the payload has parts, dive into them
        if 'parts' in payload:
            for part in payload.get('parts', []):
                # Recursively call this function for nested parts
                plain, html = _find_body_and_attachments(part, attachments_list)
                if plain and not plain_text_body:
                    plain_text_body = plain
                if html and not html_body:
                    html_body = html
        
        # If no parts, process the current payload/part itself
        else:
            mime_type = payload.get('mimeType')
            body = payload.get('body', {})
            data = body.get('data')

            if data:
                decoded_data = base64.urlsafe_b64decode(data).decode('utf-8')
                if mime_type == 'text/plain':
                    plain_text_body = decoded_data
                elif mime_type == 'text/html':
                    html_body = decoded_data

        # Check for attachments at the current level, regardless of parts
        filename = payload.get('filename')
        attachment_id = payload.get('body', {}).get('attachmentId')
        if filename and attachment_id:
            attachments_list.append({
                'filename': filename,
                'mime_type': payload.get('mimeType'),
                'attachment_id': attachment_id,
                'size': payload.get('body', {}).get('size', 0)
            })
            
    except Exception as e:
        print(f"  -> Error while parsing part: {e}")
        
    return plain_text_body, html_body