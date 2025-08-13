#import all required
import base64
from email.utils import parseaddr



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
    Extracts the subject and body from an email message.
    Returns a dictionary {'subject': subject, 'body': body}.
    Values can be None if not found.
    """
    details = {'subject': None, 'body': None}
    payload = msg_detail.get('payload', {})
    headers = payload.get('headers', [])

    # Extract Subject
    try:
        subject_header = next((h['value'] for h in headers if h['name'].lower() == 'subject'), None)
        if subject_header:
            details['subject'] = subject_header
    except Exception as e:
        print(f"  -> Error finding subject: {e}")

    # Extract Body (prioritizing plain text)
    try:
        body_data = None
        if 'parts' in payload:
            for part in payload['parts']:
                if part.get('mimeType') == 'text/plain':
                    body_data = part.get('body', {}).get('data')
                    break # Found plain text, stop looking
            if not body_data: # Fallback to HTML if no plain text
                for part in payload['parts']:
                    if part.get('mimeType') == 'text/html':
                        body_data = part.get('body', {}).get('data')
                        break
        elif 'body' in payload:
            body_data = payload.get('body', {}).get('data')

        if body_data:
            details['body'] = base64.urlsafe_b64decode(body_data).decode('utf-8')

    except Exception as e:
        print(f"  -> Error decoding email body: {e}")
    
    return details

