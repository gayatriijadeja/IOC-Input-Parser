import email
import os
import re
from email import policy
from email.parser import BytesParser

def extract_fanged_ip(body_content):
    # Define the regex pattern for matching fanged IP addresses
    fanged_ip_pattern = re.compile(r'\b\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}\b')

    # Find the fanged IP address
    match = re.search(fanged_ip_pattern, body_content)

    if match:
        return match.group(0)
    else:
        return None

# Example usage:
email_body = "This is the email body containing the IP 69[.]197[.]134[.]103."

# Extract the fanged IP from the body
fanged_ip = extract_fanged_ip(email_body)

# Print the fanged IP
if fanged_ip:
    print("Fanged IP:", fanged_ip)
else:
    print("Fanged IP not found in the email body.")


def extract_body_from_eml(file_path):
    with open(file_path, 'rb') as file:
        # Parse the email message
        msg = BytesParser(policy=policy.default).parse(file)

        # Extract the plain text body
        body = extract_text_body(msg)

        return body

def extract_text_body(msg):
    if msg.is_multipart():
        # If the message is multipart, iterate over its parts
        for part in msg.iter_parts():
            # Extract text/plain part
            if part.get_content_type() == 'text/plain':
                return part.get_payload(decode=True).decode(part.get_content_charset(), 'ignore')
    else:
        # If the message is not multipart, return the plain text content
        return msg.get_payload(decode=True).decode(msg.get_content_charset(), 'ignore')

# Example usage:
eml_file_path = 'ioc1.eml'
body_content = extract_body_from_eml(eml_file_path)



def extract_fanged_ip(body_content):
    # Define the regex pattern for matching fanged IP addresses
    fanged_ip_pattern = re.compile(r'\b\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}\b')

    # Find the fanged IP address
    match = re.search(fanged_ip_pattern, body_content)

    if match:
        return match.group(0)
    else:
        return None

# Example usage:
email_body = body_content

# Extract the fanged IP from the body
fanged_ip = extract_fanged_ip(email_body)

# Print the fanged IP
if fanged_ip:
    print("Fanged IP:", fanged_ip)
else:
    print("Fanged IP not found in the email body.")


# Print the extracted body content
# print("Extracted Body Content:")
# print(body_content)


