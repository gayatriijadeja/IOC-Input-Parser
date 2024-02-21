import email
import imaplib
import re


# Function to extract and defang IP addresses, domains, and URLs from text
def extract_information_from_text(text):
    ip_pattern = re.compile(r"\b\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}\b")
    domain_pattern = re.compile(r"\b\w+\[.\]\w+\b")
    url_pattern = re.compile(r"\bhttps?://\S+\b")

    fanged_ips = re.findall(ip_pattern, text)
    defanged_ips = [ip.replace("[.]", ".") for ip in fanged_ips]

    domains = re.findall(domain_pattern, text)
    urls = re.findall(url_pattern, text)

    return defanged_ips, domains, urls


# Function to extract information from an email
def process_email(email_message):
    """ """
    subject = email_message["Subject"]
    body_text = ""

    for part in email_message.walk():
        if part.get_content_type() == "text/plain":
            body_text += part.get_payload(decode=True).decode("utf-8", errors="ignore")

    fanged_ips, domains, urls = extract_information_from_text(body_text)

    attachments = []
    for part in email_message.walk():
        if part.get_content_type() == "text/plain" and part.get_filename():
            if part.get_filename().endswith(".txt"):
                attachment_data = part.get_payload(decode=True).decode(
                    "utf-8", errors="ignore"
                )
                attachments.append({"filename": "ioc.eml", "content": attachment_data})

    return {
        "Subject": subject,
        "Fanged IPs": fanged_ips,
        "Domains": domains,
        "URLs": urls,
        "Attachments": attachments,
    }


# Connect to the email server and retrieve emails
mail = imaplib.IMAP4_SSL("smtp.gmail.com")
mail.login("gvjadeja2002@gmail.com", "Gayu2002!")
mail.select("inbox")

status, messages = mail.search(None, "ALL")
message_ids = messages[0].split()

output_data = []

for message_id in message_ids:
    _, msg_data = mail.fetch(message_id, "(RFC822)")
    raw_email = msg_data[0][1]
    email_message = email.message_from_bytes(raw_email)

    extracted_info = process_email(email_message)
    output_data.append(extracted_info)

# Write the extracted information to output.txt
with open("output.txt", "w", encoding="utf-8") as output_file:
    for info in output_data:
        output_file.write(f"Subject: {info['Subject']}\n")
        output_file.write(f"Fanged IPs: {info['Fanged IPs']}\n")
        output_file.write(f"Domains: {info['Domains']}\n")
        output_file.write(f"URLs: {info['URLs']}\n")
        output_file.write("Attachments:\n")
        for attachment in info["Attachments"]:
            output_file.write(f"\tFilename: {attachment['filename']}\n")
            output_file.write(f"\tContent: {attachment['content']}\n")
        output_file.write("\n")

# Logout from the email server
mail.logout()
