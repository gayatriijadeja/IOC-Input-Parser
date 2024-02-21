import email
import email.encoders


def encode_email_headers(email_message):
    for header in [
        "Delivered-To",
        "Received",
        "ARC-Authentication-Results",
        "Return-Path",
        "Received-SPF",
        "Authentication-Results",
        "From",
        "To",
        "Cc",
    ]:
        header_value = email_message[header]
        if isinstance(header_value, bytes):
            header_value = header_value.decode("utf-8")
        if any(char in header_value for char in ["<", ">"]):
            email.encoders.encode_base64(email_message[header])


def process_email_file(email_filename):
    with open(email_filename, "r") as file:
        msg = email.message_from_file(file)

    encode_email_headers(msg)

    return msg


email_filename = "ioc1.eml"
email_message = process_email_file(email_filename)

# Print the encoded headers
# print("From:", email_message["From"])
# print("To:", email_message["To"])
# print("Subject:", email_message["Subject"])
