import email
import re
import base64
from mongo_wrapper import MongoWrapper
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def extract_info(filename: str) -> dict:
    """Extracts information from a batch of eml files, saves to MongoDB Atlas, and returns a response.

    Request:
        - files (list): List of eml files uploaded as multipart/form-data.

    Response:
        - dictionary:
            - message (str): Success or error message.
            - data (dict, optional): Extracted information if successful.
    """
    results = []
    mongo_wrapper = MongoWrapper("prl-db", "mailInfo")
    try:
        with open(filename, "rb") as fp:
            msg = email.message_from_bytes(fp.read())

            # Extract basic information (sender, subject, time)
            sender = msg["From"]
            subject = msg["Subject"]
            time = msg["Date"]

            # Split body into content and encoded headers/footers
            body_parts = []
            header_footers = []
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type in ["text/plain", "text/html"]:
                    body_parts.append(part.get_payload(decode=True))

            body_content = b"\n".join(body_parts).decode("ISO-8859-1")

            # Extract information from the main body (excluding headers/footers)
            if body_content:
                body_content = body_content.strip()
                ips = list(
                    set(re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", body_content))
                )
                emails = list(
                    set(
                        re.findall(
                            r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,4}",
                            body_content,
                        )
                    )
                )
                domains = list(
                    set(
                        re.findall(
                            r"^((?!-)[A-Za-z0–9-]{1, 63}(?<!-)\.)+[A-Za-z]{2, 6}$",
                            body_content,
                        )
                    )
                )
                urls = list(set(re.findall(r"https?://[^\s]+", body_content)))

                # Combine extracted data with encoded headers/footers
                extracted_data = {
                    "filename": filename,
                    "sender": sender,
                    "subject": subject,
                    "time": time,
                    "body": body_content,
                    "ips": ips,
                    "emails": emails,
                    "urls": urls,
                    "headers_footers": header_footers,
                }

                # Insert extracted data into MongoDB
                if not mongo_wrapper.insert_one(extracted_data):
                    results.append(
                        {"filename": filename, "error": "Failed to save data"}
                    )
                else:
                    results.append(
                        {"filename": filename, "extracted_data": extracted_data}
                    )

    except Exception as e:
        print(f"Error processing {filename}: {e}")
        results.append({"filename": filename, "error": f"Error processing file: {e}"})

    return {"result": results}


for file in [
    "ioc.eml",
    "ioc1.eml",
    "ioc2.eml",
    "ioc3.eml",
    "ioc4.eml",
    "ioc5.eml",
    "ioc6.eml",
]:
    extract_info(filename=file)
