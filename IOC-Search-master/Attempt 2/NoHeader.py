import re
import email
from email import policy
from email.parser import BytesParser


def defanged_to_proper(ip_defanged):
    return ip_defanged.replace("[.]", ".")


def extract_ips_from_email(email_filename, output_filename):
    with open(email_filename, "rb") as email_file, open(
        output_filename, "w"
    ) as output_file:
        msg = BytesParser(policy=policy.default).parse(email_file)

        # Skip the header and process from the body onwards
        for part in msg.walk():
            if (
                part.get_content_maintype() == "text"
                and part.get_content_type() != "text/plain"
            ):
                continue
            process_part(part, output_file, set())


def process_part(part, output_file, processed_parts):
    part_id = id(part)  # Using the object ID as a hashable identifier
    if part_id in processed_parts:
        return

    processed_parts.add(part_id)

    if part.is_multipart():
        for sub_part in part.iter_parts():
            process_part(sub_part, output_file, processed_parts)
    else:
        if part.get_content_type().startswith("text"):
            defanged_ips = re.findall(
                r"\b(?:\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3})\b",
                part.get_content(),
            )
            for defanged_ip in defanged_ips:
                proper_ip = defanged_to_proper(defanged_ip)
                output_file.write(proper_ip + "\n")
        elif part.get_content_type().startswith("multipart"):
            # Handle nested attachments
            for sub_part in part.iter_parts():
                process_part(sub_part, output_file, processed_parts)
        elif part.get_filename() and part.get_filename().endswith(".txt"):
            # Process text attachments
            text_content = part.get_payload(decode=True).decode("utf-8", "ignore")
            defanged_ips = re.findall(
                r"\b(?:\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3})\b",
                text_content,
            )
            for defanged_ip in defanged_ips:
                proper_ip = defanged_to_proper(defanged_ip)
                output_file.write(proper_ip + "\n")


if __name__ == "__main__":
    email_filename = "ioc.eml"
    output_filename = "output.txt"

    extract_ips_from_email(email_filename, output_filename)
