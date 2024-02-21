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
        process_part(msg, output_file)


def process_part(part, output_file):
    if part.is_multipart():
        for sub_part in part.iter_parts():
            process_part(sub_part, output_file)
    else:
        if part.get_content_type().startswith("text"):
            defanged_ips = re.findall(
                r"\b(?:\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3})\b",
                part.get_content(),
            )
            for defanged_ip in defanged_ips:
                proper_ip = defanged_to_proper(defanged_ip)
                output_file.write(proper_ip + "\n")


if __name__ == "__main__":
    email_filename = "ioc1.eml"
    output_filename = "output.txt"
    extract_ips_from_email(email_filename, output_filename)
