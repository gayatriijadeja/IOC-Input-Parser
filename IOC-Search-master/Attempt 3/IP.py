import re
import email
from email.parser import BytesParser
from email.policy import default


def defanged_to_proper(defanged_ip):
    proper_ip = defanged_ip.replace("[.]", ".")
    return proper_ip


def extract_ips_from_email(email_filename, output_filename):
    with open(email_filename, "rb") as email_file, open(
        output_filename, "w"
    ) as output_file:
        msg = BytesParser(policy=default).parse(email_file)
        ip_addresses = set()
        process_part(msg, ip_addresses)
        for ip_address in ip_addresses:
            output_file.write(ip_address + "\n")


def process_part(part, ip_addresses: set):
    if part.is_multipart():
        for sub_part in part.iter_parts():
            process_part(sub_part, ip_addresses)

    if part.get_content_type().startswith("text"):
        defanged_ips = re.findall(
            r"\b(?:\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3})\b",
            part.get_content(),
        )
        normal_ips = re.findall(
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", part.get_content()
        )
        for defanged_ip in defanged_ips:
            proper_ip = defanged_to_proper(defanged_ip)
            ip_addresses.add(proper_ip)

        for normal_ip in normal_ips:
            ip_addresses.add(normal_ip)


if __name__ == "__main__":
    email_filename = "ioc7.eml"
    output_filename = "output1.txt"

    extract_ips_from_email(email_filename, output_filename)
