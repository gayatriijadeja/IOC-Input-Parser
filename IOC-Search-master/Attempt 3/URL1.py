import re
import email
from email.parser import BytesParser
from email.policy import default
from urllib.parse import urlparse


def defanged_to_proper(defanged_url):
    proper_url = re.sub(r"hxxps?|hXXps?", "https", defanged_url, flags=re.IGNORECASE)
    proper_url = re.sub(r"hxxp|hXXp", "http", defanged_url, flags=re.IGNORECASE)
    return proper_url


def extract_urls_from_email(email_filename, output_filename):
    with open(email_filename, "rb") as email_file, open(
        output_filename, "w"
    ) as output_file:
        msg = BytesParser(policy=default).parse(email_file)
        urls = set()
        process_part(msg, urls)
        for url in urls:
            output_file.write(f"{url}" + "\n")


def process_part(part, urls: set):
    if part.is_multipart():
        for sub_part in part.iter_parts():
            process_part(sub_part, urls)

    if part.get_content_type().startswith("text"):
        defanged_urls = re.findall(
            r"\b(?:h?xx(p|ps):\/\/[^ ]+)", part.get_content(), re.IGNORECASE
        )
        normal_urls = re.findall(
            r"(?:https?://[^ ]+)", part.get_content(), re.IGNORECASE
        )
        for defanged_url in defanged_urls:
            proper_url = defanged_to_proper(defanged_url)
            urls.add(proper_url)

        for normal_url in normal_urls:
            urls.add(normal_url)


if __name__ == "__main__":
    email_filename = "ioc4.eml"
    output_filename = "output_urls.txt"

    extract_urls_from_email(email_filename, output_filename)
