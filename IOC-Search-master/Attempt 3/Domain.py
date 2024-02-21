import os
import re
import email
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from bs4 import BeautifulSoup


def extract_domains_from_email(email_filename, output_domains_filename):
    with open(email_filename, "rb") as file:
        msg = email.message_from_binary_file(file)

    domains = set()
    process_part(msg, domains)

    with open(output_domains_filename, "w") as file:
        for domain in sorted(domains):
            file.write(f"{domain}\n")


def process_part(part, domains: set):
    if part.is_multipart():
        for sub_part in part.iter_subparts():
            process_part(sub_part, domains)

    elif part.get_content_type().startswith("text"):
        domains.update(
            re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", part.get_payload())
        )

    elif part.get_content_type() == "text/html":
        soup = BeautifulSoup(part.get_payload(), "html.parser")
        for link in soup.find_all("a"):
            href = link.get("href")
            if href and href.startswith("http"):
                try:
                    url = urlparse(href)
                    domain = url.netloc
                    if not any(
                        domain.endswith(ext)
                        for ext in [".lnk", ".pdf", ".exe", ".zip", ".jpg", ".png"]
                    ):
                        domains.add(domain)
                except Exception as e:
                    pass

    elif part.get_content_type().startswith("application/octet-stream"):
        try:
            filename = part.get_filename()
            if not any(
                filename.endswith(ext)
                for ext in [".lnk", ".pdf", ".exe", ".zip", ".jpg", ".png"]
            ):
                domains.update(
                    re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", filename)
                )
        except Exception as e:
            pass


if __name__ == "__main__":
    email_filename = "ioc2.eml"
    output_domains_filename = "output_domains.txt"

    extract_domains_from_email(email_filename, output_domains_filename)
# Error
