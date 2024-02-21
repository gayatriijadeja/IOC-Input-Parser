import re
import email
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from bs4 import BeautifulSoup

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
                email_message[header] = email.header.Header(header_value).encode()


def defangeddomain_to_proper(defanged_domain):
    return defanged_domain.replace("[.]", ".")


def extract_domains_from_email(email_filename, output_domains_filename):
    with open(email_filename, "rb") as file:
        msg = BytesParser(policy=policy.default).parse(file)

    domains = set()
    emails = set()
    process_part(msg, domains, emails)

    filtered_domains = set()
    for domain in domains:
        if not any(
            domain.endswith(ext)
            for ext in [
                ".lnk",
                ".pdf",
                ".exe",
                ".zip",
                ".jpg",
                ".png",
                ".LNK",
                ".PDF",
                ".EXE",
                ".ZIP",
                ".JPG",
                ".PNG",
                ".GOV",
                ".GOV.IN",
                ".gov",
                ".gov.in",
            ]
        ):
            filtered_domain = defangeddomain_to_proper(domain)
            filtered_domains.add(filtered_domain)

    email_domains = {email.split("@")[1] for email in emails}
    filtered_domains = filtered_domains - email_domains

    emails = {email.split("@")[0] for email in emails}

    with open(output_domains_filename, "w") as file:
        for domain in sorted(filtered_domains):
            file.write(f"{domain}\n")

    with open("output_emails.txt", "w") as file:
        for email in sorted(emails):
            file.write(f"{email}\n")


def process_part(part, domains, emails):
    if part.is_multipart():
        for sub_part in part.iter_parts():
            process_part(sub_part, domains, emails)

    elif part.get_content_type().startswith("text"):
        content = part.get_content()  # Extract content
        domains.update(re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", content))
        defanged_domains = re.findall(r"\w+(?:\[\.\]\w+)+", content)
        domains.update(defanged_domains)

        email_addresses = re.findall(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", content
        )
        for email in email_addresses:
            emails.add(email)

        # Extract URLs from HTML content
        if part.get_content_type() == "text/html":
            soup = BeautifulSoup(content, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if href.startswith("http"):
                    try:
                        url = urlparse(href)
                        domain = url.netloc
                        defanged_domain = re.sub(r"[.]", "[.]", domain)
                        domains.add(defanged_domain)
                    except Exception as e:
                        pass

    elif part.get_content_type().startswith("application/octet-stream"):
        try:
            filename = part.get_filename()
            if filename and not any(
                filename.endswith(ext)
                for ext in [
                    ".lnk",
                    ".pdf",
                    ".exe",
                    ".zip",
                    ".jpg",
                    ".png",
                    ".EXE",
                    ".LNK",
                    ".PDF",
                    ".ZIP",
                    ".JPG",
                    ".PNG",
                    ".GOV",
                    ".GOV.IN",
                    ".gov",
                    ".gov.in",
                ]
            ):
                domains.update(
                    re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", filename)
                )
                domains.update(re.findall(r"\w+(?:\[\.\]\w+)+", filename))
        except Exception as e:
            pass


def process_email_file(email_filename):
    with open(email_filename, "rb") as file:
        msg = BytesParser(policy=policy.default).parse(file)

    encode_email_headers(msg)
    process_part(msg, set(), set())
    return msg


email_filename = "ioc1.eml"
email_message = process_email_file(email_filename)


if __name__ == "__main__":
    email_filename = "ioc4.eml"
    output_domains_filename = "output_domains.txt"

    extract_domains_from_email(email_filename, output_domains_filename)
