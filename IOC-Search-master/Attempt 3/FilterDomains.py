import os
import re
import email
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from bs4 import BeautifulSoup


def extract_domains_from_email(email_filename, output_domains_filename):
    with open(email_filename, "rb") as file:
        msg = BytesParser(policy=policy.default).parse(file)

    domains = set()
    emails = set()
    process_part(msg, domains)

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
                ".EXE",
                ".gov",
                ".gov.in",
                ".LNK",
                ".PDF",
                ".ZIP",
                ".JPG",
                ".PNG",
            ]
        ):
            domain_emails = re.findall(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", domain
            )

            if not any(domain.endswith(email) for email in domain_emails):
                filtered_domains.add(domain)
    with open(output_domains_filename, "w") as file:
        for domain in sorted(filtered_domains):
            file.write(f"{domain}\n")


def process_part(part, domains: set):
    if part.is_multipart():
        for sub_part in part.iter_parts():
            process_part(sub_part, domains)

    elif part.get_content_type().startswith("text"):
        domains.update(
            re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", part.get_content())
        )

    elif part.get_content_type() == "text/html":
        content = part.get_content()
        soup = BeautifulSoup(content, "html.parser")
        for link in soup.find_all("a"):
            href = link.get("href")
            if href and href.startswith("http"):
                try:
                    url = urlparse(href)
                    domain = url.netloc
                    domains.update(
                        re.findall(
                            r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\.lnk|\.pdf|\.exe|\.zip|\.jpg|\.png|\.EXE|\.gov|\.gov.in|\.LNK|\.PDF|\.EXE|\.ZIP|\.JPG|\.PNG)\b",
                            domain,
                        )
                    )

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
                    ".gov",
                    ".gov.in",
                    ".JPG",
                    ".PNG",
                    ".ZIP",
                    ".PDF",
                    ".LNK",
                ]
            ):
                domains.update(
                    re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", filename)
                )
        except Exception as e:
            pass


if __name__ == "__main__":
    email_filename = "ioc4.eml"
    output_domains_filename = "output_domains.txt"

    extract_domains_from_email(email_filename, output_domains_filename)
