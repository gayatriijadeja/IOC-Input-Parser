import os
import re
import email
from email.parser import BytesParser
from email.policy import default
from bs4 import BeautifulSoup
from urllib.parse import urlparse


def extract_domains_from_email(email_filename, output_filename):
    with open(email_filename, "rb") as email_file, open(
        output_filename, "w"
    ) as output_file:
        msg = BytesParser(policy=default).parse(email_file)
        domains = set()
        process_part(msg, domains)

        output_file.write("List of Domains: \n\n")
        for domain in domains:
            output_file.write(domain + "\n")


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
                    domains.add(domain)
                except Exception as e:
                    pass

    elif part.get_content_type().startswith("application/octet-stream"):
        try:
            with open(part.get_filename(), "rb") as file:
                content = file.read()
                domains.update(
                    re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", content.decode())
                )
        except Exception as e:
            pass


if __name__ == "__main__":
    email_filename = "ioc2.eml"
    output_domains_filename = "output_domains.txt"

    extract_domains_from_email(email_filename, output_domains_filename)
