import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import email
from email.policy import default
from mongo_wrapper import MongoWrapper
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi


def defanged_to_proper(defanged_ip):
    proper_ip = defanged_ip.replace("[.]", ".")
    return proper_ip


def defanged_to_proper(defanged_url):
    proper_url = defanged_url.replace("[.]", ".")
    return proper_url


def defanged_to_proper(domains):
    proper_domain = domains.replace("[.]", ".")
    return proper_domain


def extract_ips_from_email(email_filename, output_filename1):
    with open(email_filename, "rb") as email_file, open(
        output_filename1, "w"
    ) as output_file:
        msg = BytesParser(policy=default).parse(email_file)
        ip_addresses = set()
        process_part_ip(msg, ip_addresses)
        for ip_address in ip_addresses:
            output_file.write(ip_address + "\n")


def process_part_ip(part, ip_addresses: set):
    if part.is_multipart():
        for sub_part in part.iter_parts():
            process_part_ip(sub_part, ip_addresses)

    if part.get_content_type().startswith("text"):

        defanged_ips = re.findall(
            r"\b(?:\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3})\b", part.get_content()
        )
        normal_ips = re.findall(
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", part.get_content()
        )
        for defanged_ip in defanged_ips:
            proper_ip = defanged_to_proper(defanged_ip)
            ip_addresses.add(proper_ip)
        for normal_ip in normal_ips:
            ip_addresses.add(normal_ip)


def defanged_to_proper(defanged_url):
    proper_url = re.sub(r"hxxps?|hXXps?", "https", defanged_url, flags=re.IGNORECASE)
    proper_url = re.sub(r"hxxp|hXXp", "http", proper_url, flags=re.IGNORECASE)
    return proper_url


def extract_urls_from_email(email_filename, output_filename):
    with open(email_filename, "rb") as email_file, open(
        output_filename, "w"
    ) as output_file:
        msg = BytesParser(policy=default).parse(email_file)
        urls = set()
        process_part(msg, urls, domains)
        for url in urls:
            output_file.write(f"{url}\n")


"""
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

        with open(output_filename, "w") as file:
            for defanged_url in sorted(defanged_urls):
                file.write(f"{defanged_url}\n")
            for normal_url in sorted(normal_urls):
                file.write(f"{normal_url}\n")

"""


def extract_domains_from_email(email_filename, output_domains_filename):
    domains = set()
    emails = set()
    with open(email_filename, "rb") as file:
        msg = BytesParser(policy=policy.default).parse(file)
        process_part(msg, urls, domains)
        extract_info(msg, domains, emails, output_domains_filename)


def process_part(part, urls: set, domains: set):
    if part.is_multipart():
        for sub_part in part.iter_parts():
            process_part(sub_part, urls, domains)

    if part.get_content_type().startswith("text"):
        # Get the entire content of the part
        content = part.get_payload(decode=True).decode()

        # Exclude header and footer content
        header_footer_removed = exclude_header_footer(content)

        defanged_urls = re.findall(
            r"\b(?:h?xx(p|ps):\/\/[^ ]+)", header_footer_removed, re.IGNORECASE
        )
        normal_urls = re.findall(
            r"(?:https?://[^ ]+)", header_footer_removed, re.IGNORECASE
        )
        for defanged_url in defanged_urls:
            proper_url = defanged_to_proper(defanged_url)
            urls.add(proper_url)
        for normal_url in normal_urls:
            urls.add(normal_url)

        domains.update(
            re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", header_footer_removed)
        )

        with open(output_filename, "w") as file:
            for defanged_url in sorted(defanged_urls):
                file.write(f"{defanged_url}\n")
            for normal_url in sorted(normal_urls):
                file.write(f"{normal_url}\n")


def extract_info(msg, domains: set, emails: set, output_filename2: str):
    if msg.is_multipart():
        for sub_part in msg.iter_parts():
            extract_info(sub_part, domains, emails, output_filename2)
    elif msg.get_content_type().startswith("text"):
        content = msg.get_content()
        domains.update(re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", content))
        email_addresses = re.findall(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,4}\b", content
        )
        for email in email_addresses:
            emails.add(email)

        if msg.get_content_type() == "text/html":
            content = msg.get_filename()
        if content and not any(
            content.endswith(ext)
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
            domains.update(re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", content))
            """ soup = BeautifulSoup(content, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if href.startswith("http"):"""
            try:
                # url = urlparse(href)
                domain = url.netloc
                domains.add(domain)
            except Exception as e:
                pass

    elif msg.get_content_type().startswith("application/octet-stream"):
        filename = msg.get_filename()
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
            domains.update(re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", filename))


def exclude_header_footer(content):
    # Split content into lines to identify header and footer
    lines = content.splitlines()

    # Remove header and footer content
    body_lines = []
    in_header = True
    for line in lines:
        if line.strip() == "":
            # Empty line signifies end of header
            in_header = False
        elif not line.startswith(">") and not in_header:
            # If line doesn't start with ">", it's not footer
            body_lines.append(line)

    # Join lines to reconstruct body content
    body_content = "\n".join(body_lines)
    return body_content


if __name__ == "__main__":
    output_filename = "output_urls.txt"
    output_filename1 = "output_ips.txt"
    output_filename2 = "output_domains.txt"

    urls = set()
    domains = set()
    for file in ["ioc2.eml", "ioc3.eml"]:

        extract_domains_from_email(
            email_filename=file, output_domains_filename=output_filename2
        )
        extract_urls_from_email(email_filename=file, output_filename=output_filename)
        extract_ips_from_email(email_filename=file, output_filename1=output_filename1)

    with open(output_filename, "w") as file:
        for url in sorted(urls):
            file.write(f"{url}\n")

    with open(output_filename2, "w") as file:
        for domain in sorted(domains):
            file.write(f"{domain}\n")

"""
    with open(output_filename2, "w") as file:
        for domain in sorted(domains):
            file.write(f"{domain}\n")
        for email in sorted(emails):
            file.write(f"{email}\n")


if __name__ == "__main__":

    output_filename = "output_urls.txt"
    output_filename1 = "output_ips.txt"
    output_filename2 = "output_domains.txt"
    for file in [
        "ioc7.eml",
    ]:

        extract_domains_from_email(
            email_filename=file, output_domains_filename=output_filename2
        )
        extract_urls_from_email(email_filename=file, output_filename=output_filename)
        extract_ips_from_email(email_filename=file, output_filename1=output_filename1)
"""
