import email
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from email.parser import BytesParser
from email.policy import default
from mongo_wrapper import MongoWrapper


def defanged_to_proper(defanged_ip):
    proper_ip = defanged_ip.replace("[.]", ".")
    return proper_ip


def extract_ips_from_email(email_filename, output_filename):
    with open(email_filename, "rb") as email_file, open(
        output_filename, "w"
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


def extract_domains_from_email(email_filename, output_domains_filename):
    with open(email_filename, "rb") as file:
        msg = BytesParser(policy=default).parse(file)

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
            filtered_domains.add(domain)

    email_domains = {email.split("@")[1] for email in emails}
    filtered_domains = filtered_domains - email_domains
    emails = {email.split("@")[0] for email in emails}

    with open(output_domains_filename, "w") as file:
        for domain in sorted(filtered_domains):
            file.write(f"{domain}\n")

    with open("output_emails.txt", "w") as file:
        for email in sorted(emails):
            file.write(f"{email}\n")


def process_part(part, domains: set, emails: set):
    if part.is_multipart():
        for sub_part in part.iter_parts():
            process_part(sub_part, domains, emails)

    elif part.get_content_type().startswith("text"):
        content = part.get_content()
        domains.update(re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", content))

        email_addresses = re.findall(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", content
        )
        for email in email_addresses:
            emails.add(email)

        if part.get_content_type() == "text/html":
            soup = BeautifulSoup(content, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if href.startswith("http"):
                    try:
                        url = urlparse(href)
                        domain = url.netloc
                        domains.add(domain)
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
        except Exception as e:
            pass


def extract_info(filename: str) -> dict:
    results = []
    mongo_wrapper = MongoWrapper("prl-db", "mailInfo")
    try:
        with open(filename, "rb") as fp:
            msg = email.message_from_bytes(fp.read())

            sender = msg["From"]
            subject = msg["Subject"]
            time = msg["Date"]

            body_parts = []
            header_footers = []
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type in ["text/plain", "text/html"]:
                    body_parts.append(part.get_payload(decode=True))

            body_content = b"\n".join(body_parts).decode("ISO-8859-1")

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


if __name__ == "__main__":
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
