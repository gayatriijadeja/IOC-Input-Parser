import re
import email
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse


def defangeddomain_to_proper(defanged_domain):
    return defanged_domain.replace("[.]", ".")


def extract_from_text(text):
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    domain_pattern = (
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    )
    defanged_domain_pattern = r"\w+(?:\[\.\]\w+)+"
    url_pattern = r"\bhttps?://\S+\b"

    ips = re.findall(ip_pattern, text)
    domains = re.findall(domain_pattern, text)
    defanged_domains = re.findall(defanged_domain_pattern, text)
    urls = re.findall(url_pattern, text)

    return ips, domains, defanged_domains, urls


def extract_from_part(part):
    ips = []
    domains = []
    defanged_domains = []
    urls = []

    if part.is_multipart():
        for sub_part in part.iter_parts():
            sub_ips, sub_domains, sub_defanged_domains, sub_urls = extract_from_part(
                sub_part
            )
            ips.extend(sub_ips)
            domains.extend(sub_domains)
            defanged_domains.extend(sub_defanged_domains)
            urls.extend(sub_urls)
    elif part.get_content_type().startswith("text"):
        text = part.get_content()
        sub_ips, sub_domains, sub_defanged_domains, sub_urls = extract_from_text(text)
        ips.extend(sub_ips)
        domains.extend(sub_domains)
        defanged_domains.extend(sub_defanged_domains)
        urls.extend(sub_urls)

    return ips, domains, defanged_domains, urls


def extract_from_attachment(part):
    ips = []
    domains = []
    defanged_domains = []
    urls = []

    filename = part.get_filename()
    if filename:
        attachment_type = part.get_content_type()
        if attachment_type.startswith("text"):
            content = part.get_content()
            sub_ips, sub_domains, sub_defanged_domains, sub_urls = extract_from_text(
                content
            )
            ips.extend(sub_ips)
            domains.extend(sub_domains)
            defanged_domains.extend(sub_defanged_domains)
            urls.extend(sub_urls)
        else:
            # If the attachment is not a text file, you may handle it differently.
            # For example, you could extract IPs, domains, and URLs from binary content.
            pass

    return ips, domains, defanged_domains, urls


def extract_from_eml(eml_filename):
    ips = []
    domains = []
    defanged_domains = []
    urls = []

    with open(eml_filename, "rb") as file:
        msg = BytesParser(policy=policy.default).parse(file)

    for part in msg.walk():
        if part.get_content_type().startswith("text"):
            content_type = part.get_content_type()
            if content_type == "text/plain":
                text = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                if text:
                    text = (
                        text.lower()
                    )  # Convert to lowercase to handle case-insensitive patterns
                    ips_part, domains_part, defanged_domains_part, urls_part = (
                        extract_from_text(text)
                    )
                    ips.extend(ips_part)
                    domains.extend(domains_part)
                    defanged_domains.extend(defanged_domains_part)
                    urls.extend(urls_part)
        elif part.get_content_maintype() == "multipart":
            ips_part, domains_part, defanged_domains_part, urls_part = (
                extract_from_part(part)
            )
            ips.extend(ips_part)
            domains.extend(domains_part)
            defanged_domains.extend(defanged_domains_part)
            urls.extend(urls_part)
        else:
            ips_part, domains_part, defanged_domains_part, urls_part = (
                extract_from_attachment(part)
            )
            ips.extend(ips_part)
            domains.extend(domains_part)
            defanged_domains.extend(defanged_domains_part)
            urls.extend(urls_part)

    return ips, domains, defanged_domains, urls


if __name__ == "__main__":
    eml_filename = "ioc.eml"
    ips, domains, defanged_domains, urls = extract_from_eml(eml_filename)

    print("IP Addresses:")
    for ip in ips:
        print(ip)

    print("\nDomains:")
    for domain in domains:
        print(domain)

    print("\nDefanged Domains:")
    for defanged_domain in defanged_domains:
        print(defangeddomain_to_proper(defanged_domain))

    print("\nURLs:")
    for url in urls:
        print(url)
