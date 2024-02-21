import os
import re
import email
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse, urlunparse


def parse_email(filename):
    with open(filename, "rb") as file:
        msg = BytesParser(policy=policy.default).parse(file)
    return msg


def extract_urls(msg):
    urls = set()
    stack = [msg]
    while stack:
        part = stack.pop()
        if part.get_content_type().startswith("text"):
            content = part.get_content()
            urls.update(re.findall(r"(h?xx(p|ps)://[^ ]+)", content, re.IGNORECASE))
        if part.is_multipart():
            stack.extend(part.iter_parts())
    return urls


def sanitize_urls(urls):
    sanitized_urls = set()
    for url in urls:
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc
        if "hxxp" in netloc:
            netloc = netloc.replace("hxxp", "http").replace("hxxps", "https")
            sanitized_url = urlunparse(
                (
                    parsed_url.scheme,
                    str(netloc),  # Ensure netloc is treated as a string
                    str(parsed_url.path),  # Ensure path is treated as a string
                    str(parsed_url.params),  # Ensure params is treated as a string
                    str(parsed_url.query),  # Ensure query is treated as a string
                    str(parsed_url.fragment),  # Ensure fragment is treated as a string
                )
            )
            sanitized_urls.add(sanitized_url)
        elif "hxxps" in netloc:
            netloc = netloc.replace("hxxps", "https")
            sanitized_url = urlunparse(
                (
                    parsed_url.scheme,
                    str(netloc),  # Ensure netloc is treated as a string
                    str(parsed_url.path),  # Ensure path is treated as a string
                    str(parsed_url.params),  # Ensure params is treated as a string
                    str(parsed_url.query),  # Ensure query is treated as a string
                    str(parsed_url.fragment),  # Ensure fragment is treated as a string
                )
            )
            sanitized_urls.add(sanitized_url)
        else:
            sanitized_urls.add(url)
    return sanitized_urls


def main():
    email_filename = "ioc3.eml"
    output_filename = "output_urls.txt"

    msg = parse_email(email_filename)
    urls = extract_urls(msg)
    sanitized_urls = sanitize_urls(urls)

    with open(output_filename, "w") as file:
        for url in sorted(sanitized_urls):
            file.write(f"{url}\n")


if __name__ == "__main__":
    main()
