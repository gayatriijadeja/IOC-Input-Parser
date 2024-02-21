import argparse
import email
import io
import os
import re


def defanged_to_proper(defanged_url):
    proper_url = re.sub(r"hXXps?|HXXps?", "https", defanged_url, flags=re.IGNORECASE)
    proper_url = re.sub(r"hXXp|HXXp", "http", proper_url, flags=re.IGNORECASE)
    # Remove any square brackets
    proper_url = re.sub(r"\[|\]", ".", proper_url)
    return proper_url


def extract_defanged_urls(eml_file):
    with open(eml_file, "rb") as f:
        email_message = email.message_from_file(f)

    defanged_urls = []
    for part in email_message.walk():
        content_type = part.get_content_type()
        if content_type == "text/plain":
            content = part.get_payload(decode=True).decode("utf-8")
            defanged_urls.extend(
                re.findall(r"hXXps?|hXXps?|hXXp|hXXp", content, re.IGNORECASE)
            )

    return defanged_urls


def extract_urls_from_attachments(eml_file):
    def parse_text_file(filename):
        with open(filename, "r") as f:
            content = f.read()
        urls = re.findall(r"https?://\S+", content)
        return urls

    with open(eml_file, "rb") as f:
        email_message = email.message_from_file(f)

    urls = []
    for part in email_message.walk():
        content_type = part.get_content_type()
        if content_type in ("text/plain"):
            filename = part.get_filename()
            if filename:
                filepath = os.path.join(os.getcwd(), filename)
                urls.extend(parse_text_file(filepath))

    return urls


def convert_defanged_to_proper(defanged_urls):
    proper_urls = set()
    for defanged_url in defanged_urls:
        proper_url = defanged_to_proper(defanged_url)
        if proper_url not in proper_urls:
            proper_urls.add(proper_url)
    return list(proper_urls)


def main():
    parser = argparse.ArgumentParser(description="Extract URLs from an email file.")
    parser.add_argument("eml_file", help="Path to the .eml file")
    parser.add_argument("output_file", help="Path to the output .txt file")

    args = parser.parse_args()

    eml_file = "ioc3.eml"
    output_file = "output2.txt"

    defanged_urls = extract_defanged_urls(eml_file)
    urls_from_attachments = extract_urls_from_attachments(eml_file)

    urls = convert_defanged_to_proper(defanged_urls + urls_from_attachments)

    with open(output_file, "w") as f:
        for url in urls:
            f.write(f"{url}\n")


if __name__ == "__main__":
    main()
