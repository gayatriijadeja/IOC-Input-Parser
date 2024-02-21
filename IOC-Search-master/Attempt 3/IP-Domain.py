import re
import email
from email.parser import BytesParser
from email.policy import default


def defanged_to_proper(defanged_ip):
    proper_ip = defanged_ip.replace("[.]", ".")
    return proper_ip


def extract_ips_from_email(
    email_filename, output_ips_filename, output_domains_filename
):
    with open(email_filename, "rb") as email_file, open(
        output_ips_filename, "w"
    ) as output_ips_file, open(output_domains_filename, "w") as output_domains_file:
        msg = BytesParser(policy=default).parse(email_file)
        ip_addresses = set()
        domains = set()
        process_part(msg, ip_addresses, domains)

        # Write IPs to the output file
        for ip_address in ip_addresses:
            output_ips_file.write(ip_address + "\n")

        # Write Domains to the output file
        for domain in domains:
            output_domains_file.write(domain + "\n")


def process_part(part, ip_addresses: set, domains: set):
    if part.is_multipart():
        for sub_part in part.iter_parts():
            process_part(sub_part, ip_addresses, domains)

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

            # Extract domains using a simple regex (modify as needed)
            domain_matches = re.findall(
                r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", part.get_content()
            )
            for match in domain_matches:
                domain = match.replace("https://", "").replace("www.", "").strip("/")
                domains.add(domain)


if __name__ == "__main__":
    email_filename = "ioc4.eml"
    output_ips_filename = "output_ips.txt"
    output_domains_filename = "output_domains.txt"

    extract_ips_from_email(email_filename, output_ips_filename, output_domains_filename)
