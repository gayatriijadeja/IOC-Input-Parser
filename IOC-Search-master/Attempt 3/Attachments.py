import re
import email
from email import policy
from email.parser import BytesParser


def defanged_to_proper(ip_defanged):
    return ip_defanged.replace("[.]", ".")


def extract_ips_from_email(email_filename, output_filename):
    with open(email_filename, "rb") as email_file, open(
        output_filename, "w"
    ) as output_file:
        msg = BytesParser(policy=policy.default).parse(email_file)

        body = msg.get_body(preferencelist=("plain", "html"))
        if body:
            defanged_ips = re.findall(
                r"\b(?:\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3})\b",
                body.get_content(),
            )
            for defanged_ip in defanged_ips:
                proper_ip = defanged_to_proper(defanged_ip)
                output_file.write(proper_ip + "\n")

        for part in msg.iter_attachments():
            if part.get_content_type().startswith("text"):
                defanged_ips = re.findall(
                    r"\b(?:\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3})\b",
                    part.get_content(),
                )
                for defanged_ip in defanged_ips:
                    proper_ip = defanged_to_proper(defanged_ip)
                    output_file.write(proper_ip + "\n")


if __name__ == "__main__":
    email_filename = "ioc.eml"
    output_filename = "output.txt"
    extract_ips_from_email(email_filename, output_filename)
