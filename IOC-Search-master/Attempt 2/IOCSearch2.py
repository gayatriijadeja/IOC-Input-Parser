import re


def extract_iocs(email_file_path, output_file_path):
    with open(email_file_path, "r") as file:
        email_content = file.read()

    # Define regular expressions for extracting IPs, domains, and URLs
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    domain_pattern = r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    url_pattern = r"\bhttps?://[^\s]+"

    # Extract IPs, domains, and URLs from the email content
    ips = re.findall(ip_pattern, email_content)
    domains = re.findall(domain_pattern, email_content)
    urls = re.findall(url_pattern, email_content)

    # Output the extracted IOCs to the desired format
    with open(output_file_path, "w") as output_file:
        output_file.write("List of IPs:\n")
        output_file.write("\n".join(ips) + "\n\n")

        output_file.write("List of Domains:\n")
        output_file.write("\n".join(domains) + "\n\n")

        output_file.write("List of URLs:\n")
        output_file.write("\n".join(urls) + "\n\n")

    print("Extraction complete. Check the output file:", output_file_path)


# Example usage:
input_email_file = "ioc.eml"
output_ioc_file = (
    "C:\\Users\\User\\Desktop\\Sem 8\\IOC-Search-master\\Attempt 2\\iocs.txt"
)

extract_iocs(input_email_file, output_ioc_file)
