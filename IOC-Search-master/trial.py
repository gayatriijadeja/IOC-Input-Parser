import re
import os


def search_ip_in_file(file_path):
    ip_pattern = re.compile(r"\[\d{1,3}\]\.\[\d{1,3}\]\.\[\d{1,3}\]\.\[\d{1,3}\]")

    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        content = file.read()
        matches = re.findall(ip_pattern, content)
        return matches


def search_ip_in_directory(directory_path, extensions=[".eml", ".txt"]):
    ip_addresses = []

    for root, dirs, files in os.walk(directory_path):
        for file_name in files:
            if any(file_name.lower().endswith(ext) for ext in extensions):
                file_path = os.path.join(root, file_name)
                ip_addresses.extend(search_ip_in_file(file_path))

    return ip_addresses


directory_path = "C:\\Users\\User\\Desktop\\Sem 8\\IOC-Search-master\\ioc.eml"
ip_addresses_found = search_ip_in_directory(directory_path)


print("IP addresses found:")
for ip_address in ip_addresses_found:
    print(ip_address)
