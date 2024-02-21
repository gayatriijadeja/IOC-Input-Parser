import re


def defanged_to_proper(ip_defanged):
    # Replace '[.]' with '.'
    return ip_defanged.replace("[.]", ".")


def extract_ips(input_filename, output_filename):
    with open(input_filename, "r") as input_file, open(
        output_filename, "w"
    ) as output_file:
        for line in input_file:
            # Using regular expression to find defanged IPs in the line
            defanged_ips = re.findall(
                r"\b(?:\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3}\[.\]\d{1,3})\b", line
            )

            # Convert defanged IPs to proper format and write to the output file
            for defanged_ip in defanged_ips:
                proper_ip = defanged_to_proper(defanged_ip)
                output_file.write(proper_ip + "\n")


if __name__ == "__main__":
    input_filename = "ioc.eml"  # Replace with the actual input file name
    output_filename = "output.txt"  # Replace with the desired output file name

    extract_ips(input_filename, output_filename)
