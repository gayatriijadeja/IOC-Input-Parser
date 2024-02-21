import re


def refang_ioc(ioc):
    # Refang the IOC
    ioc = ioc.replace("[.]", ".")
    return ioc


def parse_and_refang_iocs(input_text, output_file):
    # Define a regex pattern for extracting IOC information
    ioc_pattern = re.compile(
        r"(\d+\.\d+\.\d+\.\d+:\d+), (\d{2}-\d{2}-\d{4}), ([A-Z]{2})"
    )

    # Open the output file for writing
    with open(output_file, "w") as out_file:
        # Find all matches of the IOC pattern in the input text
        ioc_matches = ioc_pattern.findall(input_text)

        # Iterate through matches and write refanged IOC to the output file
        for ioc_match in ioc_matches:
            ioc_refanged = refang_ioc(ioc_match[0])
            out_file.write(f"{ioc_refanged}, {ioc_match[1]}, {ioc_match[2]}\n")


if __name__ == "__main__":
    # Sample input text
    input_text = "sample.txt"

    # Output file path
    output_file = "parsed_iocs.txt"

    # Parse and refang IOCs, then write to output file
    parse_and_refang_iocs(input_text, output_file)
