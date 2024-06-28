import csv
import argparse

def getHexValue(file_path, num_chars=128):
    with open(file_path, 'rb') as file:
        # Read the first 'num_chars' bytes from the file
        bytes_data = file.read(num_chars // 2)  # Each byte is represented by 2 hex chars
        # Convert bytes to hex string and normalize
        hex_data = bytes_data.hex()
        return hex_data

def getSignatures(txt_path):
    signatures = []
    with open(txt_path, 'r') as txtfile:
        reader = csv.DictReader(txtfile)
        for row in reader:
            hex_signature = row['Header (hex)'].strip().replace(' ', '').lower()
            description = row['Description'].strip()
            signatures.append((hex_signature, description))
    return signatures

def compareHexValue(hex_data, signatures):
    matches = []
    for signature, description in signatures:
        if hex_data.startswith(signature):
            matches.append(description)
    return matches

def putHexValue(file_path, txt_path):
    hex_data = getHexValue(file_path)
    signatures = getSignatures(txt_path)
    matches = compareHexValue(hex_data, signatures)
    
    if len(matches) > 1:
        return f"Multiple matches found: {'; '.join(matches)}"
    elif len(matches) == 1:
        return f"Match found: {matches[0]}"
    else:
        return "No matching signature found."

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract hex values and compare to signatures.")
    parser.add_argument("file_path", help="Path to the file to be analyzed")
    
    args = parser.parse_args()
    
    txt_path = 'file_sigs_CSV.txt'  # Hardcoded path to the signatures file
    
    hexValue = getHexValue(args.file_path)
    description = putHexValue(args.file_path, txt_path)
    
    print(f"Hex Value: {hexValue}")
    print(description)
