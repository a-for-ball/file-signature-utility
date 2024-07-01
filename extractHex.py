import csv
import os
from typing import List, Tuple

SIGNATURE_FILE_PATH = 'file_sigs_CSV.txt'

def get_hex_value(file_path: str, num_chars: int = 128) -> str:
    try:
        with open(file_path, 'rb') as file:
            bytes_data = file.read(num_chars // 2)
        return bytes_data.hex()
    except IOError as e:
        raise IOError(f"Error reading file {file_path}: {e}")

def get_signatures(signature_file_path: str) -> List[Tuple[str, str]]:
    try:
        with open(signature_file_path, 'r') as txtfile:
            reader = csv.DictReader(txtfile)
            return [(row['Header (hex)'].strip().replace(' ', '').lower(), row['Description'].strip()) for row in reader]
    except IOError as e:
        raise IOError(f"Error reading signature file {signature_file_path}: {e}")

def compare_hex_value(hex_data: str, signatures: List[Tuple[str, str]]) -> List[str]:
    return [description for signature, description in signatures if hex_data.startswith(signature)]

def is_csv_file(file_path: str) -> bool:
    try:
        with open(file_path, 'r', newline='') as csvfile:
            sample = csvfile.read(1024)
            dialect = csv.Sniffer().sniff(sample)
            has_header = csv.Sniffer().has_header(sample)
            
            # Additional checks
            lines = sample.split('\n')
            if len(lines) < 2:
                return False
            
            # Check if all lines have the same number of fields
            field_counts = [len(line.split(dialect.delimiter)) for line in lines if line.strip()]
            return len(set(field_counts)) == 1 and field_counts[0] > 1
    except:
        return False

def detect_encoding(file_path: str) -> str:
    encodings = ['utf-8', 'ascii', 'latin-1', 'utf-16']
    for enc in encodings:
        try:
            with open(file_path, 'r', encoding=enc) as file:
                file.read(1024)
            return enc
        except UnicodeDecodeError:
            continue
    return 'unknown'

def is_text_file(file_path: str, encoding: str) -> bool:
    try:
        with open(file_path, 'r', encoding=encoding) as file:
            sample = file.read(1024)
            return all(ord(char) < 128 for char in sample)
    except UnicodeDecodeError:
        return False

def get_file_extension(file_path: str) -> str:
    return os.path.splitext(file_path)[1].lower()

def analyze_file(file_path: str, signature_file_path: str) -> str:
    hex_data = get_hex_value(file_path)
    signatures = get_signatures(signature_file_path)
    matches = compare_hex_value(hex_data, signatures)

    if matches:
        if len(matches) > 1:
            return f"Multiple matches found: {'; '.join(matches)}"
        else:
            return f"Match found: {matches[0]}"

    # Check file extension
    extension = get_file_extension(file_path)
    if extension:
        if extension == '.csv':
            if is_csv_file(file_path):
                return "File type: CSV"
            else:
                return "File has .csv extension but doesn't appear to be a valid CSV"
        elif extension in ['.txt', '.py', '.asm', '.c', '.cpp', '.h', '.java', '.js', '.html', '.css']:
            encoding = detect_encoding(file_path)
            if encoding != 'unknown' and is_text_file(file_path, encoding):
                return f"File type: Text file ({extension[1:].upper()}, {encoding})"

    # Additional checks for text-based files without specific extensions
    if is_csv_file(file_path):
        return "File type: CSV (without .csv extension)"

    encoding = detect_encoding(file_path)
    if encoding != 'unknown':
        if is_text_file(file_path, encoding):
            return f"File type: Generic text file (encoding: {encoding})"

    return "Unable to determine file type"

def main():
    while True:
        file_path = input("Enter the path to the file you want to analyze (or 'q' to quit): ").strip()
        
        if file_path.lower() == 'q':
            print("Exiting the program.")
            break
        
        try:
            result = analyze_file(file_path, SIGNATURE_FILE_PATH)
            print(result)
        except Exception as e:
            print(f"An error occurred: {e}")
        
        print()  

if __name__ == "__main__":
    main()