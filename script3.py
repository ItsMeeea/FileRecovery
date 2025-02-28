import binascii
import csv
import json
import os
import shutil
import hashlib
import struct
import datetime

def calculate_sha256(file_path):
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating SHA-256 for {file_path}: {e}")
        return None

def identify_file_extension_and_magic(file_path):
    """
    Identifies the file extension and extracts magic number data in one pass.
    :param file_path: Path to the file
    :return: File extension and magic number data
    """
    magic_numbers = {
        b'%PDF-': "PDF Document",
        b'\x40\x65\x63\x68': "Batch Script",
        b'\xef\xbb\xbf\x3c': "PowerShell Script",
        b'\x4d\x5a': "Windows Executable",
        b'\x89PNG\r\n\x1a\n': "PNG Image",
        b'\xff\xd8\xff\xe1': "Digital camera JPG using EXIF",
        b'\xff\xd8\xff\xe0': "JPEG/JFIF Graphics File",
        b'PK\x03\x04': "ZIP Archive"
    }
    try:
        with open(file_path, "rb") as file:
            content = file.read(64)

            # Check for subtypes
            first_four_bytes = struct.unpack("4s", content[:4])[0]  # Reads first 4 bytes
            first_two_bytes = struct.unpack("2s", content[:2])[0]  # Reads first 2 bytes
            if first_four_bytes == b'PK\x03\x04':
                file.seek(0)
                return check_zip_subtype(file)
            elif first_two_bytes == b'\x4d\x5a':
                return check_exec_subtype(file_path)
            
            for sig, file_type in magic_numbers.items():
                unpacked_sig = struct.unpack(f"{len(sig)}s", content[:len(sig)])[0]
                if unpacked_sig == sig:
                    return file_type, sig

        return "Text File", b'0'
    except Exception as e:
        print(f"Error identifying file extension and magic number for {file_path}: {e}")
        return "Text File", b'0'

def check_zip_subtype(file):
    try:
        file.seek(0)
        while True:
            data = file.read(4096)
            if not data:
                break
            if b'ppt/' in data or b'ppt\\' in data:
                return "PowerPoint Presentation", b'PK\x03\x04'
            elif b'xl/' in data or b'xl\\' in data:
                return "Excel Spreadsheet", b'PK\x03\x04'
            elif b'word/' in data or b'word\\' in data:
                return "Word Document", b'PK\x03\x04'
        return "ZIP Archive", b'PK\x03\x04'
    except Exception as e:
        print(f"Error checking ZIP subtype: {e}")
        return "ZIP Archive", b'PK\x03\x04'
    
def check_exec_subtype(file_path):
    try:
        with open(file_path, "rb") as f:
            # Read DOS Header
            f.seek(0x3C)  # PE header offset location
            pe_offset = struct.unpack("<I", f.read(4))[0]  # Read 4-byte little-endian integer
            
            # Move to PE Header and read signature
            f.seek(pe_offset)
            pe_signature = f.read(4)
            if pe_signature != b"PE\x00\x00":
                return "Text File", b'0'

            # Move to File Header and read Characteristics field (offset 0x16 from PE Header start)
            f.seek(pe_offset + 22)
            characteristics = struct.unpack("<H", f.read(2))[0]  # Read 2-byte little-endian value

            # Check flags
            is_executable = characteristics & 0x0002  # IMAGE_FILE_EXECUTABLE_IMAGE
            is_dll = characteristics & 0x2000         # IMAGE_FILE_DLL
            
            # Determine type
            if is_dll:
                return "DLL File", b'\x4d\x5a'
            elif is_executable:
                return "EXE File", b'\x4d\x5a'
            else:
                return "Text File", b'0'

    except Exception as e:
        return f"Error reading file: {e}"

def get_extension(file_type):
    """Returns the appropriate file extension based on file type."""
    extensions = {
        "Word Document": ".docx",
        "PowerPoint Presentation": ".pptx",
        "Excel Spreadsheet": ".xlsx",
        "PDF Document": ".pdf",
        "Text File": ".txt",
        "Batch Script": ".bat",
        "PowerShell Script": ".ps1",
        "EXE File": ".exe",
        "DLL File": ".dll",
        "PNG Image": ".png",
        "Digital camera JPG using EXIF": ".jpg",
        "JPEG/JFIF Graphics File": ".jpg"
    }
    return extensions.get(file_type, "")

def extract_metadata(file_path, file_type):
    metadata = {}
    try:
        with open(file_path, "rb") as f:
            content = f.read()
            
            if file_type in ["Word Document", "PowerPoint Presentation", "Excel Spreadsheet"]:
                metadata["ZIP Signature"] = binascii.hexlify(content[:4]).decode().upper()
                metadata["Document Size"] = len(content)
            
            elif file_type == "PDF Document":
                metadata["PDF Signature"] = binascii.hexlify(content[:5]).decode().upper()
                metadata["First 100 Bytes"] = content[:100].decode(errors='ignore')
            
            elif file_type in ["PNG Image", "Digital camera JPG using EXIF", "JPEG/JFIF Graphics File"]:
                metadata["File Signature"] = binascii.hexlify(content[:8]).decode().upper()
                metadata["EXIF Segment"] = binascii.hexlify(content[6:20]).decode().upper()
            
            elif file_type in ["EXE File", "DLL File"]:
                pe_offset = struct.unpack("<I", content[0x3C:0x40])[0]
                metadata["PE Header Offset"] = hex(pe_offset)
                metadata["PE Signature"] = binascii.hexlify(content[pe_offset:pe_offset+4]).decode().upper()
                characteristics_offset = pe_offset + 22  # Offset for Characteristics field
                characteristics = struct.unpack("<H", content[characteristics_offset:characteristics_offset+2])[0]
                metadata["Characteristics"] = hex(characteristics)
                
                if characteristics & 0x2000:  # IMAGE_FILE_DLL
                    metadata["Offset"] = hex(characteristics_offset)
                elif characteristics & 0x0002:  # IMAGE_FILE_EXECUTABLE_IMAGE
                    metadata["Offset"] = hex(characteristics_offset)
                else:
                    metadata["Offset"] = "NA"
                
                metadata["Timestamp"] = datetime.datetime.utcfromtimestamp(struct.unpack("<I", content[pe_offset+8:pe_offset+12])[0]).isoformat()
            
            elif file_type in ["Text File", "Batch Script", "PowerShell Script"]:
                metadata["File Size"] = len(content)
                metadata["Encoding Type"] = "UTF-8" if content.startswith(b'\xef\xbb\xbf') else "ASCII or other"
            
    except Exception as e:
        metadata["Error"] = str(e)
    
    return metadata if metadata else {"Info": "No metadata extracted"}

def recover_file(file_path, recovered_folder):
    try:
        file_type, magic_number = identify_file_extension_and_magic(file_path)
        if file_type != "Unknown":
            extension = get_extension(file_type)
            recovered_path = os.path.join(recovered_folder, os.path.splitext(os.path.basename(file_path))[0] + extension)
            shutil.copy2(file_path, recovered_path)
            
            metadata = extract_metadata(file_path, file_type)
            
            print(f"File recovered and saved to {recovered_path}")
            print(f"File Type: {file_type}")
            print(f"Metadata: {metadata}")
            
            return recovered_path, metadata
        else:
            print("File type could not be identified; recovery failed.")
            return None, None
    except Exception as e:
        print(f"Error recovering file {file_path}: {e}")
        return None, None

def process_files_in_folder(folder_path, recovery_folder, output_csv):
    if not os.path.isdir(folder_path):
        print("Invalid folder path.")
        return
    os.makedirs(recovery_folder, exist_ok=True)
    
    data = []

    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):
            print(f"\nProcessing file: {file_name}")
            original_sha256 = calculate_sha256(file_path)
            recovered_path, metadata = recover_file(file_path, recovery_folder)
            
            if recovered_path:
                recovered_sha256 = calculate_sha256(recovered_path)
                file_type, magic_number = identify_file_extension_and_magic(file_path)
                magic_hex = "NA" if magic_number == b'0' else binascii.hexlify(magic_number).decode().upper()
                magic_ascii = "NA" if magic_number == b'0' else magic_number.decode('latin-1', errors='replace')
                magic_offset = metadata.get("Offset", "NA")
                
                metadata_str = json.dumps(metadata, separators=(',', ':')) if metadata else "NA"
                
                data.append([file_name, original_sha256, recovered_sha256, magic_hex, magic_offset, magic_ascii, metadata_str])
    
    # Write to CSV
    with open(output_csv, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["File Name", "Original SHA-256", "Recovered SHA-256", "Magic (Hex)", "Offset", "Magic (ASCII)", "Metadata"])
        writer.writerows(data)
    
    print(f"Summary saved to: {output_csv}")

folder_path = ".\\files"
recovery_folder = ".\\recovered_files"
output_csv = "file_recovery_report.csv"
process_files_in_folder(folder_path, recovery_folder, output_csv)