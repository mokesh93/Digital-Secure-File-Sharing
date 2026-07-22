import os
from utils.logger import logger

FILES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "files")

def ensure_directory_exists(dir_path: str):
    """Ensures a given directory exists."""
    if not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)

def create_sample_file(file_name: str = "sample.txt") -> str:
    """Creates a sample text file in the files/ directory if it doesn't exist."""
    ensure_directory_exists(FILES_DIR)
    file_path = os.path.join(FILES_DIR, file_name)
    if not os.path.exists(file_path):
        sample_content = (
            "=====================================================\n"
            "   DIGITAL SECURE FILE SHARING DEMO SAMPLE FILE\n"
            "=====================================================\n"
            "This is confidential project documentation for User B.\n"
            "Encryption: AES-256-GCM + RSA-4096 Hybrid Cryptography.\n"
            "Digital Signature: SHA-256 with RSA-PSS Padding.\n"
            "Created for Cybersecurity Internship Project.\n"
        )
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(sample_content)
        logger.info(f"Sample file created at: {file_path}")
    return file_path

def format_file_size(size_in_bytes: int) -> str:
    """Formats raw file size into human-readable representation."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_in_bytes < 1024.0:
            return f"{size_in_bytes:.2f} {unit}"
        size_in_bytes /= 1024.0
    return f"{size_in_bytes:.2f} TB"
