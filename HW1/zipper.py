import zipfile

files_to_zip = ["main.py",
                "load_NVD.py",
                "read_pom.py",
                "README.md",
                "requirements.txt",
                "vulnerabilities.db",
                "report.pdf"]
zip_filename = "HW1.zip"

with zipfile.ZipFile(zip_filename, 'w') as zipf:
    for file in files_to_zip:
        zipf.write(file)