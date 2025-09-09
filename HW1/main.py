import sqlite3
import sys
import os
from read_pom import read_pom
from load_NVD import fill_db
from packaging import version

DB_FILE = "vulnerabilities.db"
OUTPUT_FILE = "Output.txt"

##### Checking Inputs #####
# Checking number of inputs
if len(sys.argv) < 3:
    print("Usage: python main.py <mode> <path_to_pom>")
    sys.exit(1)

mode = sys.argv[1]
pom_path = sys.argv[2]

# Checking input quality
if not mode == "detect" and not mode == "all":
    print("Mode must be either 'all' or 'detect'")
    sys.exit(1)
if not os.path.exists(pom_path):
    print("Pom path does not exist")
    sys.exit(1)

##### Comparing Dependencies
# Realoading knowledge base
if mode == "all":
    print("Re-loading Knowledge base...")
    fill_db()
    print("Knowledge Base Reloaded")

# Get dependencies
deps = read_pom(pom_path)

# Connecting to the database
conn = sqlite3.connect(DB_FILE)
cur = conn.cursor()

with open(OUTPUT_FILE, "w") as file:
    file.write("Known security vulnerabilities detected:\n")
    vuln_found = False

    for group_id, artifact_id, pom_version in deps:
        cur.execute("""
            SELECT cve_id, description, cpe_uri, severity
            FROM vulnerabilities
            WHERE cpe_uri LIKE ? AND cpe_uri LIKE ?
        """, (f"%:{group_id}:%", f"%:{artifact_id}:%"))
        
        results = cur.fetchall()
        entry = False

        seen_cves = set()

        for cve_id, desc, cpe_uri, severity in results:
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

            splits = cpe_uri.split(":")
            cpe_product = splits[4]
            cpe_version = splits[5]
            v_start_inc = splits[6]
            v_start_exc = splits[7]
            v_end_inc = splits[8]
            v_end_exc = splits[9]

            pom_v = version.parse(pom_version)

            # If singular version shared
            if cpe_version != "*":
                if cpe_version == pom_version:
                    if not entry:
                        file.write(f"\nDependency: {cpe_product}\n")
                        file.write(f"Version(s): {cpe_version}\n")
                        file.write(f"Vulnerabilities:\n")
                        entry = True
                    file.write(f"- {cve_id} (Severity: {severity})\n")
                continue

            # Checking Version Ranges
            version_in_range = True
            version_string = ""
            # Start including
            if v_start_inc != "*":
                if pom_v < version.parse(v_start_inc):
                    version_in_range = False
                else:
                    version_string.append(f"<= {v_start_inc} ")
            # Start excluding
            if v_start_exc != "*":
                if pom_v <= version.parse(v_start_exc):
                    version_in_range = False
                else:
                    version_string.append(f"< {v_start_exc} ")
            # End including
            if v_end_inc != "*":
                if pom_v > version.parse(v_end_inc):
                    version_in_range = False
                else:
                    version_string.append(f"> {v_end_inc}")
            # End excluding
            if v_end_exc != "*":
                if pom_v >= version.parse(v_end_exc):
                    version_in_range = False
                else:
                    version_string.append(f">= {v_end_exc}")

            # Show output if in a range
            if version_in_range and version_string:
                if not entry:
                    file.write(f"\nDependency: {cpe_product}\n")
                    file.write(f"Version(s): {version_string}\n")
                    file.write(f"Vulnerabilities:\n")
                    entry = True
                file.write(f"- {cve_id} (Severity: {severity})\n")
                continue


            # No version specified
            if cpe_version == "*" or cpe_version == "-":
                if not entry:
                    file.write(f"\nDependency: {cpe_product}\n")
                    file.write(f"Version(s): *\n")
                    file.write(f"Vulnerabilities:\n")
                    entry = True
                file.write(f"- {cve_id} (Severity: {severity})\n")
                continue
            
        if entry:
            vuln_found = True
            
    if not vuln_found:
        file.write(f"\nNo vulnerability found")

conn.close()