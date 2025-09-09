import json
import requests
import gzip
import tempfile
import sqlite3
import os

DB_FILE = "vulnerabilities.db"

START_YEAR = 2021
END_YEAR = 2022

def init_db():
    # Delete the database file if it exists
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print(f"Deleted existing database {DB_FILE}")

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE vulnerabilities (
            cve_id TEXT,
            description TEXT,
            cpe_uri TEXT,
            severity TEXT
        )
    """)
    conn.commit()
    conn.close()

#######################
##### Main Script #####
#######################
def fill_db():
    init_db()

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    for year in range(START_YEAR, END_YEAR):
        # Obtain the JSON data
        url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
        response = requests.get(url)

        if response.status_code != 200:
            print(f"Failed to download {url}")
            continue

        with tempfile.TemporaryFile() as temp:
            temp.write(response.content)
            temp.seek(0)
            with gzip.open(temp, 'rb') as f:
                file_content = f.read()
                data = json.loads(file_content)

                rows_to_insert = []

                for entry in data['vulnerabilities']:
                    cve = entry['cve']
                    cve_id = cve['id']
                    cve_description = "\n".join(
                        x["value"] for x in cve['descriptions'] if x["lang"] == "en"
                    )

                    severity = "UNKNOWN"
                    if "metrics" in cve and "cvssMetricV31" in cve["metrics"]:
                        severity = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]

                    if "configurations" not in cve:
                        continue

                    for config in cve['configurations']:
                        for config_nodes in config["nodes"]:
                            for cpe_match in config_nodes.get("cpeMatch", []):
                                cpe_uri = cpe_match.get("criteria")
                                if cpe_uri:
                                    rows_to_insert.append(
                                        (cve_id, cve_description, cpe_uri, severity)
                                    )

                # Insert all rows for current year at once
                cur.executemany(
                    "INSERT INTO vulnerabilities (cve_id, description, cpe_uri, severity) VALUES (?, ?, ?, ?)",
                    rows_to_insert
                )
                conn.commit()

        print(f"Finished {year}")

    # Close DB connection
    conn.close()
