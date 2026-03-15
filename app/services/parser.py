import pandas as pd


def parse_nessus_csv(file_path):

    df = pd.read_csv(file_path)

    findings = []

    for _, row in df.iterrows():

        finding = {
            "host": row.get("Host"),
            "port": row.get("Port"),
            "name": row.get("Name"),
            "severity": row.get("Risk"),
            "cvss": row.get("CVSS v3.0 Base Score"),
            "cve": row.get("CVE"),
            "description": row.get("Description"),
            "solution": row.get("Solution"),
        }

        findings.append(finding)

    return findings