"""
nvd_client.py
~~~~~~~~~~~~~
Fetches CVE enrichment data from the NVD API 2.0.
Docs: https://nvd.nist.gov/developers/vulnerabilities

Rate limits (unauthenticated): 5 requests / 30 seconds
Rate limits (with API key):    50 requests / 30 seconds

Set NVD_API_KEY in your environment for production use:
    export NVD_API_KEY=your-key-here
"""

import os
import time
import logging
import requests

logger = logging.getLogger(__name__)

NVD_BASE      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY   = os.getenv("NVD_API_KEY", "")          # optional but recommended
REQUEST_DELAY = 0.7 if NVD_API_KEY else 7.0            # seconds between calls


def _headers() -> dict:
    h = {"Accept": "application/json"}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h


def fetch_cve(cve_id: str) -> dict | None:
    """
    Fetch a single CVE from the NVD API.

    Returns a dict with keys:
        cvss_score      float  – CVSS v3.1 base score (falls back to v2)
        cwe             str    – primary CWE ID  e.g. "CWE-79"
        description     str    – English description from NVD
        patch_available bool   – True if any reference tag contains "Patch"

    Returns None on any error (network, 404, malformed).
    """
    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return None

    cve_id = cve_id.strip().upper()

    try:
        time.sleep(REQUEST_DELAY)          # respect rate limit

        resp = requests.get(
            NVD_BASE,
            params={"cveId": cve_id},
            headers=_headers(),
            timeout=10
        )

        if resp.status_code == 404:
            logger.warning("CVE not found in NVD: %s", cve_id)
            return None

        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        cve_data = vulns[0].get("cve", {})

        return {
            "cvss_score":      _extract_cvss(cve_data),
            "cwe":             _extract_cwe(cve_data),
            "description":     _extract_description(cve_data),
            "patch_available": _extract_patch(cve_data),
        }

    except requests.RequestException as e:
        logger.error("NVD request failed for %s: %s", cve_id, e)
        return None
    except Exception as e:
        logger.error("Unexpected error fetching %s: %s", cve_id, e)
        return None


# ── helpers ────────────────────────────────────────────────────────────────

def _extract_cvss(cve_data: dict) -> float:
    """Prefer CVSSv3.1 → CVSSv3.0 → CVSSv2. Return 0.0 if none found."""
    metrics = cve_data.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            try:
                return float(entries[0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                pass

    entries = metrics.get("cvssMetricV2", [])
    if entries:
        try:
            return float(entries[0]["cvssData"]["baseScore"])
        except (KeyError, TypeError, ValueError):
            pass

    return 0.0


def _extract_cwe(cve_data: dict) -> str:
    """Return the first CWE ID, or empty string."""
    try:
        weaknesses = cve_data.get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    return val
    except Exception:
        pass
    return ""


def _extract_description(cve_data: dict) -> str:
    """Return the English description, or empty string."""
    try:
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                return d.get("value", "")
    except Exception:
        pass
    return ""


def _extract_patch(cve_data: dict) -> bool:
    """Return True if any NVD reference is tagged as a Patch."""
    try:
        for ref in cve_data.get("references", []):
            tags = ref.get("tags", [])
            if "Patch" in tags:
                return True
    except Exception:
        pass
    return False


def enrich_vulnerabilities(db, vuln_ids: list[int]) -> None:
    """
    Given a list of Vulnerability IDs, fetch NVD data for any that:
    - have a CVE ID set
    - have not been fetched yet (nvd_fetched == False)

    Updates the DB rows in place. Called by scan_ingestor after ingestion.
    """
    from app.models.vulnerability import Vulnerability

    vulns = db.query(Vulnerability).filter(
        Vulnerability.id.in_(vuln_ids),
        Vulnerability.nvd_fetched == False,         # noqa: E712
        Vulnerability.cve != None,                  # noqa: E711
        Vulnerability.cve != "",
    ).all()

    logger.info("Enriching %d vulnerabilities from NVD", len(vulns))

    for vuln in vulns:
        result = fetch_cve(vuln.cve)

        if result:
            # Prefer NVD's CVSS if Nessus didn't provide one
            if result["cvss_score"] and (not vuln.cvss_score or vuln.cvss_score == 0.0):
                vuln.cvss_score = result["cvss_score"]

            vuln.cwe             = result["cwe"]
            vuln.nvd_description = result["description"]
            vuln.patch_available = result["patch_available"]

        # Mark fetched regardless of success so we don't hammer the API
        vuln.nvd_fetched = True

    db.commit()
    logger.info("NVD enrichment complete")