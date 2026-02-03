import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def lookup_cves(service, version, max_results=3):
    if not service or service == "unknown":
        return []

    query = f"{service} {version}".strip()

    params = {
        "keywordSearch": query,
        "resultsPerPage": max_results
    }

    try:
        r = requests.get(NVD_API, params=params, timeout=10)
        data = r.json()
    except Exception:
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cves.append({
            "id": cve.get("id"),
            "description": cve.get("descriptions", [{}])[0].get("value", "")
        })

    return cves
