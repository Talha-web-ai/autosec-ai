def calculate_severity(port, service, cve_count):
    if cve_count >= 3:
        return "High"
    if cve_count >= 1:
        return "Medium"

    if port in [22, 3389]:
        return "Medium"

    return "Low"
