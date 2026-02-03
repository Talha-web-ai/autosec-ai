import subprocess
import json
import os
import tempfile

def run_nikto(target):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        output_file = tmp.name

    command = [
        "nikto",
        "-h", target,
        "-Format", "json",
        "-output", output_file
    ]

    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        with open(output_file, "r") as f:
            data = json.load(f)
    except Exception:
        data = {}

    os.remove(output_file)
    return data
