# nmap.py

import subprocess
import re
from typing import Dict

def nmap_scan(ip_range: str) -> Dict:
    """
    Performs an Nmap ping scan (-PE) on the first 5 IPs of a given IP address or range.

    Args:
        ip_range: The IP address or range to scan (e.g., "192.168.1.0/24").

    Returns:
        A dictionary containing the Nmap output or an error message.
    """
    # 1. Input Validation for Security
    if not isinstance(ip_range, str):
        return {
            "status": "error",
            "message": "Input must be a string."
        }

    # Regex to validate an IP address or CIDR notation.
    # This is a simplified regex for this example.
    ip_regex = re.compile(r"^[0-9./\s-]+$")
    if not ip_regex.match(ip_range):
        return {
            "status": "error",
            "message": f"Invalid IP range format: '{ip_range}'. Input must be a valid IP address, CIDR notation, or IP range."
        }

    # 2. Resolve IP range to a list of targets and take the first 5
    try:
        # Use nmap's list scan (-sL) to resolve the range to a list of hosts.
        # -n avoids DNS resolution.
        sL_result = subprocess.run(
            ['nmap', '-sL', '-n', ip_range],
            capture_output=True,
            text=True,
            check=True,
            timeout=60
        )
        # Extract IPs from output. Example line: "Nmap scan report for 192.168.1.1"
        all_targets = re.findall(r"Nmap scan report for (\S+)", sL_result.stdout)
        
        if not all_targets:
            return {
                "status": "success",
                "ip_range": ip_range,
                "output": "No targets found in the given range."
            }
            
        targets_to_scan = all_targets[:5]

    except subprocess.CalledProcessError as e:
        return {
            "status": "error",
            "message": f"Failed to resolve IP range with 'nmap -sL': {e.stderr.strip()}",
            "command": e.cmd
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"An unexpected error occurred during IP range resolution: {str(e)}"
        }

    print(f"First 5 IPs to be scanned: {targets_to_scan}")

    # 3. Safe Command Execution
    try:
        command = ['nmap', '-sn', '-PE'] + targets_to_scan
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=60  # Increased timeout for potentially long scans
        )
        return {
            "status": "success",
            "ip_range": ip_range,
            "scanned_targets": targets_to_scan,
            "output": result.stdout.strip()
        }
    except subprocess.CalledProcessError as e:
        return {
            "status": "error",
            "message": f"Nmap command failed: {e.stderr.strip()}",
            "command": e.cmd
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"An unexpected error occurred: {str(e)}"
        }
