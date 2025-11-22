# whois.py

import subprocess
import re
from typing import Dict, Optional

def _get_ip_range(whois_output: str) -> Optional[str]:
    """
    Parses WHOIS output for an IP address to find the CIDR block or NetRange.
    Args:
        whois_output: The raw text output from the whois command.
    Returns:
        The CIDR block string (e.g., "192.168.1.0/24") or NetRange if found, otherwise None.
    """
    # Search for CIDR first, as it's more precise for scanning
    cidr_match = re.search(r'CIDR:\s*([0-9./]+)', whois_output, re.IGNORECASE)
    if cidr_match:
        return cidr_match.group(1).strip()

    # Fallback to NetRange if CIDR is not found
    netrange_match = re.search(r'NetRange:\s*([0-9.\s-]+)', whois_output, re.IGNORECASE)
    if netrange_match:
        # The range is often in the format "IP1 - IP2". nmap can handle this format.
        return netrange_match.group(1).strip()

    return None

def get_whois_info(target: str) -> Dict:
    """
    Retrieves public registration (WHOIS) information for a given domain name or IP address,
    after validating the input for security. If an IP address is provided, it also
    attempts to extract the IP range (CIDR or NetRange).
    Args:
        target: The domain (e.g., example.com) or IP address to look up.
    Returns:
        A dictionary containing the WHOIS output or an error message.
        If an IP is given, the dictionary may also contain an 'ip_range'.
    """
    # 1. Input Validation for Security
    if not isinstance(target, str):
        return {
            "status": "error",
            "message": "Input must be a string."
        }
    
    # Regex for domain names
    domain_regex = re.compile(
        r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$',
        re.IGNORECASE
    )
    
    # Regex for IPv4 addresses
    ip_regex = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')

    is_domain = domain_regex.match(target)
    is_ip = ip_regex.match(target)

    if not is_domain and not is_ip:
        return {
            "status": "error",
            "message": f"Invalid format: '{target}'. Input must be a valid domain name or IP address and must not contain shell metacharacters."
        }

    # 2. Safe Command Execution
    try:
        result = subprocess.run(
            ['whois', target],
            capture_output=True,
            text=True,
            check=True,
            timeout=10
        )
        
        output = result.stdout.strip()
        response = {
            "status": "success",
            "target": target,
            "output": output
        }

        if is_ip:
            ip_range = _get_ip_range(output)
            if ip_range:
                response["ip_range"] = ip_range

        return response
        
    except subprocess.CalledProcessError as e:
        return {
            "status": "error",
            "message": f"Whois command failed: {e.stderr.strip()}",
            "command": e.cmd
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"An unexpected error occurred: {str(e)}"
        }