#!/usr/bin/env python3
"""
Query phpIPAM subnets and enable the custom field `vRA_Range`
"""

import requests

# -----------------------------
# CONFIGURATION
# -----------------------------
API_HOST = "https://api.host.org"
API_APP_ID = "AriaID"
USERNAME = "username"
PASSWORD = "password"
VERIFY_SSL = True

# List of subnets to query
SUBNETS = [
    "10.1.1.0/24",
    "10.1.2.0/24"
]

# -----------------------------
# FUNCTIONS
# -----------------------------

def set_vra_range(subnet_id, headers, value=1):
    """Update the custom_vRA_Range field for a subnet."""
    uri = f"{API_HOST}/api/{API_APP_ID}/subnets/{subnet_id}/"
    payload = {"custom_vRA_Range": value}
    resp = requests.patch(uri, json=payload, headers=headers, verify=VERIFY_SSL)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise Exception(f"Failed to update vRA_Range: {data.get('message')}")
    return True

def get_token():
    """Authenticate and return token header dict"""
    auth_uri = f"{API_HOST}/api/{API_APP_ID}/user/"
    resp = requests.post(auth_uri, auth=(USERNAME, PASSWORD), verify=VERIFY_SSL)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise Exception(f"Auth failed: {data}")
    return {"token": data["data"]["token"]}


def get_subnet_info_by_cidr(cidr, headers):
    """Get subnet details by CIDR string."""
    network, mask = cidr.split("/")
    uri = f"{API_HOST}/api/{API_APP_ID}/subnets/cidr/{network}/{mask}/"
    resp = requests.get(uri, headers=headers, verify=VERIFY_SSL)

    if resp.status_code == 404:
        return None

    resp.raise_for_status()
    return resp.json()


def main():
    token = get_token()

    print(f"\nQuerying subnets: {SUBNETS}\n")
    for cidr in SUBNETS:
        try:
            info = get_subnet_info_by_cidr(cidr, token)
            if not info:
                print(f"[{cidr}] Not found in phpIPAM")
                continue

            if not info.get("success"):
                print(f"[{cidr}] Failed: {info.get('message')}")
                continue

            data = info["data"]

            # Handle list vs single object
            subnets = data if isinstance(data, list) else [data]

            for subnet in subnets:
                vra_range = subnet.get("custom_vRA_Range", "NOT SET")
                subnet_id = subnet.get("id")
                cidr_out = f"{subnet['subnet']}/{subnet['mask']}"
                print(f"[{subnet_id}] {cidr_out} -> vRA_Range = {vra_range}")

                # Set vRA_Range to 1
                try:
                    set_vra_range(subnet_id, token, value=1)
                    print(f"[{subnet_id}] {cidr_out} -> vRA_Range successfully set to 1")
                except Exception as e:
                    print(f"[{subnet_id}] Error setting vRA_Range: {e}")

        except Exception as e:
            print(f"[{cidr}] Error: {e}")


if __name__ == "__main__":
    main()
    
