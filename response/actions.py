"""
Response actions. kill_process still reaches into the Windows guest via
vmrun (same mechanism the pipeline already uses). block_ip now genuinely
blocks at the network perimeter -- it adds the attacker's IP to an OPNsense
firewall alias via OPNsense's own REST API, rather than the endpoint's own
Windows Firewall. This is the actual point of having built OPNsense: the
block happens before traffic ever reaches the victim, not after.

Every function still defaults to dry_run=True. Nothing executes for real
unless dry_run is explicitly set to False.

SETUP REQUIRED (one time, in OPNsense's web GUI) before block_ip/unblock_ip
can work live:
  1. Firewall -> Aliases -> +Add. Name: SOC_Blocked_IPs. Type: Host(s).
  2. Firewall -> Rules -> WAN -> +Add. Action: Block. Source: SOC_Blocked_IPs
     (type the alias name directly into the source field). Drag this rule
     to the TOP of the WAN rule list -- it must be evaluated before your
     existing allow rule, or the block never takes effect.
  3. System -> Access -> Users -> your admin user -> API keys -> "+".
     Fill OPNSENSE_API_KEY / OPNSENSE_API_SECRET below with the downloaded
     values. Never commit real values to git -- keep them here only on
     your own machine, or better, load them from an environment variable.
"""

import subprocess
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VMRUN_PATH = r"C:\Program Files\VMware\VMware Workstation\vmrun.exe"
VMX_PATH = r"C:\Users\Zirar\Documents\Virtual Machines\Victim-Win10-v2\Victim-Win10.vmx"

# --- OPNsense API settings -- fill these in from your generated API key ---
OPNSENSE_HOST = "https://192.168.20.1"
OPNSENSE_API_KEY = "PASTE_YOUR_API_KEY_HERE"
OPNSENSE_API_SECRET = "PASTE_YOUR_API_SECRET_HERE"
OPNSENSE_ALIAS_NAME = "SOC_Blocked_IPs"


def run_in_guest(guest_user, guest_password, program, args, dry_run=True):
    """Run a program inside the guest VM via vmrun. Returns (success, output)."""
    cmd_display = f"{program} {' '.join(args)}"
    if dry_run:
        return True, f"[DRY RUN] Would execute inside guest: {cmd_display}"

    cmd = [
        VMRUN_PATH, "-T", "ws",
        "-gu", guest_user, "-gp", guest_password,
        "runProgramInGuest", VMX_PATH,
        program
    ] + args

    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def kill_process(pid, guest_user, guest_password, dry_run=True):
    """Kill a process inside the guest VM by PID."""
    if not pid:
        return False, "No PID provided -- nothing to kill"
    return run_in_guest(
        guest_user, guest_password,
        r"C:\Windows\System32\taskkill.exe",
        ["/PID", str(pid), "/F"],
        dry_run=dry_run
    )


def verify_process_killed(pid, guest_user, guest_password, dry_run=True):
    if dry_run or not pid:
        return None
    success, output = run_in_guest(
        guest_user, guest_password,
        r"C:\Windows\System32\tasklist.exe",
        ["/FI", f"PID eq {pid}"],
        dry_run=False
    )
    return success and str(pid) not in output


def block_ip(ip_address, guest_user, guest_password, dry_run=True):
    """
    Block an IP at the network perimeter, by adding it to OPNsense's
    SOC_Blocked_IPs alias via the OPNsense REST API. guest_user/guest_password
    are accepted for signature compatibility with kill_process but not
    actually used here -- this action never touches the Windows guest.
    """
    if not ip_address:
        return False, "No IP address provided -- nothing to block"

    url = f"{OPNSENSE_HOST}/api/firewall/alias_util/add/{OPNSENSE_ALIAS_NAME}"

    if dry_run:
        return True, f"[DRY RUN] Would POST to {url} with address={ip_address}"

    try:
        resp = requests.post(
            url,
            auth=(OPNSENSE_API_KEY, OPNSENSE_API_SECRET),
            json={"address": ip_address},
            verify=False,
            timeout=10,
        )
        data = resp.json()
        success = data.get("status") == "done"
        return success, str(data)
    except Exception as e:
        return False, f"OPNsense API call failed: {e}"


def unblock_ip(ip_address, dry_run=True):
    """
    Remove an IP from the SOC_Blocked_IPs alias -- use this between test
    runs so the same Kali IP can attack again without needing to touch
    OPNsense's GUI by hand each time.
    """
    if not ip_address:
        return False, "No IP address provided"

    url = f"{OPNSENSE_HOST}/api/firewall/alias_util/delete/{OPNSENSE_ALIAS_NAME}"

    if dry_run:
        return True, f"[DRY RUN] Would POST to {url} with address={ip_address}"

    try:
        resp = requests.post(
            url,
            auth=(OPNSENSE_API_KEY, OPNSENSE_API_SECRET),
            json={"address": ip_address},
            verify=False,
            timeout=10,
        )
        data = resp.json()
        success = data.get("status") == "done"
        return success, str(data)
    except Exception as e:
        return False, f"OPNsense API call failed: {e}"


def verify_ip_blocked(ip_address, guest_user, guest_password, dry_run=True):
    """Best-effort check: fetch the alias's current contents and look for the IP."""
    if dry_run or not ip_address:
        return None
    try:
        url = f"{OPNSENSE_HOST}/api/firewall/alias_util/list/{OPNSENSE_ALIAS_NAME}"
        resp = requests.get(url, auth=(OPNSENSE_API_KEY, OPNSENSE_API_SECRET), verify=False, timeout=10)
        return ip_address in resp.text
    except Exception:
        return None
