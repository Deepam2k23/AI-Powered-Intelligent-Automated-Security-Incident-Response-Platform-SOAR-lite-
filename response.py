"""Step 5: Response action - block via iptables."""

#import subprocess


#def block_ip(ip):
#    subprocess.run(
#        ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
#        check=True,
#    )

"""Response action: block and unblock IP addresses using iptables."""

import ipaddress
import subprocess


IPTABLES = "/usr/sbin/iptables"


def validate_ip(ip):
    """Validate and normalize an IPv4 or IPv6 address."""

    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


def is_blocked(ip):
    """Check whether an IP already has an INPUT DROP rule."""

    valid_ip = validate_ip(ip)

    if not valid_ip:
        return False

    result = subprocess.run(
        [
            IPTABLES,
            "-C",
            "INPUT",
            "-s",
            valid_ip,
            "-j",
            "DROP",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    return result.returncode == 0


def block_ip(ip):
    """
    Add an iptables INPUT DROP rule.

    Returns:
        True  - IP is blocked
        False - blocking failed
    """

    valid_ip = validate_ip(ip)

    if not valid_ip:
        print(f"[RESPONSE ERROR] Invalid IP address: {ip}")
        return False

    if is_blocked(valid_ip):
        print(f"[RESPONSE] {valid_ip} is already blocked in iptables.")
        return True

    result = subprocess.run(
        [
            IPTABLES,
            "-A",
            "INPUT",
            "-s",
            valid_ip,
            "-j",
            "DROP",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(
            f"[RESPONSE ERROR] Failed to block {valid_ip}: "
            f"{result.stderr.strip()}"
        )
        return False

    if not is_blocked(valid_ip):
        print(
            f"[RESPONSE ERROR] Rule command succeeded, but "
            f"{valid_ip} was not found in iptables."
        )
        return False

    print(f"[RESPONSE] Firewall DROP rule created for {valid_ip}")
    return True


def unblock_ip(ip):
    """Remove all matching INPUT DROP rules for an IP."""

    valid_ip = validate_ip(ip)

    if not valid_ip:
        print(f"[RESPONSE ERROR] Invalid IP address: {ip}")
        return False

    removed = False

    while is_blocked(valid_ip):
        result = subprocess.run(
            [
                IPTABLES,
                "-D",
                "INPUT",
                "-s",
                valid_ip,
                "-j",
                "DROP",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print(
                f"[RESPONSE ERROR] Failed to unblock {valid_ip}: "
                f"{result.stderr.strip()}"
            )
            return False

        removed = True

    if removed:
        print(f"[RESPONSE] Unblocked {valid_ip}")
    else:
        print(f"[RESPONSE] {valid_ip} was not blocked.")

    return True
