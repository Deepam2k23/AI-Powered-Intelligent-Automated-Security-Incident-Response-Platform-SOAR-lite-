"""Step 4: Decision engine."""

def should_block(ioc, abuse_info):
    rule = ioc.get("rule_desc", "").lower()

    # Immediately block reconnaissance attacks
    if "nmap" in rule:
        return True

    if "suricata" in rule:
        return True

    # Otherwise use AbuseIPDB reputation
    return abuse_info.get("abuse_score", 0) >= 50
