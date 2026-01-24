import socket
import ssl
import datetime
import os
import time
import requests

# Fallback DNS (requires: pip install dnspython)
import dns.resolver
import dns.exception

DOMAINS = [
    "charts.zebpay.com",
    "auth.zebpay.com",
    "blog.zebpay.com",
    "chart.zebpay.com",
    "link.zebpay.com",
    "www.zebpay.com",
    "build.zebpay.com",
    "brave.zebpay.com",
    "v.zebpay.com",
    "static.zebpay.com",
    "zebpay.com",
    "emaildl.zebpay.com",
    "otc.zebpay.com",
    "help.zebpay.com",
    "connect.zebpay.com",
    "web.zebpay.com",
    "beta.zebpay.com",
    "pro.zebpay.com",
    "hvkyc.zebpay.com",
    "app.zebpay.com",
    "public.zebpay.com",
    # "zebapi.com",  # removed as discussed (timeouts from GitHub Actions)
    "walletdashboard.zebpay.co",
    "techsupport.zebpay.co",
    "download.zebpay.com",
    "enterpriseenrollment.zebpay.com",
    "api.zebpay.com",
    "onboarding.zebpay.com",
]

# Hosts that should NOT be TLS-validated because they are external aliases
SKIP_SSL = {
    "enterpriseenrollment.zebpay.com",  # CNAME to Microsoft; cert mismatch expected
}

# Public resolvers for fallback DNS (when system resolver flakes in CI)
FALLBACK_RESOLVERS = ["1.1.1.1", "8.8.8.8"]

alerts = []
healthy = []


# ---------------- Slack Helper ----------------
def send_slack(message: str) -> None:
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook:
        return
    requests.post(webhook, json={"text": message}, timeout=10)


# ---------------- DNS Fallback ----------------
def _fallback_dns_lookup(domain: str):
    """
    Resolve A/AAAA using public resolvers to avoid flaky system DNS in CI.
    Returns (ips:list[str], cname:str|None)
    """
    ips = set()
    cname = None

    for ns in FALLBACK_RESOLVERS:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [ns]
        r.timeout = 3
        r.lifetime = 5

        # Try A/AAAA
        for rtype in ("A", "AAAA"):
            try:
                ans = r.resolve(domain, rtype)
                for rr in ans:
                    ips.add(rr.to_text().strip())
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                pass
            except Exception:
                pass

        # Try CNAME (for context)
        try:
            ans = r.resolve(domain, "CNAME")
            for rr in ans:
                cname = rr.to_text().strip().rstrip(".")
        except Exception:
            pass

        if ips:
            break

    return sorted(ips), cname


# ---------------- DNS Check ----------------
def check_dns(domain: str):
    """
    1) Try system resolver (IPv4+IPv6) with retries.
    2) If it fails, fallback to public resolvers (dnspython).
    Returns: (ok: bool, ips: list[str])
    """
    last_err = None

    # Primary: system resolver (fast)
    for attempt in range(3):
        try:
            infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
            ips = sorted({info[4][0] for info in infos})
            if not ips:
                raise RuntimeError("No A/AAAA addresses returned")
            print(f"DNS OK: {domain} resolves to {', '.join(ips)}")
            return True, ips
        except Exception as e:
            last_err = e
            if attempt < 2:
                time.sleep(2)

    # Fallback: public resolvers
    ips, cname = _fallback_dns_lookup(domain)
    if ips:
        extra = f" (fallback via {', '.join(FALLBACK_RESOLVERS)})"
        print(f"DNS OK: {domain} resolves to {', '.join(ips)}{extra}")
        return True, ips

    # If we got a CNAME but no IPs, still give a helpful warning
    if cname:
        msg = f"⚠️ DNS WARNING: {domain} has CNAME → {cname} but no A/AAAA via fallback resolvers"
        print(msg)
        alerts.append(msg)
        return False, []

    msg = f"❌ DNS FAILED: {domain} → {last_err}"
    print(msg)
    alerts.append(msg)
    return False, []


# ---------------- SSL Check ----------------
def check_ssl(domain: str, ips_hint=None):
    """
    Try to connect by hostname first.
    If name resolution fails, retry using IPs from DNS fallback and SNI.
    """
    ips_hint = ips_hint or []

    def _connect(host: str, port: int, server_name: str):
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=server_name) as ssock:
                return ssock.getpeercert()

    try:
        # Normal path: connect using hostname
        cert = _connect(domain, 443, domain)

        exp_date = datetime.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=datetime.timezone.utc)

        now = datetime.datetime.now(datetime.timezone.utc)
        days_left = (exp_date - now).days

        if days_left < 0:
            msg = f"❌ SSL EXPIRED: {domain} (expired {-days_left} days ago)"
            print(msg)
            alerts.append(msg)
        elif days_left <= 7:
            msg = f"⚠️ SSL EXPIRING SOON: {domain} ({days_left} days left)"
            print(msg)
            alerts.append(msg)
        else:
            msg = f"✅ SSL OK: {domain} ({days_left} days left)"
            print(msg)
            healthy.append(f"{domain} ({days_left} days left)")

    except socket.gaierror as e:
        # Name resolution failed: try connecting via IPs (still uses SNI = domain)
        last_err = e
        for ip in ips_hint:
            try:
                cert = _connect(ip, 443, domain)

                exp_date = datetime.datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=datetime.timezone.utc)

                now = datetime.datetime.now(datetime.timezone.utc)
                days_left = (exp_date - now).days

                if days_left < 0:
                    msg = f"❌ SSL EXPIRED: {domain} (expired {-days_left} days ago) [via {ip}]"
                    print(msg)
                    alerts.append(msg)
                elif days_left <= 7:
                    msg = f"⚠️ SSL EXPIRING SOON: {domain} ({days_left} days left) [via {ip}]"
                    print(msg)
                    alerts.append(msg)
                else:
                    msg = f"✅ SSL OK: {domain} ({days_left} days left) [via {ip}]"
                    print(msg)
                    healthy.append(f"{domain} ({days_left} days left)")
                return
            except Exception as ee:
                last_err = ee

        msg = f"❌ SSL ERROR: {domain} → {last_err}"
        print(msg)
        alerts.append(msg)

    except Exception as e:
        msg = f"❌ SSL ERROR: {domain} → {e}"
        print(msg)
        alerts.append(msg)


# ---------------- Main ----------------
for domain in DOMAINS:
    print("\n-----------------------------------")
    print(f"Checking {domain}...")

    dns_ok, ips = check_dns(domain)

    if domain in SKIP_SSL:
        print(f"SSL SKIP: {domain} (external alias; cert mismatch expected)")
        continue

    # Even if system DNS fails, we may have IPs via fallback; check_ssl can use them.
    if dns_ok or ips:
        check_ssl(domain, ips)
    else:
        print(f"SSL SKIP: {domain} (DNS failed; no IPs to attempt TLS)")

print("\n===================================")

# ---------------- Slack Summary ----------------
if alerts:
    message = (
        "🚨 *SSL / DNS Issues Detected*\n\n"
        + "\n".join(alerts)
        + "\n\n✅ *Rest of the domains are healthy.*"
    )
    send_slack(message)
else:
    message = (
        "✅ *All domains are healthy*\n\n"
        + "\n".join(f"• {d}" for d in healthy)
    )
    send_slack(message)
