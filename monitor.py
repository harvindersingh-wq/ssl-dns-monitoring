import socket
import ssl
import datetime
import os
import time
import requests

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
    # "zebapi.com",  # removed
    "walletdashboard.zebpay.co",
    "techsupport.zebpay.co",
    "download.zebpay.com",
    "enterpriseenrollment.zebpay.com",
    "api.zebpay.com",
    "onboarding.zebpay.com",
]

# Hosts that should NOT be TLS-validated because they are external aliases
# (DNS may point to a third-party that will not serve a cert for zebpay.com hostnames)
SKIP_SSL = {
    "enterpriseenrollment.zebpay.com",  # CNAME to Microsoft; cert mismatch expected
}

alerts = []
healthy = []

# ---------------- Slack Helper ----------------
def send_slack(message):
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook:
        return
    requests.post(webhook, json={"text": message}, timeout=10)

# ---------------- DNS Check ----------------
def check_dns(domain):
    """
    Resolve both IPv4 (A) and IPv6 (AAAA) using getaddrinfo(),
    with a single retry to avoid transient resolver flaps.
    """
    last_err = None
    for attempt in range(2):
        try:
            infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
            ips = sorted({info[4][0] for info in infos})
            if not ips:
                raise RuntimeError("No A/AAAA addresses returned")

            print(f"DNS OK: {domain} resolves to {', '.join(ips)}")
            return True

        except Exception as e:
            last_err = e
            if attempt == 0:
                time.sleep(1)

    msg = f"❌ DNS FAILED: {domain} → {last_err}"
    print(msg)
    alerts.append(msg)
    return False

# ---------------- SSL Check ----------------
def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

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

    except Exception as e:
        msg = f"❌ SSL ERROR: {domain} → {e}"
        print(msg)
        alerts.append(msg)

# ---------------- Main ----------------
for domain in DOMAINS:
    print("\n-----------------------------------")
    print(f"Checking {domain}...")

    if check_dns(domain):
        if domain in SKIP_SSL:
            print(f"SSL SKIP: {domain} (external alias; cert mismatch expected)")
        else:
            check_ssl(domain)

print("\n===================================")

# ---------------- Slack Summary ----------------
if alerts:
    message = (
        "🚨 *SSL / DNS Issues Detected*\n\n"
        + "\n".join(alerts)
    )
    send_slack(message)
else:
    message = (
        "✅ *All domains are healthy*\n\n"
        + "\n".join(f"• {d}" for d in healthy)
    )
    send_slack(message)
