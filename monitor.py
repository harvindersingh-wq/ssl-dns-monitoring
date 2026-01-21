#!/usr/bin/env python3

import socket
import ssl
from datetime import datetime, timezone
import dns.resolver
import time
import requests
import os
from concurrent.futures import ThreadPoolExecutor

# ================= CONFIG =================
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
    "zebapi.com",
    "walletdashboard.zebpay.co",
    "techsupport.zebpay.co",
    "download.zebpay.com",
    "enterpriseenrollment.zebpay.com",
    "api.zebpay.com",
    "onboarding.zebpay.com"
]

SSL_WARNING_DAYS = 7
SSL_TIMEOUT = 20  # seconds
SSL_RETRIES = 2   # retry once on handshake failure

# Get Slack webhook from environment variable
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")


# ================= FUNCTIONS =================
def send_alert(message):
    """Send alert to Slack and print locally"""
    print(f"ALERT: {message}")  # local output
    if SLACK_WEBHOOK_URL:
        try:
            payload = {"text": f":warning: {message}"}
            requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        except Exception as e:
            print(f"Failed to send alert to Slack: {e}")


def check_dns(domain):
    """Check if domain resolves"""
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip_list = [rdata.address for rdata in answers]
        print(f"DNS OK: {domain} resolves to {', '.join(ip_list)}")
    except Exception as e:
        send_alert(f"DNS issue detected for {domain} -> {e}")


def check_ssl(domain):
    """Check SSL certificate validity"""
    if domain.startswith("http://"):
        print(f"Skipping SSL check for non-HTTPS domain: {domain}")
        return

    for attempt in range(SSL_RETRIES):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=SSL_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

            exp_str = cert['notAfter']
            exp_date = datetime.strptime(exp_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (exp_date - now).days

            if days_left < 0:
                send_alert(f"SSL certificate for {domain} has EXPIRED!")
            elif days_left <= SSL_WARNING_DAYS:
                send_alert(f"SSL certificate for {domain} is about to expire -> {days_left} days left")
            else:
                print(f"SSL OK: {domain} certificate valid for {days_left} more days")
            return  # success

        except Exception as e:
            if attempt < SSL_RETRIES - 1:
                print(f"Retrying SSL check for {domain} due to error: {e}")
                time.sleep(2)
            else:
                send_alert(f"SSL issue detected for {domain} -> {e}")


def monitor_domain(domain):
    """Check DNS and SSL for a single domain"""
    print(f"\nChecking {domain}...")
    check_dns(domain)
    check_ssl(domain)
    print("-----------------------------------")


def main():
    """Main monitoring loop (parallel for speed)"""
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(monitor_domain, DOMAINS)


if __name__ == "__main__":
    main()

