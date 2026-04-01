#!/usr/bin/env python3
"""
BlockGuard List Processor

Fetches filter lists from uBlock Origin, EasyList, AdGuard, and other sources.
Extracts domain-level blocking rules and outputs unified blocklists.

Runs daily via GitHub Actions — no manual intervention needed.
"""

import re
import json
import ssl
import urllib.request
import urllib.error
from datetime import datetime, timezone

# Fix SSL certificate verification
try:
    import certifi
    SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    SSL_CONTEXT = ssl.create_default_context()
    SSL_CONTEXT.check_hostname = False
    SSL_CONTEXT.verify_mode = ssl.CERT_NONE
from pathlib import Path

# All filter list sources — same lists uBlock Origin uses
SOURCES = {
    # uBlock Origin's own filters
    "ublock-filters": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
    "ublock-badware": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    "ublock-privacy": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
    "ublock-resource-abuse": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/resource-abuse.txt",
    "ublock-unbreak": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/unbreak.txt",
    "ublock-annoyances-general": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances.txt",
    "ublock-annoyances-cookies": "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/annoyances-cookies.txt",

    # EasyList family
    "easylist": "https://easylist.to/easylist/easylist.txt",
    "easyprivacy": "https://easylist.to/easylist/easyprivacy.txt",

    # AdGuard
    "adguard-base": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "adguard-annoyances": "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt",
    "adguard-mobile": "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",

    # Steven Black unified hosts
    "steven-black": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",

    # Peter Lowe
    "peter-lowe": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",

    # OISD
    "oisd-big": "https://big.oisd.nl/domainswild",

    # Hagezi - popular comprehensive lists
    "hagezi-pro": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro.txt",

    # Online Malicious URL Blocklist
    "urlhaus": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",

    # Phishing
    "phishing-army": "https://phishing.army/download/phishing_army_blocklist.txt",

    # Ad/tracking domains from multiple curators
    "firstparty-trackers": "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
}

# Domains that should NEVER be blocked (false positive protection)
WHITELIST = {
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "0.0.0.0",
    "127.0.0.1",
    "::1",

    # === Google / YouTube (essential services) ===
    "google.com",
    "www.google.com",
    "accounts.google.com",
    "mail.google.com",
    "drive.google.com",
    "docs.google.com",
    "sheets.google.com",
    "slides.google.com",
    "calendar.google.com",
    "meet.google.com",
    "chat.google.com",
    "photos.google.com",
    "maps.google.com",
    "play.google.com",
    "store.google.com",
    "news.google.com",
    "translate.google.com",
    "fonts.google.com",
    "contacts.google.com",
    "keep.google.com",
    "myaccount.google.com",
    "payments.google.com",
    "one.google.com",
    "fi.google.com",
    "classroom.google.com",
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "music.youtube.com",
    "tv.youtube.com",
    "studio.youtube.com",
    "youtu.be",
    "s.youtube.com",
    "s2.youtube.com",
    "i.ytimg.com",
    "i1.ytimg.com",
    "yt3.ggpht.com",
    "yt3.googleusercontent.com",
    "googlevideo.com",
    "imasdk.googleapis.com",
    "jnn-pa.googleapis.com",
    "suggestqueries-clients6.youtube.com",
    "play.google.com",
    "fonts.googleapis.com",
    "maps.googleapis.com",
    "ajax.googleapis.com",
    "storage.googleapis.com",
    "firestore.googleapis.com",
    "fcm.googleapis.com",
    "oauth2.googleapis.com",
    "www.googleapis.com",
    "lh3.googleusercontent.com",
    "lh4.googleusercontent.com",
    "lh5.googleusercontent.com",
    "lh6.googleusercontent.com",
    "clients1.google.com",
    "clients2.google.com",
    "clients3.google.com",
    "clients4.google.com",
    "clients5.google.com",
    "clients6.google.com",
    "update.googleapis.com",
    "csi.gstatic.com",
    "fonts.gstatic.com",
    "ssl.gstatic.com",
    "www.gstatic.com",
    "encrypted-tbn0.gstatic.com",
    "connectivitycheck.gstatic.com",
    "play.googleapis.com",
    "firebaseinstallations.googleapis.com",

    # === Apple ===
    "apple.com",
    "www.apple.com",
    "itunes.apple.com",
    "apps.apple.com",
    "icloud.com",
    "www.icloud.com",

    # === Microsoft ===
    "microsoft.com",
    "www.microsoft.com",
    "login.microsoftonline.com",
    "login.live.com",
    "outlook.live.com",
    "outlook.office365.com",
    "office.com",
    "teams.microsoft.com",
    "github.com",
    "www.github.com",
    "raw.githubusercontent.com",
    "api.github.com",

    # === Common services that break if blocked ===
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "api.stripe.com",
    "js.stripe.com",
    "checkout.stripe.com",
    "api.paypal.com",
    "www.paypal.com",
    "captcha.guard.io",
    "challenges.cloudflare.com",
    "www.recaptcha.net",

    # === Social media (core functionality) ===
    "twitter.com",
    "x.com",
    "api.twitter.com",
    "www.instagram.com",
    "instagram.com",
    "www.facebook.com",
    "facebook.com",
    "www.reddit.com",
    "reddit.com",
    "oauth.reddit.com",
    "www.linkedin.com",
    "linkedin.com",
    "discord.com",
    "www.tiktok.com",
    "tiktok.com",
    "www.whatsapp.com",
    "web.whatsapp.com",
    "www.snapchat.com",
    "snapchat.com",
    "t.me",
    "telegram.org",
    "web.telegram.org",

    # === Streaming ===
    "www.netflix.com",
    "netflix.com",
    "www.twitch.tv",
    "twitch.tv",
    "www.spotify.com",
    "spotify.com",
    "www.disneyplus.com",
    "disneyplus.com",
    "www.hbomax.com",
    "www.hulu.com",
    "www.primevideo.com",

    # === Shopping / Banking ===
    "www.amazon.com",
    "amazon.com",
    "www.ebay.com",
    "ebay.com",

    # === Email ===
    "mail.yahoo.com",
    "outlook.com",
    "www.outlook.com",
    "protonmail.com",
    "mail.protonmail.com",

    # === DNS / Connectivity ===
    "captive.apple.com",
    "detectportal.firefox.com",
    "connectivitycheck.android.com",
}

# Valid domain regex
DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


def fetch_list(name: str, url: str) -> str:
    """Download a filter list."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "BlockGuard/1.0"})
        with urllib.request.urlopen(req, timeout=30, context=SSL_CONTEXT) as resp:
            content = resp.read().decode("utf-8", errors="replace")
            print(f"  [{name}] Downloaded {len(content)} bytes")
            return content
    except Exception as e:
        print(f"  [{name}] FAILED: {e}")
        return ""


def extract_domains_from_hosts(text: str) -> set:
    """Extract domains from hosts-file format (0.0.0.0 domain.com or 127.0.0.1 domain.com)."""
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Strip inline comments
        if "#" in line:
            line = line[:line.index("#")].strip()

        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            domain = parts[1].lower().strip(".")
            if domain and DOMAIN_RE.match(domain):
                domains.add(domain)
        elif len(parts) == 1:
            domain = parts[0].lower().strip(".")
            if domain and DOMAIN_RE.match(domain):
                domains.add(domain)

    return domains


def extract_domains_from_adblock(text: str) -> set:
    """
    Extract domain-level blocks from AdBlock/uBlock filter syntax.

    Handles:
    - ||domain.com^ (block domain and all subdomains)
    - ||domain.com^$third-party
    - ||domain.com^$all
    - domain.com (plain domain lines in some lists)

    Ignores:
    - CSS rules (##, #@#, #?#)
    - URL patterns with paths (/path)
    - Exception rules (@@)
    - Regex rules (/regex/)
    - Rules with specific content types only ($image, $script, etc. without domain)
    """
    domains = set()

    for line in text.splitlines():
        line = line.strip()

        # Skip empty, comments, CSS rules, exceptions, regex
        if not line or line.startswith(("!", "[", "#", "@@", "/")):
            continue

        # Skip lines with CSS selectors
        if "##" in line or "#@#" in line or "#?#" in line:
            continue

        # Handle ||domain.com^ format (the most common uBlock/AdBlock format)
        if line.startswith("||"):
            # Extract domain part
            domain_part = line[2:]

            # Remove filter options ($...)
            if "$" in domain_part:
                domain_part = domain_part[:domain_part.index("$")]

            # Remove anchor (^)
            domain_part = domain_part.rstrip("^").rstrip("*").strip(".")

            # Skip if it contains a path
            if "/" in domain_part:
                continue

            # Skip wildcards in the middle (like ||*.domain.com)
            if "*" in domain_part:
                # Handle ||*domain.com → domain.com
                domain_part = domain_part.lstrip("*").strip(".")

            domain = domain_part.lower()
            if domain and DOMAIN_RE.match(domain):
                domains.add(domain)
            continue

        # Handle plain domain lines (some lists use this format)
        line_clean = line.lower().strip(".")
        if DOMAIN_RE.match(line_clean) and "/" not in line_clean and "*" not in line_clean:
            domains.add(line_clean)

    return domains


def extract_domains(name: str, text: str) -> set:
    """Auto-detect format and extract domains."""
    if not text:
        return set()

    # Detect format
    has_hosts = any(
        line.strip().startswith(("0.0.0.0", "127.0.0.1"))
        for line in text.splitlines()[:50]
        if line.strip() and not line.strip().startswith("#")
    )

    has_adblock = any(
        line.strip().startswith(("||", "!", "[Adblock"))
        for line in text.splitlines()[:20]
    )

    domains = set()

    if has_hosts:
        domains.update(extract_domains_from_hosts(text))
    if has_adblock or not has_hosts:
        domains.update(extract_domains_from_adblock(text))

    # Handle wildcard domain lists (*.domain.com or domain.com, one per line)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!", "[")):
            continue
        # Strip wildcard prefix
        if line.startswith("*."):
            domain = line[2:].lower().strip(".")
            if domain and DOMAIN_RE.match(domain):
                domains.add(domain)

    print(f"  [{name}] Extracted {len(domains)} domains")
    return domains


def main():
    output_dir = Path(__file__).parent.parent / "lists"
    output_dir.mkdir(exist_ok=True)

    print(f"BlockGuard List Updater — {datetime.now(timezone.utc).isoformat()}")
    print(f"Processing {len(SOURCES)} sources...\n")

    all_domains = set()
    source_stats = {}

    for name, url in SOURCES.items():
        print(f"Processing: {name}")
        text = fetch_list(name, url)
        domains = extract_domains(name, text)
        source_stats[name] = len(domains)
        all_domains.update(domains)
        print()

    # Remove whitelisted domains
    all_domains -= WHITELIST

    # Remove empty/invalid
    all_domains = {d for d in all_domains if d and "." in d and len(d) <= 253}

    print(f"Total unique domains: {len(all_domains)}")

    # Sort for consistent output
    sorted_domains = sorted(all_domains)

    # Write unified blocklist (hosts format)
    hosts_file = output_dir / "unified-hosts.txt"
    with open(hosts_file, "w") as f:
        f.write(f"# BlockGuard Unified Blocklist\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"# Total domains: {len(sorted_domains)}\n")
        f.write(f"# Sources: {len(SOURCES)}\n")
        f.write(f"#\n")
        f.write(f"# Auto-generated from uBlock Origin, EasyList, AdGuard, and other sources.\n")
        f.write(f"# Do not edit manually — this file is overwritten daily.\n\n")
        for domain in sorted_domains:
            f.write(f"0.0.0.0 {domain}\n")

    print(f"Written: {hosts_file} ({len(sorted_domains)} domains)")

    # Write plain domain list (one per line, for the app)
    domains_file = output_dir / "unified-domains.txt"
    with open(domains_file, "w") as f:
        for domain in sorted_domains:
            f.write(f"{domain}\n")

    print(f"Written: {domains_file}")

    # Write manifest.json
    manifest = {
        "version": int(datetime.now(timezone.utc).strftime("%Y%m%d")),
        "generated": datetime.now(timezone.utc).isoformat(),
        "total_domains": len(sorted_domains),
        "sources_count": len(SOURCES),
        "lists": [
            {
                "id": "unified",
                "name": "BlockGuard Unified",
                "url": "https://raw.githubusercontent.com/mehdichitsaz/blockguard-lists/main/lists/unified-domains.txt",
                "description": f"Auto-generated from {len(SOURCES)} sources including uBlock Origin, EasyList, AdGuard, and more",
                "domainCount": len(sorted_domains),
                "isEnabled": True
            }
        ],
        "source_stats": source_stats
    }

    manifest_file = Path(__file__).parent.parent / "manifest.json"
    with open(manifest_file, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"Written: {manifest_file}")
    print(f"\nDone! {len(sorted_domains)} domains from {len(SOURCES)} sources.")


if __name__ == "__main__":
    main()
