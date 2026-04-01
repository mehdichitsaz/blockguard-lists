# BlockGuard Lists

Auto-updated ad, tracker, and malware domain blocklists for the [BlockGuard](https://github.com/mehdichitsaz/BlockGuard) iOS app.

## Sources

Domains are extracted from 19 filter list sources including:

- **uBlock Origin** filters, badware, privacy, resource-abuse
- **EasyList** and **EasyPrivacy**
- **AdGuard** Base, Annoyances, Mobile
- **Steven Black** unified hosts
- **Peter Lowe's** ad servers
- **OISD Big** curated blocklist
- **Hagezi Pro** comprehensive list
- **URLhaus** malware filter
- **Phishing Army** blocklist
- **First-party trackers** list

## How It Works

A GitHub Action runs every 6 hours:
1. Fetches all source filter lists
2. Extracts domain-level blocking rules
3. Deduplicates and merges into a unified list
4. Commits changes if the list has changed

The BlockGuard app periodically fetches `manifest.json` and downloads the updated domain list.

## Files

- `manifest.json` — list metadata and download URLs
- `lists/unified-domains.txt` — one domain per line (used by the app)
- `lists/unified-hosts.txt` — hosts file format (0.0.0.0 domain)
- `scripts/update_lists.py` — the processor script
