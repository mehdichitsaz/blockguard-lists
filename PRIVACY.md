# BlockGuard Privacy Policy

**Last updated:** April 1, 2026

## Overview

BlockGuard is a system-wide ad blocker for iOS that filters DNS queries locally on your device. Your privacy is our top priority — we do not collect, store, or share any of your data.

## Data Collection

**We do not collect any data.** Specifically:

- No personal information is collected
- No browsing history is collected
- No DNS queries are logged or transmitted
- No analytics or tracking SDKs are included
- No data is shared with third parties
- No account or sign-in is required

## How BlockGuard Works

BlockGuard installs a local VPN profile on your device using Apple's NetworkExtension framework. This VPN configuration is used solely for DNS filtering — it intercepts DNS queries on your device and blocks known ad, tracker, and malware domains by checking them against a locally stored blocklist.

**All processing happens entirely on your device.** No internet traffic is routed through external servers. The VPN profile does not tunnel your traffic to any remote server.

## Blocklist Updates

BlockGuard periodically downloads updated blocklists from our public GitHub repository (github.com/mehdichitsaz/blockguard-lists). These downloads are standard HTTPS requests and do not include any personal or device information beyond what is included in a standard web request (IP address, which is not logged by us).

## Third-Party Services

BlockGuard forwards allowed DNS queries to your chosen upstream DNS provider (e.g., Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9, or OpenDNS). These providers have their own privacy policies. BlockGuard does not control or have access to any data handled by these providers.

## Data Storage

All app data (blocklist, settings, whitelist, blocked count) is stored locally on your device using iOS App Groups. No data is stored on external servers.

## Children's Privacy

BlockGuard does not collect any data from any user, including children under the age of 13.

## Changes to This Policy

We may update this privacy policy from time to time. Any changes will be posted on this page with an updated date.

## Contact

If you have any questions about this privacy policy, please contact us at:

- GitHub Issues: https://github.com/mehdichitsaz/blockguard-lists/issues
- Email: mehdichitsaz15@yahoo.com
