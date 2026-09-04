# Integration Sources

## AbuseIPDB API v2

Official documentation: <https://docs.abuseipdb.com/#introduction>

The implemented analyst-approved reputation lookup uses the documented `GET https://api.abuseipdb.com/api/v2/check` endpoint with the `ipAddress` query parameter, optional `maxAgeInDays`, the `Key` request header, and `Accept: application/json`. The returned `data` object is treated as provider evidence and stored privately with the case.

## IPWHOIS Approximate Geolocation

Official documentation: <https://ipwhois.io/documentation>

The implemented analyst-approved geolocation lookup uses the documented IP lookup service for an extracted public IP only. Approximate country, region, city, latitude, and longitude are saved privately with a provider label. Private, loopback, link-local, and invalid IPv4 addresses are rejected before any external lookup.

## VirusTotal IP Reputation

Official endpoint documentation: <https://docs.virustotal.com/reference/ip-info>

Official IP object fields: <https://docs.virustotal.com/reference/ip-object>

The planned analyst-approved lookup uses the documented `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}` endpoint with the required `x-apikey` request header. The private case evidence will retain a concise provider snapshot of `last_analysis_stats`, community reputation, country, ASN/AS owner, network, and the report timestamp; it will not send email content, attachments, or account data.

## PhishTank Credentials-Free Data Feed Assessment

Official API information: <https://www.phishtank.net/api_info.php>

Official developer information: <https://www.phishtank.net/developer_info.php>

PhishTank's official documentation states that its simple URL-check API accepts an optional application key, although anonymous usage has a substantially lower rate limit and requires a descriptive user-agent. Its developer documentation also lists an hourly updated, verified-online database feed and permits a small number of downloads per day without a key; registered applications receive higher limits. The published feed URLs use HTTP, so the implementation will proceed only if the same feed is reachable via HTTPS and will cache a bounded result rather than repeatedly download the whole feed for individual cases.
