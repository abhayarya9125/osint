import socket
import requests
from .base_adapter import BaseAdapter, DataPoint

# ── API KEYS ──────────────────────────────────────────────────────────────────
SHODAN_KEY    = "nO9ylPk4oDekeiO7Pjh9sBjvopVzY1yd"
VIRUSTOTAL_KEY= "07aced537babd1a528e2572615096858b03afaf961101db31add96fe971cb904"
IPINFO_KEY    = "859fa3037f46c0"
HIBP_KEY      = "YOUR_HIBP_KEY"   # Add if you have one
# ─────────────────────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
}


class TechnicalAdapter(BaseAdapter):

    def fetch(self, entity: str) -> list:
        results = []
        is_domain = self._is_domain(entity)
        is_ip     = self._is_ip(entity)

        if is_domain:
            results += self._whois(entity)
            results += self._dns_lookup(entity)
            results += self._ssl_certs(entity)
            results += self._virustotal_domain(entity)
            results += self._hunter_domain(entity)

            # Get IP then do IP lookups
            ip = self._resolve_ip(entity)
            if ip:
                results += self._ipinfo(ip)
                results += self._shodan_host(ip)

        elif is_ip:
            results += self._ipinfo(entity)
            results += self._shodan_host(entity)
            results += self._reverse_dns_ip(entity)

        else:
            # Person name — search GitHub + Hunter person
            results += self._hunter_person_search(entity)

        results += self._github_search(entity)
        results += self._hibp_check(entity)
        return results

    # ── Helpers ────────────────────────────────────────────────────────────
    def _is_domain(self, s):
        import re
        return bool(re.match(r'^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(\.[a-zA-Z]{2,})?$', s.strip()))

    def _is_ip(self, s):
        import re
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s.strip()))

    def _resolve_ip(self, domain):
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    def _fail(self, source, category, reason, url="N/A"):
        return [DataPoint(
            source=source, category=category,
            data={"status": f"FAIL TO FIND — {reason}"},
            url=url, confidence=0.0,
        )]

    # ── 1. WHOIS ───────────────────────────────────────────────────────────
    def _whois(self, domain: str) -> list:
        # Try python-whois first
        try:
            import whois
            w = whois.whois(domain)
            data = {
                "registrar":       str(w.registrar or "N/A"),
                "creation_date":   str(w.creation_date or "N/A"),
                "expiration_date": str(w.expiration_date or "N/A"),
                "updated_date":    str(w.updated_date or "N/A"),
                "org":             str(w.org or "N/A"),
                "country":         str(w.country or "N/A"),
                "emails":          str(w.emails or "N/A"),
                "name_servers":    str(w.name_servers or "N/A"),
                "status":          str(w.status or "N/A"),
            }
            real = any(v not in ("N/A", "None", "[]", "") for v in data.values())
            if real:
                return [DataPoint(
                    source="WHOIS",
                    category="technical",
                    data=data,
                    url=f"https://who.is/whois/{domain}",
                    confidence=0.95,
                )]
        except Exception:
            pass

        # Fallback: HackerTarget WHOIS
        try:
            r = requests.get(
                f"https://api.hackertarget.com/whois/?q={domain}",
                headers=HEADERS, timeout=15
            )
            if r.status_code == 200 and len(r.text) > 50 and "error" not in r.text[:20].lower():
                parsed = {}
                for line in r.text.splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        k, v = k.strip().lower(), v.strip()
                        if v and k in ["registrar","creation date","expiry date",
                                       "registrant organization","registrant country",
                                       "name server","registrant email"]:
                            parsed[k] = v
                if parsed:
                    return [DataPoint(
                        source="WHOIS",
                        category="technical",
                        data=parsed,
                        url=f"https://who.is/whois/{domain}",
                        confidence=0.9,
                    )]
        except Exception:
            pass

        return self._fail("WHOIS", "technical", "WHOIS data not available for this domain",
                          f"https://who.is/whois/{domain}")

    # ── 2. DNS Records ─────────────────────────────────────────────────────
    def _dns_lookup(self, domain: str) -> list:
        try:
            import dns.resolver
            records = {}
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
                try:
                    ans = dns.resolver.resolve(domain, rtype, lifetime=8)
                    records[rtype] = [str(r) for r in ans]
                except Exception:
                    pass
            if records:
                return [DataPoint(
                    source="DNS Records",
                    category="technical",
                    data=records,
                    url=f"https://dnsdumpster.com",
                    confidence=0.95,
                )]
            return self._fail("DNS Records", "technical",
                              "No DNS records found", "N/A")
        except Exception as e:
            return self._fail("DNS Records", "technical", str(e)[:80])

    # ── 3. SSL Certificates (crt.sh) ───────────────────────────────────────
    def _ssl_certs(self, domain: str) -> list:
        try:
            r = requests.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                headers=HEADERS, timeout=15
            )
            if r.status_code == 200:
                certs = r.json()
                subdomains = {}
                for c in certs[:50]:
                    name = c.get("name_value", "").strip()
                    if name and name not in subdomains:
                        subdomains[name] = {
                            "subdomain":  name,
                            "issuer":     c.get("issuer_name", "N/A")[:60],
                            "not_before": c.get("not_before", "N/A")[:10],
                            "not_after":  c.get("not_after", "N/A")[:10],
                        }
                if subdomains:
                    return [DataPoint(
                        source="SSL Certificates (crt.sh)",
                        category="technical",
                        data={
                            "total_certs": len(certs),
                            "unique_subdomains": len(subdomains),
                            "subdomains": list(subdomains.values())[:15],
                        },
                        url=f"https://crt.sh/?q=%25.{domain}",
                        confidence=0.9,
                    )]
        except Exception:
            pass
        return self._fail("SSL Certificates (crt.sh)", "technical",
                          "No SSL cert data found",
                          f"https://crt.sh/?q=%25.{domain}")

    # ── 4. VirusTotal Domain ───────────────────────────────────────────────
    def _virustotal_domain(self, domain: str) -> list:
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            r = requests.get(url, headers={"x-apikey": VIRUSTOTAL_KEY}, timeout=15)
            if r.status_code == 200:
                d = r.json().get("data", {}).get("attributes", {})
                stats = d.get("last_analysis_stats", {})
                cats  = d.get("categories", {})
                reps  = d.get("reputation", 0)
                return [DataPoint(
                    source="VirusTotal",
                    category="technical",
                    data={
                        "reputation_score": reps,
                        "malicious_votes":  stats.get("malicious", 0),
                        "suspicious_votes": stats.get("suspicious", 0),
                        "harmless_votes":   stats.get("harmless", 0),
                        "categories":       list(cats.values())[:5],
                        "creation_date":    str(d.get("creation_date", "N/A")),
                        "last_seen":        str(d.get("last_modification_date", "N/A")),
                        "registrar":        d.get("registrar", "N/A"),
                        "tags":             d.get("tags", []),
                    },
                    url=f"https://www.virustotal.com/gui/domain/{domain}",
                    confidence=0.95,
                )]
            return self._fail("VirusTotal", "technical",
                              f"API returned {r.status_code}",
                              f"https://www.virustotal.com/gui/domain/{domain}")
        except Exception as e:
            return self._fail("VirusTotal", "technical", str(e)[:80])

    # ── 5. Hunter.io Domain Search ─────────────────────────────────────────
    def _hunter_domain(self, domain: str) -> list:
        try:
            from config_keys import HUNTER_KEY
        except Exception:
            from adapters.technical_adapter import _HUNTER_KEY as HUNTER_KEY_LOC
            HUNTER_KEY_LOC = "e589bf9fd1ab608dd27052ced0a3eb0c0dea40e9"

        HUNTER_KEY = "e589bf9fd1ab608dd27052ced0a3eb0c0dea40e9"
        try:
            # Domain Search
            r = requests.get(
                f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={HUNTER_KEY}",
                headers=HEADERS, timeout=15
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                emails = d.get("emails", [])
                return [DataPoint(
                    source="Hunter.io (Email Discovery)",
                    category="technical",
                    data={
                        "domain":           d.get("domain", domain),
                        "organization":     d.get("organization", "N/A"),
                        "description":      (d.get("description") or "N/A")[:150],
                        "industry":         d.get("industry", "N/A"),
                        "employee_count":   d.get("company", {}).get("size", "N/A") if d.get("company") else "N/A",
                        "emails_found":     len(emails),
                        "email_pattern":    d.get("pattern", "N/A"),
                        "emails": [
                            {
                                "email":      e.get("value", "N/A"),
                                "first_name": e.get("first_name", "N/A"),
                                "last_name":  e.get("last_name", "N/A"),
                                "position":   e.get("position", "N/A"),
                                "confidence": e.get("confidence", 0),
                                "linkedin":   e.get("linkedin", "N/A"),
                            }
                            for e in emails[:10]
                        ],
                    },
                    url=f"https://hunter.io/domain-search/{domain}",
                    confidence=0.92,
                )]
            return self._fail("Hunter.io (Email Discovery)", "technical",
                              f"API returned {r.status_code}",
                              f"https://hunter.io/domain-search/{domain}")
        except Exception as e:
            return self._fail("Hunter.io (Email Discovery)", "technical", str(e)[:80])

    # ── 6. Hunter.io Person Search ─────────────────────────────────────────
    def _hunter_person_search(self, name: str) -> list:
        HUNTER_KEY = "e589bf9fd1ab608dd27052ced0a3eb0c0dea40e9"
        try:
            parts = name.strip().split()
            if len(parts) < 2:
                return self._fail("Hunter.io (Person Search)", "technical",
                                  "Need full name (first + last) for person search")
            first, last = parts[0], parts[-1]
            r = requests.get(
                f"https://api.hunter.io/v2/email-finder?"
                f"first_name={first}&last_name={last}&api_key={HUNTER_KEY}",
                headers=HEADERS, timeout=15
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                return [DataPoint(
                    source="Hunter.io (Person Search)",
                    category="technical",
                    data={
                        "email_found":  d.get("email", "N/A"),
                        "score":        d.get("score", "N/A"),
                        "first_name":   d.get("first_name", "N/A"),
                        "last_name":    d.get("last_name", "N/A"),
                        "position":     d.get("position", "N/A"),
                        "company":      d.get("company", "N/A"),
                        "twitter":      d.get("twitter", "N/A"),
                        "linkedin":     d.get("linkedin_url", "N/A"),
                    },
                    url=f"https://hunter.io",
                    confidence=0.85,
                )]
            return self._fail("Hunter.io (Person Search)", "technical",
                              f"No email found for {name}")
        except Exception as e:
            return self._fail("Hunter.io (Person Search)", "technical", str(e)[:80])

    # ── 7. IPInfo ──────────────────────────────────────────────────────────
    def _ipinfo(self, ip: str) -> list:
        try:
            r = requests.get(
                f"https://ipinfo.io/{ip}?token={IPINFO_KEY}",
                headers=HEADERS, timeout=12
            )
            if r.status_code == 200:
                d = r.json()
                return [DataPoint(
                    source="IPInfo (Geolocation)",
                    category="technical",
                    data={
                        "ip":       d.get("ip", ip),
                        "hostname": d.get("hostname", "N/A"),
                        "city":     d.get("city", "N/A"),
                        "region":   d.get("region", "N/A"),
                        "country":  d.get("country", "N/A"),
                        "org":      d.get("org", "N/A"),
                        "timezone": d.get("timezone", "N/A"),
                        "loc":      d.get("loc", "N/A"),
                    },
                    url=f"https://ipinfo.io/{ip}",
                    confidence=0.95,
                )]
            return self._fail("IPInfo (Geolocation)", "technical",
                              f"API returned {r.status_code}",
                              f"https://ipinfo.io/{ip}")
        except Exception as e:
            return self._fail("IPInfo (Geolocation)", "technical", str(e)[:80])

    # ── 8. Shodan Host ─────────────────────────────────────────────────────
    def _shodan_host(self, ip: str) -> list:
        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}",
                headers=HEADERS, timeout=15
            )
            if r.status_code == 200:
                d = r.json()
                ports = d.get("ports", [])
                vulns = d.get("vulns", [])
                hostnames = d.get("hostnames", [])
                data_items = d.get("data", [])
                services = []
                for item in data_items[:10]:
                    services.append({
                        "port":      item.get("port", "N/A"),
                        "transport": item.get("transport", "N/A"),
                        "product":   item.get("product", "N/A"),
                        "version":   item.get("version", "N/A"),
                        "banner":    (item.get("data") or "")[:100],
                    })
                return [DataPoint(
                    source="Shodan (Internet Exposure)",
                    category="technical",
                    data={
                        "ip":              ip,
                        "hostnames":       hostnames,
                        "open_ports":      ports,
                        "os":              d.get("os", "N/A"),
                        "country":         d.get("country_name", "N/A"),
                        "city":            d.get("city", "N/A"),
                        "isp":             d.get("isp", "N/A"),
                        "org":             d.get("org", "N/A"),
                        "asn":             d.get("asn", "N/A"),
                        "total_vulns":     len(vulns),
                        "vulnerabilities": list(vulns)[:10],
                        "services":        services,
                        "last_update":     d.get("last_update", "N/A"),
                    },
                    url=f"https://www.shodan.io/host/{ip}",
                    confidence=0.95,
                )]
            elif r.status_code == 404:
                return self._fail("Shodan (Internet Exposure)", "technical",
                                  "No Shodan data found for this IP",
                                  f"https://www.shodan.io/host/{ip}")
            return self._fail("Shodan (Internet Exposure)", "technical",
                              f"API returned {r.status_code}",
                              f"https://www.shodan.io/host/{ip}")
        except Exception as e:
            return self._fail("Shodan (Internet Exposure)", "technical", str(e)[:80])

    # ── 9. Reverse DNS ─────────────────────────────────────────────────────
    def _reverse_dns_ip(self, ip: str) -> list:
        try:
            hostname, aliases, _ = socket.gethostbyaddr(ip)
            return [DataPoint(
                source="Reverse DNS",
                category="technical",
                data={"ip": ip, "hostname": hostname, "aliases": aliases},
                url=f"https://mxtoolbox.com/ReverseLookup.aspx?domain={ip}",
                confidence=0.85,
            )]
        except Exception as e:
            return self._fail("Reverse DNS", "technical", str(e)[:80])

    # ── 10. HIBP ───────────────────────────────────────────────────────────
    def _hibp_check(self, entity: str) -> list:
        if HIBP_KEY == "YOUR_HIBP_KEY":
            return [DataPoint(
                source="HIBP (HaveIBeenPwned)",
                category="technical",
                data={
                    "status": "FAIL TO FIND — HIBP requires paid API key ($3.5/month)",
                    "get_key": "https://haveibeenpwned.com/API/Key",
                },
                url="https://haveibeenpwned.com",
                confidence=0.0,
            )]
        try:
            url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{entity}"
            r = requests.get(url,
                headers={**HEADERS, "hibp-api-key": HIBP_KEY},
                timeout=12
            )
            if r.status_code == 200:
                breaches = r.json()
                return [DataPoint(
                    source="HIBP (HaveIBeenPwned)",
                    category="technical",
                    data={"breaches_found": len(breaches), "details": breaches},
                    url=url,
                    confidence=0.99,
                )]
            return [DataPoint(
                source="HIBP (HaveIBeenPwned)",
                category="technical",
                data={"status": "No breaches found for this domain"},
                url=url,
                confidence=0.99,
            )]
        except Exception as e:
            return self._fail("HIBP (HaveIBeenPwned)", "technical", str(e)[:80])

    # ── 11. GitHub Search ──────────────────────────────────────────────────
    def _github_search(self, entity: str) -> list:
        try:
            r = requests.get(
                f"https://api.github.com/search/repositories?q={entity}&per_page=5&sort=stars",
                headers=HEADERS, timeout=12
            )
            if r.status_code == 200:
                items = r.json().get("items", [])
                total = r.json().get("total_count", 0)
                if items:
                    return [DataPoint(
                        source="GitHub Repositories",
                        category="technical",
                        data={
                            "total_repos_found": total,
                            "top_repos": [
                                {
                                    "name":        i["full_name"],
                                    "url":         i["html_url"],
                                    "stars":       i["stargazers_count"],
                                    "language":    i.get("language", "N/A"),
                                    "description": (i.get("description") or "N/A")[:80],
                                    "updated":     i.get("updated_at", "N/A")[:10],
                                }
                                for i in items
                            ],
                        },
                        url=f"https://github.com/search?q={entity}",
                        confidence=0.85,
                    )]
                return self._fail("GitHub Repositories", "technical",
                                  "No repos found",
                                  f"https://github.com/search?q={entity}")
            return self._fail("GitHub Repositories", "technical",
                              f"API returned {r.status_code}")
        except Exception as e:
            return self._fail("GitHub Repositories", "technical", str(e)[:80])
