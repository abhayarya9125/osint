import requests
from bs4 import BeautifulSoup
from .base_adapter import BaseAdapter, DataPoint

# ── API KEYS ──────────────────────────────────────────────────────────────────
HUNTER_KEY   = "e589bf9fd1ab608dd27052ced0a3eb0c0dea40e9"
DEHASHED_KEY = "8Ce7lpfFuwxDj/DT3ytaGQY75KbkCrtQ+G+gjLTS6UctKKkw8e0PdAA="
# ─────────────────────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
}


class RegulatoryAdapter(BaseAdapter):

    def fetch(self, entity: str) -> list:
        results = []
        results += self._opencorporates(entity)
        results += self._news_search(entity)
        results += self._wikipedia(entity)
        results += self._dehashed(entity)
        results += self._hunter_company(entity)
        return results

    def _fail(self, source, category, reason, url="N/A"):
        return [DataPoint(
            source=source, category=category,
            data={"status": f"FAIL TO FIND — {reason}"},
            url=url, confidence=0.0,
        )]

    # ── 1. OpenCorporates ─────────────────────────────────────────────────
    def _opencorporates(self, entity: str) -> list:
        try:
            url = f"https://api.opencorporates.com/v0.4/companies/search?q={entity}&per_page=5"
            r = requests.get(url, headers=HEADERS, timeout=12)
            if r.status_code == 200:
                raw = r.json().get("results", {}).get("companies", [])
                if raw:
                    companies = []
                    for c in raw[:5]:
                        comp = c.get("company", {})
                        companies.append({
                            "name":               comp.get("name", "N/A"),
                            "jurisdiction":       comp.get("jurisdiction_code", "N/A"),
                            "company_number":     comp.get("company_number", "N/A"),
                            "status":             comp.get("current_status", "N/A"),
                            "incorporation_date": comp.get("incorporation_date", "N/A"),
                            "company_type":       comp.get("company_type", "N/A"),
                            "registered_address": str(comp.get("registered_address", "N/A"))[:100],
                            "opencorp_url":       comp.get("opencorporates_url", "N/A"),
                        })
                    return [DataPoint(
                        source="OpenCorporates (Company Registry)",
                        category="regulatory",
                        data={"total_matches": len(raw), "companies": companies},
                        url=url,
                        confidence=0.9,
                    )]
            return self._fail("OpenCorporates (Company Registry)", "regulatory",
                              "No company records found", url)
        except Exception as e:
            return self._fail("OpenCorporates (Company Registry)", "regulatory",
                              str(e)[:80])

    # ── 2. News — Google News RSS (free) ──────────────────────────────────
    def _news_search(self, entity: str) -> list:
        try:
            rss = f"https://news.google.com/rss/search?q={entity}&hl=en&gl=US&ceid=US:en"
            r = requests.get(rss, headers=HEADERS, timeout=12)
            if r.status_code == 200 and "<item>" in r.text:
                soup = BeautifulSoup(r.text, "xml")
                items = soup.find_all("item")
                articles = []
                for item in items[:8]:
                    title   = item.find("title")
                    link    = item.find("link")
                    pubdate = item.find("pubDate")
                    source  = item.find("source")
                    articles.append({
                        "title":     title.get_text()  if title   else "N/A",
                        "url":       link.get_text()   if link    else "N/A",
                        "published": (pubdate.get_text()[:16] if pubdate else "N/A"),
                        "source":    source.get_text() if source  else "N/A",
                    })
                if articles:
                    return [DataPoint(
                        source="News Articles (Google News)",
                        category="contextual",
                        data={"total_found": len(articles), "articles": articles},
                        url=rss,
                        confidence=0.85,
                    )]
            return self._fail("News Articles", "contextual",
                              "No news articles found", rss)
        except Exception as e:
            return self._fail("News Articles", "contextual", str(e)[:80])

    # ── 3. Wikipedia ──────────────────────────────────────────────────────
    def _wikipedia(self, entity: str) -> list:
        try:
            url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{entity.replace(' ', '_')}"
            r = requests.get(url, headers=HEADERS, timeout=12)
            if r.status_code == 200:
                d = r.json()
                if d.get("type") != "https://mediawiki.org/wiki/HyperSwitch/errors/not_found":
                    page_url = d.get("content_urls", {}).get("desktop", {}).get("page", "N/A")
                    return [DataPoint(
                        source="Wikipedia",
                        category="contextual",
                        data={
                            "title":       d.get("title", "N/A"),
                            "description": d.get("description", "N/A"),
                            "summary":     d.get("extract", "N/A")[:500],
                            "page_url":    page_url,
                        },
                        url=page_url,
                        confidence=0.85,
                    )]
            return self._fail("Wikipedia", "contextual",
                              "No Wikipedia page found",
                              f"https://en.wikipedia.org/wiki/{entity.replace(' ', '_')}")
        except Exception as e:
            return self._fail("Wikipedia", "contextual", str(e)[:80])

    # ── 4. DeHashed (Breach Search) ───────────────────────────────────────
    def _dehashed(self, entity: str) -> list:
        # DeHashed needs email address - best used with email input
        # For domain/name we do a domain search
        try:
            import base64
            # DeHashed uses basic auth: email:apikey
            # The key provided appears to be base64 encoded
            auth_header = f"Basic {DEHASHED_KEY}"
            headers = {
                **HEADERS,
                "Authorization": auth_header,
                "Accept": "application/json",
            }
            # Search by domain or email
            query = entity if "@" in entity else f"domain:{entity}"
            url = f"https://api.dehashed.com/search?query={query}&size=5"
            r = requests.get(url, headers=headers, timeout=15)
            if r.status_code == 200:
                d = r.json()
                entries = d.get("entries", []) or []
                total   = d.get("total", 0)
                if entries:
                    cleaned = []
                    for e in entries[:8]:
                        cleaned.append({
                            "email":    e.get("email", "N/A"),
                            "username": e.get("username", "N/A"),
                            "database": e.get("database_name", "N/A"),
                            "hashed_pw": "YES" if e.get("hashed_password") else "N/A",
                            "name":     e.get("name", "N/A"),
                            "ip":       e.get("ip_address", "N/A"),
                        })
                    return [DataPoint(
                        source="DeHashed (Breach Database)",
                        category="regulatory",
                        data={
                            "total_results": total,
                            "entries": cleaned,
                            "warning": "Sensitive data — handle responsibly",
                        },
                        url="https://dehashed.com",
                        confidence=0.92,
                    )]
                return [DataPoint(
                    source="DeHashed (Breach Database)",
                    category="regulatory",
                    data={"status": "No breach entries found for this entity"},
                    url="https://dehashed.com",
                    confidence=0.85,
                )]
            return self._fail("DeHashed (Breach Database)", "regulatory",
                              f"API returned {r.status_code} — check auth key",
                              "https://dehashed.com")
        except Exception as e:
            return self._fail("DeHashed (Breach Database)", "regulatory",
                              str(e)[:80])

    # ── 5. Hunter.io Company Enrichment ───────────────────────────────────
    def _hunter_company(self, entity: str) -> list:
        import re
        # Only run for domain-like entities
        if not re.match(r'^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}', entity.strip()):
            return []
        try:
            url = f"https://api.hunter.io/v2/companies/find?domain={entity}&api_key={HUNTER_KEY}"
            r = requests.get(url, headers=HEADERS, timeout=12)
            if r.status_code == 200:
                d = r.json().get("data", {})
                if d:
                    return [DataPoint(
                        source="Hunter.io (Company Enrichment)",
                        category="regulatory",
                        data={
                            "name":         d.get("name", "N/A"),
                            "domain":       d.get("domain", "N/A"),
                            "industry":     d.get("industry", "N/A"),
                            "size":         d.get("size", "N/A"),
                            "founded":      d.get("founded_year", "N/A"),
                            "country":      d.get("country", "N/A"),
                            "city":         d.get("city", "N/A"),
                            "description":  (d.get("description") or "N/A")[:200],
                            "linkedin":     d.get("linkedin", "N/A"),
                            "twitter":      d.get("twitter", "N/A"),
                            "technologies": d.get("technologies", [])[:8],
                        },
                        url=f"https://hunter.io/companies/{entity}",
                        confidence=0.9,
                    )]
            return self._fail("Hunter.io (Company Enrichment)", "regulatory",
                              "No company data found",
                              f"https://hunter.io/companies/{entity}")
        except Exception as e:
            return self._fail("Hunter.io (Company Enrichment)", "regulatory",
                              str(e)[:80])
