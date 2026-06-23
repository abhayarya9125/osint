import time
import requests
from bs4 import BeautifulSoup
from .base_adapter import BaseAdapter, DataPoint

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Accept-Language": "en-US,en;q=0.9",
}


class SocialAdapter(BaseAdapter):

    def fetch(self, entity: str) -> list:
        results = []
        results += self._google_dork(entity)
        results += self._linkedin_search(entity)
        results += self._twitter_search(entity)
        results += self._pastebin_search(entity)
        return results

    def _fail(self, source, reason, url="N/A"):
        return [DataPoint(
            source=source, category="social",
            data={"status": f"FAIL TO FIND — {reason}"},
            url=url, confidence=0.0,
        )]

    # ── 1. Google Dorking ─────────────────────────────────────────────────
    def _google_dork(self, entity: str) -> list:
        try:
            from googlesearch import search
            dorks = [
                f'site:linkedin.com "{entity}"',
                f'"{entity}" filetype:pdf',
                f'"{entity}" email OR contact OR phone',
                f'"{entity}" site:twitter.com OR site:x.com',
                f'"{entity}" leak OR breach OR hacked OR exposed',
                f'"{entity}" pastebin OR ghostbin OR hastebin',
            ]
            all_results = []
            found_any = False
            for dork in dorks:
                try:
                    urls = list(search(dork, num_results=3, sleep_interval=2))
                    if urls:
                        found_any = True
                    all_results.append({
                        "query":          dork,
                        "results_count":  len(urls),
                        "urls":           urls,
                    })
                    time.sleep(2)
                except Exception as e:
                    all_results.append({
                        "query": dork,
                        "results_count": 0,
                        "error": str(e)[:60],
                    })

            if found_any:
                return [DataPoint(
                    source="Google Dorking",
                    category="social",
                    data={
                        "dorks_run": len(dorks),
                        "total_results": sum(d.get("results_count", 0) for d in all_results),
                        "results": all_results,
                    },
                    url=f"https://www.google.com/search?q=%22{entity}%22",
                    confidence=0.8,
                )]
            return self._fail("Google Dorking",
                              "No results from Google dorking",
                              f"https://www.google.com/search?q={entity}")
        except Exception as e:
            return self._fail("Google Dorking", str(e)[:80])

    # ── 2. LinkedIn ───────────────────────────────────────────────────────
    def _linkedin_search(self, entity: str) -> list:
        try:
            url = f"https://www.google.com/search?q=site:linkedin.com+%22{entity}%22"
            r = requests.get(url, headers=HEADERS, timeout=12)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                links = []
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if "linkedin.com" in href:
                        if href.startswith("/url?q="):
                            href = href.split("/url?q=")[1].split("&")[0]
                        if href.startswith("http") and href not in links:
                            if "/in/" in href or "/company/" in href:
                                links.append(href)
                if links:
                    return [DataPoint(
                        source="LinkedIn Profiles",
                        category="social",
                        data={"profiles_found": len(links), "urls": links[:8]},
                        url=url,
                        confidence=0.8,
                    )]
            return self._fail("LinkedIn Profiles",
                              "No LinkedIn profiles found", url)
        except Exception as e:
            return self._fail("LinkedIn Profiles", str(e)[:80])

    # ── 3. Twitter / Nitter ───────────────────────────────────────────────
    def _twitter_search(self, entity: str) -> list:
        instances = [
            "https://nitter.privacydev.net",
            "https://nitter.poast.org",
            "https://nitter.net",
        ]
        for instance in instances:
            try:
                url = f"{instance}/search?q={entity}&f=tweets"
                r = requests.get(url, headers=HEADERS, timeout=10)
                if r.status_code == 200 and "tweet" in r.text.lower():
                    soup = BeautifulSoup(r.text, "html.parser")
                    tweets = []
                    for t in soup.find_all("div", class_="tweet-content")[:6]:
                        txt = t.get_text(strip=True)
                        if txt:
                            tweets.append(txt[:120])
                    if tweets:
                        return [DataPoint(
                            source="Twitter/X Mentions",
                            category="social",
                            data={
                                "tweets_found": len(tweets),
                                "tweets": tweets,
                                "via_instance": instance,
                            },
                            url=url,
                            confidence=0.75,
                        )]
            except Exception:
                continue
        return self._fail("Twitter/X Mentions",
                          "Twitter/Nitter not accessible — try manually",
                          f"https://twitter.com/search?q={entity}")

    # ── 4. Pastebin ───────────────────────────────────────────────────────
    def _pastebin_search(self, entity: str) -> list:
        try:
            url = f"https://www.google.com/search?q=site:pastebin.com+%22{entity}%22"
            r = requests.get(url, headers=HEADERS, timeout=12)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                links = []
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if "pastebin.com" in href:
                        if href.startswith("/url?q="):
                            href = href.split("/url?q=")[1].split("&")[0]
                        if href.startswith("http") and href not in links:
                            links.append(href)
                if links:
                    return [DataPoint(
                        source="Pastebin / Paste Sites",
                        category="social",
                        data={
                            "pastes_found": len(links),
                            "urls": links[:6],
                            "note": "Review manually — may contain leaked credentials",
                        },
                        url=url,
                        confidence=0.7,
                    )]
            return self._fail("Pastebin / Paste Sites",
                              "No pastes found", url)
        except Exception as e:
            return self._fail("Pastebin / Paste Sites", str(e)[:80])
