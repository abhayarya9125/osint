import random
import requests
from urllib.robotparser import RobotFileParser


FREE_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
]


def get_session() -> requests.Session:
    """Return a requests session with rotated User-Agent."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": random.choice(FREE_USER_AGENTS),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    })
    return session


def can_fetch(base_url: str, path: str = "/", user_agent: str = "*") -> bool:
    """Check robots.txt before scraping a URL."""
    try:
        rp = RobotFileParser()
        robots_url = base_url.rstrip("/") + "/robots.txt"
        rp.set_url(robots_url)
        rp.read()
        target = base_url.rstrip("/") + "/" + path.lstrip("/")
        return rp.can_fetch(user_agent, target)
    except Exception:
        # If robots.txt unreachable, allow by default
        return True
