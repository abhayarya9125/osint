class RiskScorer:
    """
    Risk Scoring — 7 Parameters, Max 100 pts

    Parameter              Weight  Source
    ─────────────────────────────────────────────────────────
    Data Breach (HIBP)      25pts  HaveIBeenPwned API
    DeHashed Entries        25pts  DeHashed breach database
    Exposed Emails          15pts  Hunter.io + WHOIS + Dorks
    Open Ports/Vulns        15pts  Shodan API
    Exposed IPs             10pts  DNS + IPInfo
    News Mentions            5pts  Google News RSS
    GitHub Exposure          5pts  GitHub Search API
    ─────────────────────────────────────────────────────────
    Total                  100pts

    Risk Levels:
        0  - 29  => LOW
        30 - 49  => MEDIUM
        50 - 69  => HIGH
        70 - 100 => CRITICAL
    """

    WEIGHTS = {
        "breach_hibp":     25,
        "breach_dehashed": 25,
        "exposed_emails":  15,
        "shodan_vulns":    15,
        "exposed_ips":     10,
        "news_found":       5,
        "github_repos":     5,
    }

    PARAM_DESC = {
        "breach_hibp":     "HaveIBeenPwned API — checks if domain appeared in known data breaches",
        "breach_dehashed": "DeHashed DB — searches leaked credential databases for entity mentions",
        "exposed_emails":  "Hunter.io + WHOIS + Google Dorks — emails visible in public sources",
        "shodan_vulns":    "Shodan API — open ports, running services, known CVE vulnerabilities",
        "exposed_ips":     "DNS A-records + IPInfo + Reverse DNS — IP addresses linked to entity",
        "news_found":      "Google News RSS — news articles and media coverage",
        "github_repos":    "GitHub Search API — public repositories linked to entity",
    }

    def score(self, resolved: dict) -> dict:
        score = 0
        reasons = []
        parameters_used = []
        score_breakdown = []

        # ── 1. HIBP ────────────────────────────────────────────────────────
        hibp_pts = 0
        for dp in resolved.get("technical", []):
            if "HIBP" in dp.source:
                n = dp.data.get("breaches_found", 0)
                if isinstance(n, int) and n > 0:
                    hibp_pts = self.WEIGHTS["breach_hibp"]
                    score += hibp_pts
                    reasons.append(
                        f"[CRITICAL] HIBP: {n} breach(es) found => +{hibp_pts} pts"
                    )
                    score_breakdown.append(f"HIBP Breach         : +{hibp_pts} pts")
        parameters_used.append(
            f"[{'HIT' if hibp_pts else 'MISS'}] HIBP ({self.WEIGHTS['breach_hibp']} pts) "
            f"— {self.PARAM_DESC['breach_hibp']}"
        )

        # ── 2. DeHashed ────────────────────────────────────────────────────
        dh_pts = 0
        for dp in resolved.get("regulatory", []):
            if "DeHashed" in dp.source:
                total = dp.data.get("total_results", 0)
                if isinstance(total, int) and total > 0:
                    dh_pts = self.WEIGHTS["breach_dehashed"]
                    score += dh_pts
                    reasons.append(
                        f"[CRITICAL] DeHashed: {total} leaked credential entries found"
                        f" => +{dh_pts} pts"
                    )
                    score_breakdown.append(f"DeHashed Entries    : +{dh_pts} pts")
        parameters_used.append(
            f"[{'HIT' if dh_pts else 'MISS'}] DeHashed ({self.WEIGHTS['breach_dehashed']} pts) "
            f"— {self.PARAM_DESC['breach_dehashed']}"
        )

        # ── 3. Exposed Emails ──────────────────────────────────────────────
        emails = resolved.get("linked_emails", [])
        email_pts = 0
        if emails:
            email_pts = self.WEIGHTS["exposed_emails"]
            score += email_pts
            reasons.append(
                f"[HIGH] {len(emails)} email(s) exposed publicly => +{email_pts} pts"
            )
            score_breakdown.append(f"Exposed Emails      : +{email_pts} pts")
        parameters_used.append(
            f"[{'HIT' if email_pts else 'MISS'}] Exposed Emails ({self.WEIGHTS['exposed_emails']} pts) "
            f"— {self.PARAM_DESC['exposed_emails']}"
        )

        # ── 4. Shodan Vulnerabilities ──────────────────────────────────────
        shodan_pts = 0
        for dp in resolved.get("technical", []):
            if "Shodan" in dp.source and shodan_pts == 0:
                ports = dp.data.get("open_ports", [])
                vulns = dp.data.get("total_vulns", 0)
                if ports or (isinstance(vulns, int) and vulns > 0):
                    shodan_pts = self.WEIGHTS["shodan_vulns"]
                    score += shodan_pts
                    msg = f"[HIGH] Shodan: {len(ports)} open port(s)"
                    if isinstance(vulns, int) and vulns > 0:
                        msg += f", {vulns} CVE vulnerability(s)"
                    reasons.append(f"{msg} => +{shodan_pts} pts")
                    score_breakdown.append(f"Shodan Open Ports   : +{shodan_pts} pts")
        parameters_used.append(
            f"[{'HIT' if shodan_pts else 'MISS'}] Shodan ({self.WEIGHTS['shodan_vulns']} pts) "
            f"— {self.PARAM_DESC['shodan_vulns']}"
        )

        # ── 5. Exposed IPs ─────────────────────────────────────────────────
        ips = resolved.get("linked_ips", [])
        ip_pts = 0
        if ips:
            ip_pts = self.WEIGHTS["exposed_ips"]
            score += ip_pts
            reasons.append(
                f"[MEDIUM] {len(ips)} IP address(es) found in public records"
                f" => +{ip_pts} pts"
            )
            score_breakdown.append(f"Exposed IPs         : +{ip_pts} pts")
        parameters_used.append(
            f"[{'HIT' if ip_pts else 'MISS'}] Exposed IPs ({self.WEIGHTS['exposed_ips']} pts) "
            f"— {self.PARAM_DESC['exposed_ips']}"
        )

        # ── 6. News Mentions ───────────────────────────────────────────────
        news_pts = 0
        for dp in resolved.get("contextual", []):
            if "News" in dp.source and news_pts == 0:
                total = dp.data.get("total_found", 0)
                if isinstance(total, int) and total > 0:
                    news_pts = self.WEIGHTS["news_found"]
                    score += news_pts
                    reasons.append(
                        f"[LOW] {total} news article(s) found => +{news_pts} pts"
                    )
                    score_breakdown.append(f"News Mentions       : +{news_pts} pts")
        parameters_used.append(
            f"[{'HIT' if news_pts else 'MISS'}] News ({self.WEIGHTS['news_found']} pts) "
            f"— {self.PARAM_DESC['news_found']}"
        )

        # ── 7. GitHub ──────────────────────────────────────────────────────
        github_pts = 0
        for dp in resolved.get("technical", []):
            if "GitHub" in dp.source and github_pts == 0:
                repos = dp.data.get("top_repos", [])
                if repos:
                    github_pts = self.WEIGHTS["github_repos"]
                    score += github_pts
                    reasons.append(
                        f"[LOW] {len(repos)} GitHub repo(s) found => +{github_pts} pts"
                    )
                    score_breakdown.append(f"GitHub Repos        : +{github_pts} pts")
        parameters_used.append(
            f"[{'HIT' if github_pts else 'MISS'}] GitHub ({self.WEIGHTS['github_repos']} pts) "
            f"— {self.PARAM_DESC['github_repos']}"
        )

        score = min(score, 100)

        if score >= 70:
            level, color = "CRITICAL", "#FF4444"
        elif score >= 50:
            level, color = "HIGH",     "#FF8C00"
        elif score >= 30:
            level, color = "MEDIUM",   "#FFD700"
        else:
            level, color = "LOW",      "#00C851"

        if not reasons:
            reasons.append("[INFO] No risk parameters triggered — entity has low digital footprint")

        return {
            "score":           score,
            "level":           level,
            "color":           color,
            "reasons":         reasons,
            "parameters_used": parameters_used,
            "score_breakdown": score_breakdown,
        }
