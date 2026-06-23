from datetime import datetime
from fpdf import FPDF


class ReportGenerator:

    @staticmethod
    def _safe_text(text: str) -> str:
        """Safely clean text for PDF rendering."""
        if not text:
            return "[Empty]"
        clean = str(text).encode("ascii", "ignore").decode("ascii").strip()
        return clean if clean else "[Non-ASCII]"

    @staticmethod
    def _safe_multi_cell(pdf: FPDF, width: int, height: int, text: str, **kwargs):
        """Safely render multi_cell with fallback for problematic text."""
        text = ReportGenerator._safe_text(text)
        # Use fixed width 185 instead of 0 to avoid FPDF width calculation issues
        if width == 0:
            width = 185
        try:
            pdf.multi_cell(width, height, text, **kwargs)
        except Exception as e:
            try:
                simplified = text[:100]
                pdf.multi_cell(width, height, simplified, **kwargs)
            except:
                pass  # Silently fail rather than crash

    def generate_pdf(self, entity: str, resolved: dict, risk: dict,
                     output_path: str = None) -> str:
        if not output_path:
            safe = entity.replace(" ", "_").replace("/", "_")
            output_path = f"{safe}_OSINT_Report.pdf"

        pdf = FPDF()
        pdf.set_margins(15, 15, 15)
        pdf.add_page()

        # Title
        pdf.set_font("Arial", "B", 20)
        pdf.set_text_color(20, 20, 80)
        pdf.cell(0, 12, "OSINT Investigation Report", ln=True, align="C")

        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(120, 120, 120)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entity_safe = self._safe_text(entity)
        pdf.cell(0, 7, f"Generated: {ts}  |  Target: {entity_safe}", ln=True, align="C")
        pdf.ln(4)

        # Executive Summary
        self._section_header(pdf, "1. Executive Summary")
        pdf.set_font("Arial", "", 11)
        pdf.set_text_color(30, 30, 30)
        self._safe_multi_cell(pdf, 0, 8,
            f"Target Entity  : {self._safe_text(entity_safe)}\n"
            f"Risk Level     : {self._safe_text(risk['level'])}\n"
            f"Risk Score     : {risk['score']} / 100\n"
            f"Sources Queried: {resolved.get('total_sources', 0)}\n"
            f"Report Date    : {ts}"
        )
        pdf.ln(3)

        # Score Breakdown
        self._section_header(pdf, "2. Risk Score Breakdown")
        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(30, 30, 30)

        # Score basis explanation
        pdf.set_font("Arial", "B", 10)
        pdf.cell(0, 7, "Scoring Parameters (Total = 100 pts):", ln=True)
        pdf.set_font("Arial", "", 9)

        param_table = [
            ("Data Breach (HIBP)",  "40 pts", "Domain found in HaveIBeenPwned breach database"),
            ("Exposed Emails",      "20 pts", "Emails visible in WHOIS / public search"),
            ("Exposed IPs",         "15 pts", "IP addresses in DNS A-records / WHOIS"),
            ("News Mentions",       "15 pts", "News articles found via NewsAPI"),
            ("GitHub Repos",        "10 pts", "Public repos associated with entity"),
        ]
        for param, weight, desc in param_table:
            pdf.set_font("Arial", "B", 9)
            pdf.cell(50, 6, param, ln=False)
            pdf.set_font("Arial", "", 9)
            pdf.cell(18, 6, weight, ln=False)
            pdf.cell(0, 6, desc, ln=True)
        pdf.ln(3)

        # Score breakdown triggered
        breakdown = risk.get("score_breakdown", [])
        if breakdown:
            pdf.set_font("Arial", "B", 10)
            pdf.cell(0, 7, "Score Calculation for this scan:", ln=True)
            pdf.set_font("Arial", "", 9)
            for item in breakdown:
                pdf.cell(0, 6, f"  + {item}", ln=True)
            pdf.set_font("Arial", "B", 10)
            pdf.cell(0, 7, f"  TOTAL SCORE: {risk['score']} / 100  =>  Risk Level: {risk['level']}", ln=True)
        else:
            pdf.set_font("Arial", "", 9)
            pdf.cell(0, 6, "  No risk parameters triggered — Score: 0 / 100", ln=True)
        pdf.ln(3)

        # Key Findings
        self._section_header(pdf, "3. Key Findings")
        pdf.set_font("Arial", "", 10)
        for reason in risk["reasons"]:
            clean = self._safe_text(reason)
            self._safe_multi_cell(pdf, 0, 7, f"  {clean}")
        pdf.ln(3)

        # Parameters Used
        self._section_header(pdf, "4. Parameters Used in This Scan")
        pdf.set_font("Arial", "", 9)
        pdf.set_text_color(50, 50, 50)
        for param in risk.get("parameters_used", []):
            clean = self._safe_text(param)
            self._safe_multi_cell(pdf, 0, 6, f"  {clean}")
        pdf.ln(3)

        # Discovered Assets
        pdf.set_text_color(30, 30, 30)
        self._section_header(pdf, "5. Discovered Assets")
        pdf.set_font("Arial", "", 10)
        for label, key in [("Emails", "linked_emails"),
                            ("Domains", "linked_domains"),
                            ("IP Addresses", "linked_ips")]:
            items = resolved.get(key, [])
            if items:
                val = self._safe_text(", ".join(str(i) for i in items[:10]))
            else:
                val = "None found"
            pdf.set_font("Arial", "B", 10)
            pdf.cell(35, 7, f"{label}:", ln=False)
            pdf.set_font("Arial", "", 10)
            self._safe_multi_cell(pdf, 0, 7, val)
        pdf.ln(3)

        # Intelligence Sections
        section_num = 6
        for category in ["technical", "social", "regulatory", "contextual"]:
            items = resolved.get(category, [])
            if not items:
                continue
            self._section_header(pdf, f"{section_num}. {category.title()} Intelligence")
            section_num += 1

            for dp in items:
                pdf.set_font("Arial", "B", 10)
                pdf.set_text_color(0, 70, 150)
                src = self._safe_text(dp.source)
                pdf.cell(0, 7, f"[{src}]  -  Confidence: {int(dp.confidence * 100)}%", ln=True)

                pdf.set_font("Arial", "", 9)
                pdf.set_text_color(50, 50, 50)
                data_str = self._safe_text(str(dp.data))
                while len(data_str) > 0:
                    chunk = data_str[:200]
                    data_str = data_str[200:]
                    self._safe_multi_cell(pdf, 0, 6, chunk)

                pdf.set_font("Arial", "I", 8)
                pdf.set_text_color(0, 100, 200)
                url = self._safe_text(dp.url)
                pdf.cell(0, 5, f"Source URL : {url}", ln=True)
                pdf.set_text_color(100, 100, 100)
                pdf.cell(0, 5, f"Retrieved  : {dp.timestamp}", ln=True)
                pdf.ln(3)

        # Footer
        pdf.set_text_color(30, 30, 30)
        self._section_header(pdf, "Audit Trail")
        pdf.set_font("Arial", "", 9)
        footer_text = (
            f"All {resolved.get('total_sources', 0)} data points collected on {ts}. "
            "Each entry includes a source URL and retrieval timestamp for verification. "
            "Built by Abhay Arya — OSINT Investigation Tool v1.0"
        )
        self._safe_multi_cell(pdf, 0, 6, self._safe_text(footer_text))

        pdf.output(output_path)
        return output_path

    def generate_markdown(self, entity: str, resolved: dict, risk: dict,
                          output_path: str = None) -> str:
        if not output_path:
            safe = entity.replace(" ", "_").replace("/", "_")
            output_path = f"{safe}_OSINT_Report.md"

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            "# OSINT Investigation Report",
            "",
            f"**Target Entity:** {entity}",
            f"**Generated:** {ts}",
            f"**Risk Level:** {risk['level']}",
            f"**Risk Score:** {risk['score']} / 100",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"Automated OSINT scan for **{entity}** completed across 3 phases and "
            f"{resolved.get('total_sources', 0)} data sources.",
            "",
            "---",
            "",
            "## 2. Risk Score Breakdown",
            "",
            "### Scoring Parameters",
            "",
            "| Parameter | Weight | Basis |",
            "|---|---|---|",
            "| Data Breach (HIBP) | 40 pts | Domain in HaveIBeenPwned database |",
            "| Exposed Emails | 20 pts | Emails in WHOIS / public search |",
            "| Exposed IPs | 15 pts | IPs in DNS / WHOIS records |",
            "| News Mentions | 15 pts | Articles found via NewsAPI |",
            "| GitHub Repos | 10 pts | Public repos linked to entity |",
            "",
            "### Score Calculation",
            "",
        ]
        breakdown = risk.get("score_breakdown", [])
        if breakdown:
            for item in breakdown:
                lines.append(f"- {item}")
            lines.append(f"- **TOTAL: {risk['score']} / 100 => {risk['level']}**")
        else:
            lines.append(f"- No parameters triggered — Score: 0 / 100")

        lines += ["", "---", "", "## 3. Key Findings", ""]
        for reason in risk["reasons"]:
            lines.append(f"- {reason}")

        lines += ["", "---", "", "## 4. Parameters Used", ""]
        for param in risk.get("parameters_used", []):
            lines.append(f"- {param}")

        lines += ["", "---", "", "## 5. Discovered Assets", ""]
        for label, key in [("Emails", "linked_emails"),
                            ("Domains", "linked_domains"),
                            ("IP Addresses", "linked_ips")]:
            items = resolved.get(key, [])
            val = ", ".join(items[:10]) if items else "None found"
            lines.append(f"**{label}:** {val}")

        for category in ["technical", "social", "regulatory", "contextual"]:
            items = resolved.get(category, [])
            if not items:
                continue
            lines += ["", "---", "", f"## {category.title()} Intelligence", ""]
            for dp in items:
                lines += [
                    f"### {dp.source}",
                    "",
                    f"- **Confidence:** {int(dp.confidence * 100)}%",
                    f"- **Data:** `{str(dp.data)[:400]}`",
                    f"- **Source URL:** {dp.url}",
                    f"- **Retrieved:** {dp.timestamp}",
                    "",
                ]

        lines += [
            "---",
            "",
            "## Audit Trail",
            "",
            f"All {resolved.get('total_sources', 0)} data points collected on {ts}.",
            "Each entry includes source URL and retrieval timestamp.",
            "",
            "*Built by Abhay Arya | B.Tech Cybersecurity | Lamrin Tech Skills University*",
            "*OSINT Investigation Tool v1.0*",
        ]

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return output_path

    @staticmethod
    def _section_header(pdf: FPDF, title: str):
        pdf.set_font("Arial", "B", 13)
        pdf.set_text_color(20, 20, 80)
        pdf.cell(0, 9, title, ln=True)
        pdf.set_draw_color(20, 20, 80)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(3)
        pdf.set_text_color(30, 30, 30)
