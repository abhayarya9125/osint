import threading
import customtkinter as ctk
from tkinter import messagebox, filedialog

from adapters.technical_adapter import TechnicalAdapter
from adapters.social_adapter import SocialAdapter
from adapters.regulatory_adapter import RegulatoryAdapter
from analysis.entity_resolver import EntityResolver
from analysis.risk_scorer import RiskScorer
from reporting.pdf_generator import ReportGenerator

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class OSINTApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("OSINT Investigation Tool")
        self.geometry("980x750")
        self.minsize(800, 600)
        self.resizable(True, True)

        self.resolved_data = None
        self.risk_data = None
        self.entity_name = None

        self._build_ui()

    def _build_ui(self):

        # ── Header ──────────────────────────────────────────────────────────
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", padx=30, pady=(18, 4))

        ctk.CTkLabel(
            header_frame,
            text="OSINT Investigation Tool",
            font=ctk.CTkFont(size=26, weight="bold"),
        ).pack()
        ctk.CTkLabel(
            header_frame,
            text="Open-Source Intelligence  |  Automated Entity Discovery & Reporting",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        ).pack(pady=(2, 0))

        # ── Search Bar ───────────────────────────────────────────────────────
        search_frame = ctk.CTkFrame(self)
        search_frame.pack(fill="x", padx=30, pady=10)

        ctk.CTkLabel(
            search_frame,
            text="Target:",
            font=ctk.CTkFont(size=13, weight="bold"),
            width=60,
        ).pack(side="left", padx=(12, 5), pady=10)

        self.entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="Enter company or individual name  (e.g. Infosys, Travis Haasch)",
            font=ctk.CTkFont(size=13),
            height=40,
        )
        self.entry.pack(side="left", fill="x", expand=True, padx=5, pady=10)
        self.entry.bind("<Return>", lambda e: self._start_scan())

        self.scan_btn = ctk.CTkButton(
            search_frame,
            text="Start Investigate",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=40,
            width=150,
            command=self._start_scan,
        )
        self.scan_btn.pack(side="right", padx=(5, 12), pady=10)

        # ── Progress + Step Status ───────────────────────────────────────────
        prog_frame = ctk.CTkFrame(self, fg_color="transparent")
        prog_frame.pack(fill="x", padx=30)

        self.progress = ctk.CTkProgressBar(prog_frame, height=12)
        self.progress.pack(fill="x")
        self.progress.set(0)

        # Percentage label
        pct_row = ctk.CTkFrame(prog_frame, fg_color="transparent")
        pct_row.pack(fill="x", pady=(2, 0))

        self.pct_label = ctk.CTkLabel(
            pct_row,
            text="0%",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="gray",
            width=40,
        )
        self.pct_label.pack(side="left")

        self.step_label = ctk.CTkLabel(
            pct_row,
            text="Ready — Enter a target and click Start Investigate",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        )
        self.step_label.pack(side="left", padx=6)

        # ── Risk / Score / Sources Panel ─────────────────────────────────────
        info_frame = ctk.CTkFrame(self)
        info_frame.pack(fill="x", padx=30, pady=(8, 4))

        # Risk Level
        left_col = ctk.CTkFrame(info_frame, fg_color="transparent")
        left_col.pack(side="left", padx=15, pady=8)

        ctk.CTkLabel(
            left_col,
            text="RISK LEVEL",
            font=ctk.CTkFont(size=9),
            text_color="gray",
        ).pack(anchor="w")
        self.risk_label = ctk.CTkLabel(
            left_col,
            text="—",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="gray",
        )
        self.risk_label.pack(anchor="w")

        ctk.CTkFrame(info_frame, width=2, fg_color="gray30").pack(
            side="left", fill="y", pady=6
        )

        # Score
        mid_col = ctk.CTkFrame(info_frame, fg_color="transparent")
        mid_col.pack(side="left", padx=15, pady=8)

        ctk.CTkLabel(
            mid_col,
            text="SCORE",
            font=ctk.CTkFont(size=9),
            text_color="gray",
        ).pack(anchor="w")
        self.score_label = ctk.CTkLabel(
            mid_col,
            text="— / 100",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="gray",
        )
        self.score_label.pack(anchor="w")

        ctk.CTkLabel(
            mid_col,
            text="Based on: HIBP(40) + Emails(20) + IPs(15) + News(15) + GitHub(10)",
            font=ctk.CTkFont(size=9),
            text_color="gray",
        ).pack(anchor="w")

        ctk.CTkFrame(info_frame, width=2, fg_color="gray30").pack(
            side="left", fill="y", pady=6
        )

        # Sources
        right_col = ctk.CTkFrame(info_frame, fg_color="transparent")
        right_col.pack(side="left", padx=15, pady=8)

        ctk.CTkLabel(
            right_col,
            text="SOURCES QUERIED",
            font=ctk.CTkFont(size=9),
            text_color="gray",
        ).pack(anchor="w")
        self.sources_label = ctk.CTkLabel(
            right_col,
            text="—",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="gray",
        )
        self.sources_label.pack(anchor="w")

        ctk.CTkLabel(
            right_col,
            text="WHOIS + DNS + HIBP + GitHub + Dorks + LinkedIn + OpenCorp + News",
            font=ctk.CTkFont(size=9),
            text_color="gray",
        ).pack(anchor="w")

        # ── Results Box ───────────────────────────────────────────────────────
        self.result_box = ctk.CTkTextbox(
            self,
            font=ctk.CTkFont(family="Courier New", size=11),
            wrap="word",
            activate_scrollbars=True,
        )
        self.result_box.pack(fill="both", expand=True, padx=30, pady=(4, 4))
        self._show_welcome()

        # ── Export Buttons ────────────────────────────────────────────────────
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=(4, 14))

        self.pdf_btn = ctk.CTkButton(
            btn_frame, text="Export PDF",
            width=160, state="disabled",
            command=self._export_pdf,
        )
        self.pdf_btn.pack(side="left", padx=10)

        self.md_btn = ctk.CTkButton(
            btn_frame, text="Export Markdown",
            width=160, state="disabled",
            command=self._export_markdown,
        )
        self.md_btn.pack(side="left", padx=10)

        self.clear_btn = ctk.CTkButton(
            btn_frame, text="Clear",
            width=100,
            fg_color="gray30", hover_color="gray20",
            command=self._clear,
        )
        self.clear_btn.pack(side="left", padx=10)

    # ── Welcome Screen ─────────────────────────────────────────────────────────
    def _show_welcome(self):
        self.result_box.delete("1.0", "end")
        welcome = (
            "\n"
            "  ╔══════════════════════════════════════════════════════════════════╗\n"
            "  ║          OSINT Investigation Tool  v1.0  —  Welcome             ║\n"
            "  ║                                                                  ║\n"
            "  ║  Developed by : Abhay Arya                                       ║\n"
            "  ║  Degree       : B.Tech Cybersecurity (2023-2027)                 ║\n"
            "  ║  University   : Lamrin Tech Skills University, Punjab            ║\n"
            "  ║  Internships  : NCFL IFSO Delhi Police | Cyber Octopus Pvt. Ltd  ║\n"
            "  ╠══════════════════════════════════════════════════════════════════╣\n"
            "  ║                                                                  ║\n"
            "  ║  PHASE I  — Data Acquisition (Multi-Vector Search)               ║\n"
            "  ║    [+] Social & Public Footprint  : Google Dorking, LinkedIn,    ║\n"
            "  ║                                     Twitter/X Mentions           ║\n"
            "  ║    [+] Technical Infrastructure   : WHOIS, DNS History,          ║\n"
            "  ║                                     GitHub Repos, HIBP Breach    ║\n"
            "  ║    [+] Contextual & Regulatory    : OpenCorporates API,          ║\n"
            "  ║                                     News Archives                ║\n"
            "  ║                                                                  ║\n"
            "  ║  PHASE II — Analysis & Disambiguation                            ║\n"
            "  ║    [+] Entity Resolution  : Link domains, IPs, emails            ║\n"
            "  ║    [+] False Positive Filter : Contextual validation             ║\n"
            "  ║    [+] Risk Scoring       : Weighted algorithm (5 parameters)    ║\n"
            "  ║                                                                  ║\n"
            "  ║  PHASE III — Reporting Engine                                    ║\n"
            "  ║    [+] Executive Summary  : High-level digital footprint         ║\n"
            "  ║    [+] Categorized Tables : Structured discovered assets         ║\n"
            "  ║    [+] Audit Trail        : Source URL + retrieval timestamp     ║\n"
            "  ║    [+] Export             : PDF + Markdown                       ║\n"
            "  ║                                                                  ║\n"
            "  ║  ► Enter a target above and click  [ Start Investigate ]         ║\n"
            "  ╚══════════════════════════════════════════════════════════════════╝\n"
        )
        self.result_box.insert("end", welcome)

    # ── Scan ───────────────────────────────────────────────────────────────────
    def _start_scan(self):
        entity = self.entry.get().strip()
        if not entity:
            messagebox.showwarning("Input Required", "Please enter a target name.")
            return

        self.scan_btn.configure(state="disabled")
        self.pdf_btn.configure(state="disabled")
        self.md_btn.configure(state="disabled")
        self.result_box.delete("1.0", "end")
        self.progress.set(0)
        self.pct_label.configure(text="0%", text_color="white")
        self.risk_label.configure(text="Scanning...", text_color="gray")
        self.score_label.configure(text="— / 100", text_color="gray")
        self.sources_label.configure(text="—", text_color="gray")
        self.entity_name = entity

        threading.Thread(target=self._run_scan, args=(entity,), daemon=True).start()

    def _run_scan(self, entity: str):
        try:
            all_data = []

            self._update_progress(
                "Phase I  |  Step 1/3 — Technical scan (WHOIS, DNS, HIBP, GitHub)...",
                0.15
            )
            all_data += TechnicalAdapter().fetch(entity)

            self._update_progress(
                "Phase I  |  Step 2/3 — Social scan (Google Dorks, Twitter, LinkedIn)...",
                0.40
            )
            all_data += SocialAdapter().fetch(entity)

            self._update_progress(
                "Phase I  |  Step 3/3 — Regulatory scan (OpenCorporates, News)...",
                0.60
            )
            all_data += RegulatoryAdapter().fetch(entity)

            self._update_progress(
                "Phase II  |  Analyzing & resolving entities (grouping, false-positive filter)...",
                0.75
            )
            resolver = EntityResolver()
            self.resolved_data = resolver.resolve(entity, all_data)

            self._update_progress(
                "Phase II  |  Calculating risk score across 5 parameters...",
                0.85
            )
            scorer = RiskScorer()
            self.risk_data = scorer.score(self.resolved_data)

            self._update_progress(
                "Phase III  |  Building report (executive summary, audit trail)...",
                0.95
            )
            self._display_results()

            total_src = self.resolved_data["total_sources"]
            self._update_progress(
                f"Scan complete — {total_src} data sources queried across 3 phases",
                1.0
            )
            self.after(0, lambda: self.pdf_btn.configure(state="normal"))
            self.after(0, lambda: self.md_btn.configure(state="normal"))

        except Exception as e:
            self._update_progress(f"Error: {str(e)}", 0.0)
            self.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
        finally:
            self.after(0, lambda: self.scan_btn.configure(state="normal"))

    def _update_progress(self, msg: str, pct: float):
        pct_text = f"{int(pct * 100)}%"
        self.after(0, lambda: self.progress.set(pct))
        self.after(0, lambda: self.pct_label.configure(text=pct_text, text_color="white"))
        self.after(0, lambda: self.step_label.configure(text=msg, text_color="white"))

    # ── Display Results ────────────────────────────────────────────────────────
    def _display_results(self):
        r = self.resolved_data
        risk = self.risk_data

        self.after(0, lambda: self.risk_label.configure(
            text=risk["level"], text_color=risk["color"]
        ))
        self.after(0, lambda: self.score_label.configure(
            text=f"{risk['score']} / 100", text_color=risk["color"]
        ))
        self.after(0, lambda: self.sources_label.configure(
            text=str(r["total_sources"]), text_color="white"
        ))

        def write():
            box = self.result_box
            box.delete("1.0", "end")

            def ln(txt=""):
                box.insert("end", txt + "\n")

            ln("=" * 68)
            ln(f"  OSINT REPORT  |  Target: {self.entity_name.upper()}")
            ln("=" * 68)
            ln()
            ln(f"  Risk Level   : {risk['level']}")
            ln(f"  Risk Score   : {risk['score']} / 100")
            ln(f"  Sources Used : {r['total_sources']}")
            ln()

            # Score breakdown
            ln("  SCORE BREAKDOWN")
            ln("  " + "-" * 60)
            ln("  How score is calculated (max 100 pts):")
            ln("  - Data Breach (HIBP)  : 40 pts  [checks HaveIBeenPwned database]")
            ln("  - Exposed Emails      : 20 pts  [WHOIS + public search]")
            ln("  - Exposed IPs         : 15 pts  [DNS A-records + WHOIS]")
            ln("  - News Mentions       : 15 pts  [NewsAPI articles]")
            ln("  - GitHub Repos        : 10 pts  [GitHub Search API]")
            ln()

            breakdown = risk.get("score_breakdown", [])
            if breakdown:
                ln("  Triggered in this scan:")
                for item in breakdown:
                    ln(f"    + {item}")
                ln(f"    = TOTAL: {risk['score']} / 100  =>  {risk['level']}")
            else:
                ln("  No parameters triggered this scan => Score: 0 / 100")
            ln()

            # Key Findings
            ln("  KEY FINDINGS")
            ln("  " + "-" * 60)
            for reason in risk["reasons"]:
                ln(f"  {reason}")
            ln()

            # Parameters used
            ln("  PARAMETERS USED IN THIS SCAN")
            ln("  " + "-" * 60)
            for param in risk.get("parameters_used", []):
                ln(f"  {param}")
            ln()

            # Discovered assets
            ln("  DISCOVERED ASSETS")
            ln("  " + "-" * 60)
            ln(f"  Emails   : {', '.join(r['linked_emails'][:8]) or 'None found'}")
            ln(f"  Domains  : {', '.join(r['linked_domains'][:8]) or 'None found'}")
            ln(f"  IPs      : {', '.join(r['linked_ips'][:8]) or 'None found'}")
            ln()

            # Intelligence per category
            for category in ["technical", "social", "regulatory", "contextual"]:
                items = r.get(category, [])
                if not items:
                    continue
                ln(f"  {category.upper()} INTELLIGENCE")
                ln("  " + "=" * 60)
                for dp in items:
                    ln(f"\n  > [{dp.source}]  |  Confidence: {int(dp.confidence * 100)}%")
                    data_str = str(dp.data)
                    while data_str:
                        ln(f"    {data_str[:85]}")
                        data_str = data_str[85:]
                    ln(f"    URL  : {dp.url}")
                    ln(f"    Time : {dp.timestamp}")
                ln()

            ln("=" * 68)
            ln("  Export using buttons below  |  PDF or Markdown")
            ln("=" * 68)

        self.after(0, write)

    # ── Export ─────────────────────────────────────────────────────────────────
    def _export_pdf(self):
        if not self.resolved_data:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialfile=f"{self.entity_name.replace(' ', '_')}_OSINT_Report.pdf",
        )
        if path:
            try:
                saved = ReportGenerator().generate_pdf(
                    self.entity_name, self.resolved_data, self.risk_data, path
                )
                self._update_progress(f"PDF saved: {saved}", 1.0)
                messagebox.showinfo("Export Successful", f"PDF saved:\n{saved}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def _export_markdown(self):
        if not self.resolved_data:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".md",
            filetypes=[("Markdown files", "*.md")],
            initialfile=f"{self.entity_name.replace(' ', '_')}_OSINT_Report.md",
        )
        if path:
            try:
                saved = ReportGenerator().generate_markdown(
                    self.entity_name, self.resolved_data, self.risk_data, path
                )
                self._update_progress(f"Markdown saved: {saved}", 1.0)
                messagebox.showinfo("Export Successful", f"Markdown saved:\n{saved}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def _clear(self):
        self.entry.delete(0, "end")
        self.progress.set(0)
        self.pct_label.configure(text="0%", text_color="gray")
        self.step_label.configure(
            text="Ready — Enter a target and click Start Investigate",
            text_color="gray"
        )
        self.risk_label.configure(text="—", text_color="gray")
        self.score_label.configure(text="— / 100", text_color="gray")
        self.sources_label.configure(text="—", text_color="gray")
        self.pdf_btn.configure(state="disabled")
        self.md_btn.configure(state="disabled")
        self.resolved_data = None
        self.risk_data = None
        self.entity_name = None
        self._show_welcome()


if __name__ == "__main__":
    app = OSINTApp()
    app.mainloop()
