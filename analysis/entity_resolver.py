import re
from collections import defaultdict


class EntityResolver:

    def resolve(self, entity: str, data_points: list) -> dict:
        grouped = defaultdict(list)
        for dp in data_points:
            grouped[dp.category].append(dp)

        all_text = " ".join(str(dp.data) for dp in data_points)

        return {
            "entity": entity,
            "technical": grouped.get("technical", []),
            "social": grouped.get("social", []),
            "regulatory": grouped.get("regulatory", []),
            "contextual": grouped.get("contextual", []),
            "linked_emails": self._extract_emails(all_text),
            "linked_domains": self._extract_domains(all_text),
            "linked_ips": self._extract_ips(all_text),
            "total_sources": len(data_points),
        }

    def _extract_emails(self, text: str) -> list:
        found = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)
        # Remove duplicates, keep unique
        return list(dict.fromkeys(found))[:20]

    def _extract_domains(self, text: str) -> list:
        found = re.findall(r"\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,6}\b", text)
        # Filter noise - keep only meaningful domains
        blacklist = {"N/A", "None", "True", "False"}
        cleaned = [d for d in found if d not in blacklist and len(d) > 4]
        return list(dict.fromkeys(cleaned))[:20]

    def _extract_ips(self, text: str) -> list:
        found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        # Validate IP ranges
        valid = []
        for ip in found:
            parts = ip.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                valid.append(ip)
        return list(dict.fromkeys(valid))[:20]
