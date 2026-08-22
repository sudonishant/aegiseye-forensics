"""Email threat detection and forensic triage primitives.

This module intentionally uses only Python's standard library. It performs
explainable, read-only triage on a raw RFC 5322 message and returns structured
findings that can be enriched by an approved IP/domain intelligence provider.
It does not claim attribution from a single IP address.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html import unescape
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit


class EmailThreatAnalyzer:
    """Analyze a raw email without modifying the input evidence."""

    MAX_BYTES = 10 * 1024 * 1024
    URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
    IPV4_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
    AUTH_RE = {
        name: re.compile(rf"\b{name}\s*=\s*([a-z]+)\b", re.IGNORECASE)
        for name in ("spf", "dkim", "dmarc")
    }
    AUTH_FAILURES = {"fail", "softfail", "permerror", "temperror"}
    SUSPICIOUS_EXTENSIONS = {
        ".ade", ".adp", ".app", ".bat", ".cmd", ".com", ".cpl", ".dll",
        ".docm", ".exe", ".hta", ".html", ".iso", ".js", ".jse", ".lnk",
        ".msi", ".ps1", ".scr", ".url", ".vbe", ".vbs", ".wsf", ".xlsm",
        ".zip", ".rar", ".7z",
    }
    URGENCY_TERMS = {
        "urgent", "immediately", "action required", "verify", "suspend",
        "payment", "invoice", "wire transfer", "password", "login",
        "gift card", "confidential", "account locked", "reset",
    }
    SHORTENER_HOSTS = {
        "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "rebrand.ly", "cutt.ly",
    }

    def __init__(self, raw_email: str | bytes, source_name: str = "raw_message.eml") -> None:
        if isinstance(raw_email, str):
            raw_bytes = raw_email.encode("utf-8", errors="replace")
        elif isinstance(raw_email, bytes):
            raw_bytes = raw_email
        else:
            raise TypeError("raw_email must be str or bytes")
        if not raw_bytes:
            raise ValueError("raw_email cannot be empty")
        if len(raw_bytes) > self.MAX_BYTES:
            raise ValueError(f"raw_email exceeds the {self.MAX_BYTES // (1024 * 1024)} MB safety limit")

        self.raw_bytes = raw_bytes
        self.source_name = source_name
        self.message = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    @classmethod
    def from_path(cls, path: str | Path) -> "EmailThreatAnalyzer":
        source = Path(path)
        raw_bytes = source.read_bytes()
        return cls(raw_bytes, source_name=str(source))

    @staticmethod
    def _header(message: Any, name: str) -> str:
        value = message.get(name, "")
        return str(value).strip() if value is not None else ""

    @staticmethod
    def _domain_from_address(value: str) -> str:
        _, address = parseaddr(value)
        if "@" not in address:
            return ""
        return address.rsplit("@", 1)[1].lower().strip().rstrip(">").strip()

    @staticmethod
    def _root_domain(domain: str) -> str:
        parts = [part for part in domain.lower().split(".") if part]
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()

    @staticmethod
    def _severity_for_score(score: int) -> str:
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        return "low"

    @staticmethod
    def _clean_url(url: str) -> str:
        return url.rstrip(".,;:!?)]}>\"'")

    def _body_text(self) -> str:
        chunks: List[str] = []
        try:
            if self.message.is_multipart():
                parts = self.message.walk()
            else:
                parts = [self.message]
            for part in parts:
                if part.is_multipart():
                    continue
                content_type = part.get_content_type()
                if content_type not in {"text/plain", "text/html"}:
                    continue
                try:
                    content = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                chunks.append(unescape(str(content)))
        except Exception:
            return ""
        return "\n".join(chunks)

    def _attachments(self) -> List[Dict[str, Any]]:
        attachments: List[Dict[str, Any]] = []
        try:
            for part in self.message.walk():
                if part.is_multipart():
                    continue
                filename = part.get_filename()
                disposition = part.get_content_disposition()
                if filename or disposition == "attachment":
                    filename = filename or "unnamed-attachment"
                    suffix = Path(filename).suffix.lower()
                    attachments.append(
                        {
                            "filename": filename,
                            "content_type": part.get_content_type(),
                            "size_bytes": len(part.get_payload(decode=True) or b""),
                            "suspicious_extension": suffix in self.SUSPICIOUS_EXTENSIONS,
                        }
                    )
        except Exception:
            return attachments
        return attachments

    def _urls(self, body: str) -> List[Dict[str, str]]:
        urls: List[Dict[str, str]] = []
        seen = set()
        for match in self.URL_RE.findall(body):
            url = self._clean_url(match)
            if url in seen:
                continue
            seen.add(url)
            parsed = urlsplit(url if "://" in url else f"http://{url}")
            host = (parsed.hostname or "").lower().rstrip(".")
            urls.append(
                {
                    "url": url,
                    "host": host,
                    "scheme": parsed.scheme.lower(),
                    "path": parsed.path or "/",
                    "punycode": host.startswith("xn--") or ".xn--" in host,
                    "shortener": host in self.SHORTENER_HOSTS,
                }
            )
        return urls

    def _authentication(self) -> Dict[str, str]:
        auth_texts: List[str] = []
        for header_name in ("Authentication-Results", "Received-SPF", "ARC-Authentication-Results"):
            auth_texts.extend(str(value) for value in self.message.get_all(header_name, []))
        auth_text = "\n".join(auth_texts)
        statuses: Dict[str, str] = {}
        for name, pattern in self.AUTH_RE.items():
            match = pattern.search(auth_text)
            statuses[name] = match.group(1).lower() if match else "not_found"
        statuses["dkim_signature_present"] = "true" if self.message.get("DKIM-Signature") else "false"
        return statuses

    def _relay_path(self, received_headers: Iterable[str]) -> List[Dict[str, Any]]:
        path: List[Dict[str, Any]] = []
        for index, header in enumerate(received_headers, start=1):
            ips = []
            for raw_ip in self.IPV4_RE.findall(header):
                try:
                    ip = ipaddress.ip_address(raw_ip)
                except ValueError:
                    continue
                if str(ip) not in ips:
                    ips.append(str(ip))
            path.append({"hop": index, "header": header, "ips": ips})
        return path

    def analyze(self) -> Dict[str, Any]:
        message = self.message
        sender = self._header(message, "From")
        reply_to = self._header(message, "Reply-To")
        return_path = self._header(message, "Return-Path")
        subject = self._header(message, "Subject")
        body = self._body_text()
        urls = self._urls(f"{subject}\n{body}")
        attachments = self._attachments()
        auth = self._authentication()
        received_headers = [str(value) for value in message.get_all("Received", [])]
        relay_path = self._relay_path(received_headers)
        relay_ips = []
        for hop in relay_path:
            for ip in hop["ips"]:
                if ip not in relay_ips:
                    relay_ips.append(ip)
        origin_candidates = list(reversed(relay_ips))

        from_domain = self._domain_from_address(sender)
        reply_domain = self._domain_from_address(reply_to)
        return_domain = self._domain_from_address(return_path)
        display_name, sender_address = parseaddr(sender)
        lower_text = f"{subject}\n{body}".lower()
        urgency_hits = sorted(term for term in self.URGENCY_TERMS if term in lower_text)
        findings: List[Dict[str, Any]] = []
        score = 0

        def add_finding(code: str, severity: str, title: str, detail: str, recommendation: str, points: int) -> None:
            nonlocal score
            findings.append(
                {
                    "code": code,
                    "severity": severity,
                    "title": title,
                    "detail": detail,
                    "recommendation": recommendation,
                    "points": points,
                }
            )
            score += points

        for scheme in ("spf", "dkim", "dmarc"):
            status = auth[scheme]
            if status in self.AUTH_FAILURES:
                add_finding(
                    f"auth_{scheme}_{status}",
                    "high" if status in {"fail", "permerror"} else "medium",
                    f"{scheme.upper()} authentication is {status}",
                    f"The message authentication result reports {scheme.upper()}={status}.",
                    f"Review the authenticated sending service and do not trust the sender identity without corroboration.",
                    12,
                )

        if from_domain and reply_domain and from_domain != reply_domain:
            add_finding(
                "reply_to_mismatch",
                "high",
                "Reply-To domain differs from From domain",
                f"From uses {from_domain}, while Reply-To uses {reply_domain}.",
                "Verify the reply destination through a trusted channel before responding.",
                18,
            )
        if from_domain and return_domain and from_domain != return_domain:
            add_finding(
                "return_path_mismatch",
                "medium",
                "Return-Path domain differs from From domain",
                f"From uses {from_domain}, while Return-Path uses {return_domain}.",
                "Inspect the relay and authentication chain before treating the message as legitimate.",
                12,
            )

        if urls:
            external_hosts = sorted({item["host"] for item in urls if item["host"]})
            mismatched_hosts = [
                host for host in external_hosts
                if from_domain and self._root_domain(host) != self._root_domain(from_domain)
            ]
            if mismatched_hosts:
                add_finding(
                    "external_link_domain",
                    "medium",
                    "Links point outside the sender domain",
                    f"Observed link hosts: {', '.join(mismatched_hosts[:5])}.",
                    "Open links only after independent verification; prefer navigating to the known service manually.",
                    min(18, 6 * len(mismatched_hosts)),
                )
            if any(item["punycode"] for item in urls):
                add_finding(
                    "punycode_url",
                    "high",
                    "Punycode domain detected in a link",
                    "At least one URL uses an xn-- label that may conceal a lookalike domain.",
                    "Inspect the registrable domain character by character and isolate the message for review.",
                    12,
                )
            if any(item["shortener"] for item in urls):
                add_finding(
                    "shortened_url",
                    "medium",
                    "Shortened URL detected",
                    "At least one link uses a common URL-shortening service.",
                    "Expand and inspect the destination in a safe analysis environment before opening it.",
                    8,
                )

        suspicious_attachments = [item["filename"] for item in attachments if item["suspicious_extension"]]
        if suspicious_attachments:
            add_finding(
                "suspicious_attachment",
                "high",
                "Potentially dangerous attachment type detected",
                f"Suspicious filenames: {', '.join(suspicious_attachments[:5])}.",
                "Do not execute or enable macros; quarantine the message and analyze the attachment separately.",
                min(20, 10 * len(suspicious_attachments)),
            )

        if len(urgency_hits) >= 2:
            add_finding(
                "social_engineering_language",
                "medium",
                "Urgency or account-pressure language detected",
                f"Matched cues: {', '.join(urgency_hits[:8])}.",
                "Verify payment, credential, or account requests out of band before taking action.",
                min(12, 2 * len(urgency_hits)),
            )

        if not received_headers:
            add_finding(
                "missing_received_chain",
                "medium",
                "No Received chain was found",
                "The message contains no Received header that can be reconstructed locally.",
                "Preserve the original message source and obtain upstream gateway logs if available.",
                8,
            )
        elif not relay_ips:
            add_finding(
                "no_relay_ip",
                "low",
                "Received headers contain no parseable IPv4 address",
                "The visible relay chain cannot be mapped to an IP address using local parsing.",
                "Use gateway logs or an approved parser for IPv6 and provider-specific relay formats.",
                4,
            )

        risk_score = min(100, score)
        risk_level = self._severity_for_score(risk_score)
        sha256 = hashlib.sha256(self.raw_bytes).hexdigest()

        return {
            "schema_version": "1.0",
            "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
            "source_name": self.source_name,
            "evidence": {
                "raw_email_sha256": sha256,
                "analysis_mode": "read_only_local_triage",
                "chain_of_custody_note": "Preserve the original .eml; this analysis does not modify the source evidence.",
            },
            "message": {
                "subject": subject,
                "from": sender,
                "display_name": display_name,
                "sender_address": sender_address,
                "reply_to": reply_to,
                "return_path": return_path,
                "date": self._header(message, "Date"),
                "message_id": self._header(message, "Message-ID"),
                "from_domain": from_domain,
                "reply_to_domain": reply_domain,
                "return_path_domain": return_domain,
            },
            "authentication": auth,
            "relay": {
                "received_header_count": len(received_headers),
                "path": relay_path,
                "relay_ips": relay_ips,
                "origin_candidates": origin_candidates,
                "earliest_reliable_ip": origin_candidates[0] if origin_candidates else None,
                "geolocation_status": "not_queried",
                "geolocation_note": "Attach an approved IP-intelligence provider before making a location assessment.",
            },
            "indicators": {
                "urls": urls,
                "attachments": attachments,
                "urgency_terms": urgency_hits,
            },
            "findings": findings,
            "risk": {
                "score": risk_score,
                "level": risk_level,
                "finding_count": len(findings),
                "summary": f"{risk_level.upper()} risk based on {len(findings)} explainable finding(s).",
            },
        }


def analyze_email_file(path: str | Path) -> Dict[str, Any]:
    """Convenience function for CLI and integrations."""
    return EmailThreatAnalyzer.from_path(path).analyze()
