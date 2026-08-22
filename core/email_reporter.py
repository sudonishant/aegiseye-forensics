"""HTML report generation for read-only email threat triage."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


class EmailThreatReporter:
    """Render structured email-analysis results into a portable HTML report."""

    def __init__(self, target_name: str) -> None:
        self.target_name = target_name

    @staticmethod
    def _esc(value: Any) -> str:
        return html.escape(str(value if value is not None else ""))

    def generate(self, data: Dict[str, Any], output_path: str = "aegiseye_email_report.html") -> str:
        risk = data.get("risk", {})
        message = data.get("message", {})
        evidence = data.get("evidence", {})
        auth = data.get("authentication", {})
        relay = data.get("relay", {})
        indicators = data.get("indicators", {})
        findings = data.get("findings", [])

        finding_rows = "".join(
            f"<tr><td><span class='pill {self._esc(item.get('severity', 'low'))}'>{self._esc(item.get('severity', 'low')).upper()}</span></td>"
            f"<td><strong>{self._esc(item.get('title'))}</strong><br><span class='muted'>{self._esc(item.get('detail'))}</span></td>"
            f"<td>{self._esc(item.get('recommendation'))}</td></tr>"
            for item in findings
        ) or "<tr><td colspan='3'>No explainable risk indicators were found by local triage rules.</td></tr>"

        auth_rows = "".join(
            f"<tr><td>{self._esc(key.upper())}</td><td>{self._esc(value)}</td></tr>"
            for key, value in auth.items()
        )
        relay_rows = "".join(
            f"<tr><td>{self._esc(hop.get('hop'))}</td><td><code>{self._esc(', '.join(hop.get('ips', [])) or 'No IPv4 parsed')}</code></td>"
            f"<td>{self._esc(hop.get('header'))}</td></tr>"
            for hop in relay.get("path", [])
        ) or "<tr><td colspan='3'>No Received headers were present.</td></tr>"

        url_items = "".join(
            f"<li><code>{self._esc(item.get('url'))}</code> — {self._esc(item.get('host'))}"
            f"{' <span class=\"pill medium\">shortener</span>' if item.get('shortener') else ''}"
            f"{' <span class=\"pill high\">punycode</span>' if item.get('punycode') else ''}</li>"
            for item in indicators.get("urls", [])
        ) or "<li>No URLs extracted.</li>"
        attachment_items = "".join(
            f"<li><code>{self._esc(item.get('filename'))}</code> — {self._esc(item.get('content_type'))}, {self._esc(item.get('size_bytes'))} bytes"
            f"{' <span class=\"pill high\">review</span>' if item.get('suspicious_extension') else ''}</li>"
            for item in indicators.get("attachments", [])
        ) or "<li>No attachments extracted.</li>"

        score = int(risk.get("score", 0) or 0)
        level = self._esc(risk.get("level", "low"))
        generated_at = datetime.now(timezone.utc).isoformat()
        html_document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AegisEye Email Threat Report</title>
<style>
:root {{ --bg:#08111f; --card:#101c2f; --line:#233653; --text:#eef5ff; --muted:#a6b7cf; --blue:#27a3ff; --orange:#f1a247; --green:#3bc47a; --red:#ef6b73; --yellow:#e3b34e; }}
* {{ box-sizing:border-box; font-family:Inter,system-ui,-apple-system,sans-serif; }} body {{ margin:0; background:linear-gradient(135deg,#07101c,#0e1a2c); color:var(--text); padding:28px; line-height:1.45; }} main {{ max-width:1160px; margin:auto; }} header, section {{ background:rgba(16,28,47,.94); border:1px solid var(--line); border-radius:16px; padding:24px; margin-bottom:18px; box-shadow:0 14px 36px rgba(0,0,0,.18); }} h1 {{ margin:0 0 4px; font-size:30px; }} h2 {{ color:#8dd2ff; font-size:20px; margin:0 0 14px; }} h3 {{ font-size:15px; color:var(--muted); margin:0 0 6px; text-transform:uppercase; letter-spacing:.08em; }} p {{ margin:6px 0; }} .meta {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; border-top:1px solid var(--line); margin-top:18px; padding-top:18px; }} .value {{ font-weight:650; word-break:break-word; }} .risk {{ display:flex; align-items:center; gap:18px; margin-top:10px; }} .score {{ font-size:46px; font-weight:800; color:var(--orange); }} .pill {{ display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:800; letter-spacing:.06em; }} .pill.high {{ background:rgba(239,107,115,.18); color:#ff9fa6; }} .pill.medium {{ background:rgba(227,179,78,.18); color:#ffd67b; }} .pill.low {{ background:rgba(59,196,122,.18); color:#8cf0b4; }} table {{ width:100%; border-collapse:collapse; }} th,td {{ text-align:left; vertical-align:top; padding:10px 12px; border-bottom:1px solid var(--line); }} th {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.07em; }} code {{ font-family:ui-monospace,SFMono-Regular,monospace; font-size:12px; color:#cfe8ff; word-break:break-all; }} .muted {{ color:var(--muted); }} ul {{ margin:8px 0; padding-left:22px; }} footer {{ color:var(--muted); text-align:center; padding:14px; font-size:12px; }} .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }} @media(max-width:760px){{ body{{padding:14px}} .grid{{grid-template-columns:1fr}} }}
</style>
</head>
<body><main>
<header><h1>AegisEye Email Threat Report</h1><p class="muted">Read-only local triage — preserve the original message for evidentiary review.</p>
<div class="risk"><div class="score">{score}<small>/100</small></div><div><span class="pill {level}">{level.upper()}</span><p>{self._esc(risk.get('summary'))}</p></div></div>
<div class="meta"><div><h3>Source</h3><div class="value">{self._esc(Path(self.target_name).name)}</div></div><div><h3>Subject</h3><div class="value">{self._esc(message.get('subject') or '(no subject)')}</div></div><div><h3>From</h3><div class="value">{self._esc(message.get('from') or '(unknown)')}</div></div><div><h3>Evidence SHA-256</h3><div class="value"><code>{self._esc(evidence.get('raw_email_sha256'))}</code></div></div></div>
</header>
<section><h2>Explainable findings</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>Recommended action</th></tr></thead><tbody>{finding_rows}</tbody></table></section>
<div class="grid"><section><h2>Authentication</h2><table><thead><tr><th>Signal</th><th>Result</th></tr></thead><tbody>{auth_rows}</tbody></table></section>
<section><h2>Message identity</h2><table><tbody><tr><th>Reply-To</th><td>{self._esc(message.get('reply_to') or '(none)')}</td></tr><tr><th>Return-Path</th><td>{self._esc(message.get('return_path') or '(none)')}</td></tr><tr><th>Message-ID</th><td><code>{self._esc(message.get('message_id') or '(none)')}</code></td></tr><tr><th>Date</th><td>{self._esc(message.get('date') or '(none)')}</td></tr></tbody></table></section></div>
<section><h2>Relay path & origin candidates</h2><p><strong>Earliest reliable IP candidate:</strong> <code>{self._esc(relay.get('earliest_reliable_ip') or 'Unavailable')}</code></p><p class="muted">{self._esc(relay.get('geolocation_note'))}</p><table><thead><tr><th>Hop</th><th>Parsed IPs</th><th>Received header</th></tr></thead><tbody>{relay_rows}</tbody></table></section>
<div class="grid"><section><h2>URLs</h2><ul>{url_items}</ul></section><section><h2>Attachments</h2><ul>{attachment_items}</ul></section></div>
<section><h2>Evidence handling</h2><p><strong>Analysis mode:</strong> {self._esc(evidence.get('analysis_mode'))}</p><p><strong>Generated at:</strong> {self._esc(generated_at)}</p><p class="muted">{self._esc(evidence.get('chain_of_custody_note'))}</p></section>
<footer>Generated by AegisEye Forensics. This report supports triage and investigation; it does not establish attribution from a single signal.</footer>
</main></body></html>"""

        destination = Path(output_path)
        destination.write_text(html_document, encoding="utf-8")
        return str(destination.resolve())

    @staticmethod
    def as_json(data: Dict[str, Any]) -> str:
        return json.dumps(data, indent=2, sort_keys=True)
