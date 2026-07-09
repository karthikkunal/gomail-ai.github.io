from app.analyzers.text_extract import extract_text
from app.analyzers.email_headers import parse_email_headers, assess_headers
from app.analyzers.ioc import extract_iocs, build_osint_pivots
from app.analyzers.scoring import score_investigation
from app.analyzers.mitre import map_mitre
from app.analyzers.report import build_report
import hashlib


def analyze_file(filename: str, content: bytes, content_type: str):
    sha256 = hashlib.sha256(content).hexdigest()
    text, extraction_notes = extract_text(filename, content, content_type)
    header_data = parse_email_headers(filename, content, text)
    header_findings = assess_headers(header_data, text)
    iocs = extract_iocs(text)
    pivots = build_osint_pivots(iocs)
    mitre = map_mitre(iocs, header_findings, text)
    score = score_investigation(filename, text, iocs, header_findings)
    report = build_report(filename, sha256, score, header_data, header_findings, iocs, mitre, extraction_notes)
    timeline = [
        {"time":"T+0s","stage":"Ingestion","detail":f"Received {filename}"},
        {"time":"T+1s","stage":"Text extraction","detail":"Extracted readable content and normalized it."},
        {"time":"T+2s","stage":"Header analysis","detail":f"Generated {len(header_findings)} header findings."},
        {"time":"T+3s","stage":"IOC extraction","detail":f"Found {len(iocs['urls'])} URLs, {len(iocs['domains'])} domains, {len(iocs['ips'])} IPs."},
        {"time":"T+4s","stage":"Risk scoring","detail":f"Verdict: {score['verdict']} / Score: {score['score']}"},
    ]
    return {
        "filename": filename,
        "sha256": sha256,
        "content_type": content_type,
        "score": score,
        "headers": header_data,
        "header_findings": header_findings,
        "iocs": iocs,
        "osint_pivots": pivots,
        "mitre": mitre,
        "timeline": timeline,
        "extraction_notes": extraction_notes,
        "report_markdown": report,
        "preview_text": text[:5000],
        "recommendations": recommendations(score, iocs, header_findings),
    }


def recommendations(score, iocs, findings):
    recs=[]
    if score['score'] >= 70:
        recs += ["Quarantine the email and block sender/domain indicators.", "Reset credentials if the user clicked links or opened attachments.", "Create SIEM hunt queries for extracted IOCs."]
    elif score['score'] >= 40:
        recs += ["Review URLs in a sandbox before user interaction.", "Check similar emails across mailbox/search logs."]
    else:
        recs += ["No immediate malicious evidence found. Keep evidence for audit." ]
    if iocs['urls']:
        recs.append("Open OSINT pivot links from the IOC table; do not browse suspicious links directly.")
    if findings:
        recs.append("Validate authentication and routing anomalies with mail gateway logs.")
    return recs
