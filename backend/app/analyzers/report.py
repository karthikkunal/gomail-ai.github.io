def build_report(filename, sha256, score, headers, findings, iocs, mitre, notes):
    lines=[
        f"# GoMail AI Investigation Report",
        f"\n**File:** {filename}",
        f"\n**SHA256:** `{sha256}`",
        f"\n**Verdict:** **{score['verdict'].upper()}**",
        f"\n**Risk Score:** {score['score']}/100",
        "\n## Reasons",
    ]
    lines += [f"- {r}" for r in score['reasons']]
    lines.append("\n## Header Findings")
    lines += [f"- **{f['severity'].upper()}** {f['title']}: {f['detail']}" for f in findings]
    lines.append("\n## IOCs")
    for k in ['urls','domains','ips','emails','hashes']:
        vals=iocs.get(k,[])
        lines.append(f"\n### {k.title()} ({len(vals)})")
        lines += [f"- `{v}`" for v in vals[:50]] or ["- None"]
    lines.append("\n## MITRE Mapping")
    lines += [f"- **{m['tactic']}** / {m['technique']} — {m['evidence']}" for m in mitre] or ["- No strong MITRE mapping from local analysis."]
    lines.append("\n## Extraction Notes")
    lines += [f"- {n}" for n in notes]
    return '\n'.join(lines)
