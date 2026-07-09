from email import policy
from email.parser import BytesParser

INTERESTING = ['from','to','subject','date','reply-to','return-path','authentication-results','received','received-spf','dkim-signature','message-id']

def parse_email_headers(filename, content, text):
    if not filename.lower().endswith('.eml'):
        return {}
    try:
        msg=BytesParser(policy=policy.default).parsebytes(content)
        data={}
        for key in INTERESTING:
            vals=msg.get_all(key, [])
            if vals:
                data[key]=[str(v) for v in vals]
        return data
    except Exception:
        return {}


def assess_headers(headers, text):
    findings=[]
    auth=' '.join(headers.get('authentication-results',[]) + headers.get('received-spf',[])).lower()
    if headers and 'spf=fail' in auth:
        findings.append({"severity":"high","title":"SPF failed","detail":"Authentication-Results indicates SPF failure."})
    if headers and 'dkim=fail' in auth:
        findings.append({"severity":"high","title":"DKIM failed","detail":"Authentication-Results indicates DKIM failure."})
    if headers and 'dmarc=fail' in auth:
        findings.append({"severity":"high","title":"DMARC failed","detail":"Authentication-Results indicates DMARC failure."})
    if headers and 'dkim-signature' not in headers:
        findings.append({"severity":"medium","title":"Missing DKIM signature","detail":"Email does not expose DKIM-Signature header."})
    rp=' '.join(headers.get('return-path',[])).lower()
    frm=' '.join(headers.get('from',[])).lower()
    if rp and frm and rp.split('@')[-1].strip('<> ') not in frm:
        findings.append({"severity":"medium","title":"From/Return-Path mismatch","detail":"Return-Path appears different from visible From address."})
    if not headers:
        findings.append({"severity":"info","title":"No structured email headers","detail":"File is not EML or headers could not be parsed."})
    return findings
