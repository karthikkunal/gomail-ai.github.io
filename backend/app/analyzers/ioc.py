import re, tldextract

URL_RE=re.compile(r'https?://[^\s\]>)"\']+', re.I)
IP_RE=re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
EMAIL_RE=re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', re.I)
HASH_RE=re.compile(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b')
SUSPICIOUS_WORDS=['password','verify','urgent','invoice','payment','wallet','mfa','otp','login','suspended','blocked','click here']

def extract_iocs(text):
    urls=sorted(set(URL_RE.findall(text)))
    ips=sorted(set(IP_RE.findall(text)))
    emails=sorted(set(EMAIL_RE.findall(text)))
    hashes=sorted(set(HASH_RE.findall(text)))
    domains=set()
    for u in urls:
        ext=tldextract.extract(u)
        if ext.domain and ext.suffix:
            domains.add(ext.registered_domain)
    for e in emails:
        domains.add(e.split('@')[-1].lower())
    keywords=[w for w in SUSPICIOUS_WORDS if w in text.lower()]
    return {"urls":urls,"domains":sorted(domains),"ips":ips,"emails":emails,"hashes":hashes,"keywords":keywords}


def build_osint_pivots(iocs):
    pivots=[]
    for d in iocs['domains'][:50]:
        pivots += [
            {"type":"domain","value":d,"source":"VirusTotal","url":f"https://www.virustotal.com/gui/domain/{d}"},
            {"type":"domain","value":d,"source":"crt.sh","url":f"https://crt.sh/?q={d}"},
            {"type":"domain","value":d,"source":"AlienVault OTX","url":f"https://otx.alienvault.com/indicator/domain/{d}"},
        ]
    for ip in iocs['ips'][:50]:
        pivots += [
            {"type":"ip","value":ip,"source":"AbuseIPDB","url":f"https://www.abuseipdb.com/check/{ip}"},
            {"type":"ip","value":ip,"source":"VirusTotal","url":f"https://www.virustotal.com/gui/ip-address/{ip}"},
        ]
    for u in iocs['urls'][:30]:
        pivots += [
            {"type":"url","value":u,"source":"URLHaus","url":"https://urlhaus.abuse.ch/browse/"},
            {"type":"url","value":u,"source":"urlscan.io","url":"https://urlscan.io/"},
        ]
    for h in iocs['hashes'][:30]:
        pivots.append({"type":"hash","value":h,"source":"MalwareBazaar","url":f"https://bazaar.abuse.ch/browse.php?search={h}"})
    return pivots
