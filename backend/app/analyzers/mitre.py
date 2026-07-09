def map_mitre(iocs, findings, text):
    lower=text.lower()
    items=[]
    if iocs['urls'] or 'click' in lower:
        items.append({"tactic":"Initial Access","technique":"T1566.002 Phishing: Spearphishing Link","evidence":"URLs or click-driven language found."})
    if any(w in lower for w in ['invoice','payment','verify','password','mfa','otp']):
        items.append({"tactic":"Credential Access","technique":"T1566/T1539 Phishing/Credential Collection","evidence":"Credential/payment lure language present."})
    if any(f['severity']=='high' for f in findings):
        items.append({"tactic":"Defense Evasion","technique":"Email authentication bypass indicators","evidence":"Authentication failure or spoofing signal found."})
    return items
