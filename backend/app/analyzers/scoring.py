def score_investigation(filename, text, iocs, findings):
    score=0
    reasons=[]
    lower=text.lower()
    high=sum(1 for f in findings if f['severity']=='high')
    med=sum(1 for f in findings if f['severity']=='medium')
    score += high*25 + med*10
    if high: reasons.append(f"{high} high-severity authentication/header findings")
    if med: reasons.append(f"{med} medium-severity authentication/header findings")
    if len(iocs['urls'])>0: score+=15; reasons.append("Contains URLs requiring sandbox/OSINT review")
    if len(iocs['urls'])>3: score+=10; reasons.append("Multiple URLs detected")
    if iocs['keywords']:
        score += min(25, len(iocs['keywords'])*5); reasons.append("Suspicious social-engineering keywords: "+', '.join(iocs['keywords'][:8]))
    if any(x in lower for x in ['bit.ly','tinyurl','t.co/','goo.gl','rebrand.ly']):
        score+=15; reasons.append("URL shortener detected")
    if filename.lower().endswith(('.doc','.docm','.xlsm','.js','.vbs','.scr','.exe')):
        score+=30; reasons.append("Risky attachment/file extension")
    score=max(0,min(100,score))
    verdict='benign'
    if score>=70: verdict='malicious'
    elif score>=40: verdict='suspicious'
    return {"score":score,"verdict":verdict,"reasons":reasons or ["No strong malicious indicators found in local analysis."],"confidence":"medium" if score>=40 else "low-to-medium"}
