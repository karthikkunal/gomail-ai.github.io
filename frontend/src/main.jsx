import React, {useState} from 'react';
import { createRoot } from 'react-dom/client';
import { Shield, Upload, Activity, AlertTriangle, FileText, Search, Globe, Server, Brain, Download, CheckCircle2, XCircle, Zap } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line } from 'recharts';
import './styles.css';

const API = import.meta.env.VITE_API_BASE || 'https://gomail-ai-github-io.onrender.com';

function App(){
  const [result,setResult]=useState(null); const [loading,setLoading]=useState(false); const [error,setError]=useState('');
  async function onFile(e){
    const file=e.target.files?.[0]; if(!file) return; setLoading(true); setError(''); setResult(null);
    const fd=new FormData(); fd.append('file', file);
    try{ const res=await fetch(`${API}/api/analyze`,{method:'POST',body:fd}); if(!res.ok) throw new Error(await res.text()); setResult(await res.json()); }
    catch(err){ setError(String(err.message||err)); }
    finally{ setLoading(false); }
  }
  const score=result?.score?.score ?? 0;
  const verdict=result?.score?.verdict || 'waiting';
  return <div className="app">
    <Sidebar />
    <main className="main">
      <header className="hero"><div><p className="eyebrow">Go-Sec AI / GoMail AI MVP</p><h1>AI-assisted SOC email investigation dashboard</h1><p>Upload email/doc/image evidence and get local IOC extraction, header checks, risk score, MITRE mapping, OSINT pivots, and analyst report.</p></div><StatusBadge verdict={verdict} score={score}/></header>
      <section className="upload-card"><div><h2>Upload evidence</h2><p>Supported: .eml, .txt, .pdf, .docx, .png, .jpg. Use sample_phish.eml from backend/samples for testing.</p></div><label className="upload-btn"><Upload size={20}/> Select file<input type="file" onChange={onFile} hidden /></label></section>
      {loading && <div className="loading"><Zap className="spin"/> Running local investigation pipeline...</div>}
      {error && <div className="error"><XCircle/> {error}</div>}
      {!result ? <EmptyDashboard/> : <Dashboard result={result}/>} 
    </main>
  </div>
}
function Sidebar(){return <aside className="sidebar"><div className="brand"><Shield/> <span>GoMail AI</span></div>{['SOC Overview','Evidence Upload','Header Analysis','IOC Explorer','OSINT Pivots','MITRE Map','Reports'].map((x,i)=><div className="nav" key={x}>{i===0?<Activity/>:i===1?<Upload/>:i===2?<Server/>:i===3?<Search/>:i===4?<Globe/>:i===5?<Brain/>:<FileText/>}<span>{x}</span></div>)}</aside>}
function StatusBadge({verdict,score}){let cls=verdict==='malicious'?'bad':verdict==='suspicious'?'warn':'good'; return <div className={`status ${cls}`}><div className="score">{score}</div><div><strong>{verdict.toUpperCase()}</strong><p>Risk score /100</p></div></div>}
function EmptyDashboard(){const data=[{name:'Headers',v:0},{name:'URLs',v:0},{name:'Domains',v:0},{name:'IPs',v:0}];return <div className="grid"><Card title="SOC Dashboard"><p className="muted">Waiting for upload. The dashboard will populate with investigation telemetry after backend analysis.</p><ResponsiveContainer width="100%" height={180}><BarChart data={data}><XAxis dataKey="name"/><YAxis/><Tooltip/><Bar dataKey="v" radius={[8,8,0,0]}/></BarChart></ResponsiveContainer></Card><Card title="Planned Enterprise Connectors"><ul className="list"><li>Microsoft Defender / MDO connector</li><li>Splunk/Sentinel SIEM export</li><li>CrowdStrike/SentinelOne enrichment</li><li>CAPE/Cuckoo sandbox integration</li></ul></Card></div>}
function Dashboard({result}){const i=result.iocs; const counts=[{name:'URLs',v:i.urls.length},{name:'Domains',v:i.domains.length},{name:'IPs',v:i.ips.length},{name:'Emails',v:i.emails.length},{name:'Hashes',v:i.hashes.length}]; const sev=countSev(result.header_findings);return <>
  <div className="kpis"><Kpi icon={<AlertTriangle/>} label="Verdict" value={result.score.verdict}/><Kpi icon={<Search/>} label="IOCs" value={counts.reduce((a,b)=>a+b.v,0)}/><Kpi icon={<Server/>} label="Header findings" value={result.header_findings.length}/><Kpi icon={<Brain/>} label="MITRE mappings" value={result.mitre.length}/></div>
  <div className="grid"><Card title="IOC distribution"><ResponsiveContainer width="100%" height={240}><BarChart data={counts}><XAxis dataKey="name"/><YAxis/><Tooltip/><Bar dataKey="v" radius={[8,8,0,0]}/></BarChart></ResponsiveContainer></Card><Card title="Header severity"><ResponsiveContainer width="100%" height={240}><PieChart><Pie data={sev} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90}>{sev.map((_,i)=><Cell key={i}/>)}</Pie><Tooltip/></PieChart></ResponsiveContainer></Card></div>
  <Card title="Investigation timeline"><div className="timeline">{result.timeline.map((t,i)=><div className="time" key={i}><span>{t.time}</span><strong>{t.stage}</strong><p>{t.detail}</p></div>)}</div></Card>
  <Card title="Risk reasons & recommendations"><div className="cols"><div><h3>Reasons</h3><ul className="list">{result.score.reasons.map((r,i)=><li key={i}>{r}</li>)}</ul></div><div><h3>Recommendations</h3><ul className="list">{result.recommendations.map((r,i)=><li key={i}>{r}</li>)}</ul></div></div></Card>
  <Card title="IOC Explorer"><IocTable iocs={i} pivots={result.osint_pivots}/></Card>
  <Card title="Header findings"><div className="findings">{result.header_findings.map((f,i)=><div className={`finding ${f.severity}`} key={i}><strong>{f.title}</strong><p>{f.detail}</p><span>{f.severity}</span></div>)}</div></Card>
  <Card title="MITRE ATT&CK mapping"><div className="findings">{result.mitre.map((m,i)=><div className="finding" key={i}><strong>{m.tactic}</strong><p>{m.technique}</p><small>{m.evidence}</small></div>)}</div></Card>
  <Card title="Analyst report"><button className="secondary" onClick={()=>download('gomail-report.md', result.report_markdown)}><Download size={16}/> Download Markdown</button><pre className="report">{result.report_markdown}</pre></Card>
</>}
function countSev(fs){const m={high:0,medium:0,info:0,low:0}; fs.forEach(f=>m[f.severity]=(m[f.severity]||0)+1); return Object.entries(m).filter(([,v])=>v).map(([name,value])=>({name,value})) || [{name:'none',value:1}]}
function Card({title,children}){return <section className="card"><h2>{title}</h2>{children}</section>}
function Kpi({icon,label,value}){return <div className="kpi">{icon}<div><span>{label}</span><strong>{value}</strong></div></div>}
function IocTable({iocs,pivots}){const rows=[]; ['urls','domains','ips','emails','hashes'].forEach(k=>iocs[k].forEach(v=>rows.push({type:k,value:v}))); return <div className="tablewrap"><table><thead><tr><th>Type</th><th>Value</th><th>OSINT</th></tr></thead><tbody>{rows.map((r,i)=><tr key={i}><td>{r.type}</td><td className="mono">{r.value}</td><td>{pivots.filter(p=>p.value===r.value || (r.type==='urls'&&p.type==='url')).slice(0,3).map((p,j)=><a key={j} href={p.url} target="_blank">{p.source}</a>)}</td></tr>)}</tbody></table></div>}
function download(name, text){const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([text],{type:'text/markdown'})); a.download=name; a.click();}
createRoot(document.getElementById('root')).render(<App/>);
