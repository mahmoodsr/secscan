import React, {useId} from 'react';
import {AlertCircle, ArrowUpRight, Check, Circle, Clock, Folder, Minus, ShieldCheck} from 'lucide-react';
import {t, tools, states, levels} from './strings';
export const sum = counts => Object.values(counts || {}).reduce((total,value)=>total+value,0);
export const time = value => value ? new Intl.DateTimeFormat(undefined,{dateStyle:'medium',timeStyle:'medium'}).format(new Date(value)) : t.none;
export const shortDate = value => new Intl.DateTimeFormat(undefined,{month:'short',day:'numeric'}).format(new Date(value));
export const location = row => [row.file, row.line || null].filter(Boolean).join(':') || t.none;
export const label = key => tools[key] || key;
export const safeUrl = value => /^https?:\/\//i.test(value || '') ? value : undefined;
export function Badge({value, severity=false}) {
  const key=(value || 'PENDING').toLowerCase();
  const Icon=severity ? Circle : ({pass:Check,ok:Check,running:Clock,cancelling:Clock,fail:AlertCircle,error:AlertCircle,warn:AlertCircle,missing:AlertCircle,incomplete:AlertCircle})[key] || Minus;
  return <span className={'badge '+key}><Icon size={13} aria-hidden="true"/>{severity ? value : states[value] || t.toolUnknown}</span>;
}
export function Panel({title, action, className='',children}) {
  return <section className={'panel '+className}><div className="panel-head"><h2>{title}</h2>{action}</div>{children}</section>;
}
export function IconButton({title,icon:Icon,onClick,active=false}) {
  return <button className={'icon-button '+(active?'selected':'')} title={title} aria-label={title} onClick={onClick}><Icon size={17} aria-hidden="true"/></button>;
}
export function KPI({icon:Icon,name,children}) {
  return <div className="kpi"><span className="kpi-icon"><Icon size={19}/></span><div><span className="kpi-value">{children}</span><span className="small muted">{name}</span></div></div>;
}
export function Trend({rows, range,setRange}) {
  const id=useId().replace(/:/g,'');
  const data=rows.filter(row=>row.report).slice(0,range).reverse();
  const top=Math.max(4,...data.map(row=>row.blocking));
  const x=index=>52+index*(614/Math.max(1,data.length-1));
  const y=value=>166-132*value/top;
  const points=data.map((row,i)=>[x(i),y(row.blocking)]);
  const curve=points.map(([px,py],i)=>{
    if(!i)return 'M'+px+' '+py;
    const [a,b]=points[i-1],mid=(a+px)/2;
    return 'C'+mid+' '+b+' '+mid+' '+py+' '+px+' '+py;
  }).join(' ');
  const filled=curve && points.length>1 ? curve+' L'+points.at(-1)[0]+' 166 H52 Z' : '';
  return <Panel title={t.trend} className="trend" action={<div className="range" aria-label={t.trend}>{[7,30].map(n=><button key={n} aria-pressed={range===n} onClick={()=>setRange(n)}>{n===7?t.range7:t.range30}</button>)}</div>}>
    <div className="trend-summary"><strong>{data.at(-1)?.blocking ?? t.none}</strong><span className="muted">{data.length ? data.length+' '+t.scanned : t.noScans}</span></div>
    <div className="legend"><span><i className="swatch coral"/>{t.trend}</span><span><i className="dash"/>{t.threshold} · 0</span></div>
    <svg className="chart" viewBox="0 0 690 206" role="img" aria-label={data.length ? t.trend+': '+data.map(r=>shortDate(r.started)+' '+r.blocking).join(', ')+'. '+t.threshold+' 0.' : t.trendEmpty}>
      <defs><linearGradient id={id} x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="var(--coral)" stopOpacity=".42"/><stop offset="100%" stopColor="var(--coral)" stopOpacity="0"/></linearGradient></defs>
      {[top,Math.round(top/2),0].map(v=><g key={v}><line x1="52" x2="666" y1={y(v)} y2={y(v)} className={v===0?'limit-line':'grid-line'}/><text x="34" y={y(v)+4} textAnchor="end">{v}</text></g>)}
      {filled && <path d={filled} fill={'url(#'+id+')'}/>}
      {curve && <path d={curve} stroke="var(--coral)" strokeWidth="2.7" fill="none"/>}
      {points.map(([px,py],i)=><g key={data[i].id}><circle cx={px} cy={py} r={points.length>12?2:4} fill="var(--coral)"/>{(i===0||i===points.length-1||i%Math.ceil(points.length/5)===0)&&<text x={px} y="191" textAnchor={i===0?'start':i===points.length-1?'end':'middle'}>{shortDate(data[i].started)}</text>}</g>)}
      {!data.length && <text className="empty-chart" x="350" y="111" textAnchor="middle">{t.trendEmpty}</text>}
    </svg>
  </Panel>;
}
export function ToolGauge({report}) {
  const statuses=Object.keys(tools).map(tool=>[tool,report?.tools?.[tool]?.status]);
  const count=statuses.filter(([,status])=>status==='PASS').length;
  const total=statuses.length;
  return <Panel title={t.tools} className="gauge-panel" action={<ShieldCheck size={18}/>}>
    {report ? <>
      <p className="gauge-source small muted">{report.project_name} · {time(report.started_at)}</p>
      <div className="gauge" style={{'--sweep':count/total*100+'%'}} role="img" aria-label={t.tools+': '+count+' / '+total}><div><strong>{count}<small>/{total}</small></strong><span>{t.tools}</span></div></div>
      <ul className="gauge-statuses">{statuses.map(([tool,status])=><li key={tool}><span>{label(tool)}</span><Badge value={status||'UNAVAILABLE'}/></li>)}</ul>
    </> : <p className="muted">{t.noData}</p>}
  </Panel>;
}
export function SeverityMix({counts}) {
  const total=sum(counts);
  return <Panel title={t.severity} action={<ArrowUpRight size={18}/>}>
    <div className="mix-total"><strong>{total}</strong><span className="muted">{t.total}</span></div>
    <div className="mix" role="img" aria-label={levels.map(level=>level+' '+(counts?.[level] || 0)).join(', ')}>
      {total ? levels.filter(level=>counts[level]).map(level=><i key={level} className={level.toLowerCase()} style={{flex:counts[level]}} title={level+' '+counts[level]}/>) : <i className="mix-empty"/>}
    </div>
    <ul className="mix-legend">{levels.map(level=><li key={level}><Badge severity value={level}/><span>{counts?.[level] || 0}</span></li>)}</ul>
  </Panel>;
}
export function FixCards({rows=[],choose,go}) {
  const groups=new Map();
  for(const row of rows){
    const key=row.tool+'|'+row.rule;
    if(!groups.has(key)) groups.set(key,{row,count:0});
    groups.get(key).count++;
  }
  return <Panel title={t.mustFix} className="fix-panel" action={go&&<IconButton title={t.openFindings} icon={ArrowUpRight} onClick={go}/>}>
    {rows.length ? <div className="fix-grid">{[...groups.values()].slice(0,6).map(({row,count})=><button className="fix-card" key={row.id} onClick={()=>choose(row)}>
      <span className="fix-tool">{label(row.tool)}<ArrowUpRight size={15}/></span>
      <strong>{row.category==='secret' ? row.rule : row.title || row.rule}</strong>
      <span className="fix-file">{location(row)}</span>
      <span className="fix-bottom"><span><b>{count}</b><small>{count===1?t.findingSingular:t.findingPlural}</small></span><Badge severity value={row.severity}/></span>
    </button>)}</div> : <div className="empty-state"><span className="empty-icon"><ShieldCheck/></span><strong>{t.clean}</strong><p>{t.emptyFix}</p></div>}
  </Panel>;
}
export function ProjectField({value,setValue,browse,id='project-folder'}) {
  return <div className="field"><label htmlFor={id}>{t.folder}</label><div className="input-group"><Folder size={17}/><input id={id} value={value} onChange={e=>setValue(e.target.value)} placeholder={t.path} required/><button type="button" className="secondary" onClick={browse}>{t.browse}</button></div></div>;
}
