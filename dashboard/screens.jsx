import React,{useEffect,useState} from 'react';
import {Activity, ArrowUpRight, Download, Folder, Play, RefreshCw, Shield, Star, X} from 'lucide-react';
import {t, tools, levels, categories} from './strings';
import {Badge, FixCards, IconButton, Panel, ProjectField, SeverityMix, ToolGauge, Trend, label, location, safeUrl, sum, time} from './widgets';

export function Home({rows,projects,report,range,setRange,choose,go,open,star,starred,run}) {
  const recent=starred?projects.filter(row=>row.starred):projects;
  return <div className="overview">
    <div className="overview-left">
      <Trend rows={rows} range={range} setRange={setRange}/>
      <div className="mini-grid"><ToolGauge report={report}/><SeverityMix counts={report?.severity_counts}/></div>
    </div>
    <FixCards rows={report?.blocking_findings} choose={choose} go={()=>go('findings')}/>
    <Panel title={starred?t.starred:t.projects} className="projects" action={<button className="secondary" onClick={()=>go('run')}><Play size={15}/>{t.newScan}</button>}>
      {!recent.length?<p className="muted">{starred?t.starredEmpty:t.noProjects}</p>:<ul className="project-list">{recent.map(row=><li key={row.project}>
        <Folder size={20} className="project-icon"/><span className="grow"><button className="text-button" onClick={()=>open(row)}>{row.name}</button><small className="muted project-path">{row.project}</small></span>
        <time className="muted">{time(row.started)}</time><Badge value={row.status}/>
        <IconButton icon={Star} title={row.starred?t.unstar:t.star} active={!!row.starred} onClick={()=>star(row)}/>
        <button className="secondary" onClick={()=>run(row.project)}>{t.rerun}</button>
      </li>)}</ul>}
    </Panel>
  </div>;
}

export function Setup({api,notify}) {
  const [setup,setSetup]=useState(null),[busy,setBusy]=useState(false);
  async function refresh(){
    setBusy(true);
    try{setSetup(await api('/setup'));}catch(error){notify(error.message);}finally{setBusy(false);}
  }
  useEffect(()=>{refresh();},[]);
  return <div className="screen-grid">
    <Panel title={t.scanSetup} action={<button className="secondary" onClick={refresh} disabled={busy}><RefreshCw size={16}/>{t.refresh}</button>}>
      {!setup?<p aria-live="polite" className="muted">{busy?t.checking:t.noData}</p>:<ul className="setup-list">{Object.entries(setup.checks).map(([key,row])=><li key={key}>
        <div><strong>{label(key)}</strong><Badge value={row.status}/></div><p className="muted">{t.version} {row.version||t.none}{row.reason?' · '+row.reason:''}</p>
        <small className="muted">{t.install}</small><code>{row.install}</code>
      </li>)}</ul>}
    </Panel>
    <Panel title={t.connection}><p><Badge value={setup?.token_set?'OK':'MISSING'}/> {setup?.token_set?t.tokenSet:t.tokenUnset}</p>
      <button className="primary" onClick={()=>api('/connection',{method:'POST'}).then(()=>{notify(t.connected);refresh();}).catch(error=>notify(error.message))}><Activity size={16}/>{t.test}</button>
    </Panel>
  </div>;
}

export function Run({project,setProject,browse,build,setBuild,start,current,cancel,open}) {
  const active=current?.active;
  return <div className="screen-grid">
    <Panel title={t.runTitle}>
      <form onSubmit={e=>{e.preventDefault();start();}}>
        <ProjectField value={project} setValue={setProject} browse={browse}/>
        <label className="check"><input type="checkbox" checked={build} disabled={active} onChange={e=>setBuild(e.target.checked)}/>{t.build}</label>
        <p className="muted small">{t.enableBuild}</p>
        <div className="actions"><button className="primary" disabled={active}><Play size={17}/>{t.start}</button>
          {active&&<button type="button" className="secondary danger" disabled={current.status==='CANCELLING'} onClick={cancel}>{t.cancel}</button>}
          {current&&!active&&!['CANCELLED','ERROR'].includes(current.status)&&<button type="button" className="secondary" onClick={()=>open(current)}>{t.report}</button>}</div>
      </form>
    </Panel>
    <Panel title={t.progress} action={current&&<Badge value={current.status}/>}>
      <div className="progress-list" aria-live="polite">{Object.keys(tools).map(key=>{
        const events=current?.events?.filter(event=>event.tool===key)||[];
        const event=events.at(-1);
        return <div key={key}><Shield size={17}/><span><strong>{label(key)}</strong>{event?.reason&&<small>{event.reason}</small>}</span><Badge value={event?.status||(event?'RUNNING':current?.status==='CANCELLED'?'CANCELLED':'PENDING')}/></div>;
      })}</div>
    </Panel>
    <Panel title={t.log} className="wide"><pre className="activity" tabIndex="0">{current?.log?.length?current.log.join('\n'):t.noLog}</pre></Panel>
  </div>;
}

export function Results({report,record,choose,go}) {
  if(!report)return <Panel title={t.results}><p className="muted">{t.noData}</p></Panel>;
  const sonar=safeUrl(report.sonar_dashboard_url);
  return <div className="screen-grid">
    <Panel title={report.project_name} action={<Badge value={report.overall_status}/>}>
      <dl className="facts"><dt>{t.time}</dt><dd>{time(report.started_at)}</dd><dt>{t.commit}</dt><dd>{report.git?.commit||t.noCommit}</dd></dl>
      <div className="actions" aria-label={t.export}>{['html','md','json'].map(format=><a key={format} className="secondary" href={'/api/export/'+record.id+'/'+format}><Download size={15}/>{format==='md'?'Markdown':format.toUpperCase()}</a>)}</div>
    </Panel>
    <Panel title={t.gate} action={<Badge value={report.quality_gate.status}/>}>
      {sonar&&<a className="secondary" href={sonar} target="_blank" rel="noreferrer">{t.dashboard}<ArrowUpRight size={15}/></a>}
      <h3>{t.gateConditions}</h3>{report.quality_gate.conditions.length?<div className="table-wrap"><table><thead><tr>{[t.metric,t.status,t.actual,t.limit].map(item=><th key={item}>{item}</th>)}</tr></thead><tbody>{report.quality_gate.conditions.map(row=><tr key={row.metricKey}><td>{row.metricKey}</td><td><Badge value={row.status}/></td><td>{row.actualValue}</td><td>{row.errorThreshold}</td></tr>)}</tbody></table></div>:<p className="muted">{t.noGateConditions}</p>}
    </Panel>
    <Panel title={t.progress}><div className="progress-list">{Object.entries(report.tools).map(([key,row])=><div key={key}><Shield size={17}/><span><strong>{label(key)}</strong><small>{row.reason||sum(row.counts)+' '+t.total}</small></span><Badge value={row.status}/></div>)}</div></Panel>
    <SeverityMix counts={report.severity_counts}/>
    <FixCards rows={report.blocking_findings} choose={choose} go={()=>go('findings')}/>
    <Panel title={t.warnings}><ul className="notes">{report.coverage_notes.map(note=><li key={note}>{note}</li>)}</ul></Panel>
  </div>;
}

export function Findings({report,choose,focusSearch}) {
  const [filter,setFilter]=useState({tool:'',severity:'',category:'',file:'',text:''});
  const change=key=>e=>setFilter({...filter,[key]:e.target.value});
  const includes=(value,query)=>String(value||'').toLowerCase().includes(query.trim().toLowerCase());
  const rows=(report?.findings||[]).filter(row=>
    ['tool','severity','category'].every(key=>!filter[key]||row[key]===filter[key])&&includes(row.file,filter.file)&&
    includes([row.rule,row.title,row.description].filter(Boolean).join(' '),filter.text));
  const dropdown=(key,items,title)=> <label className="field compact">{t[key]}<select value={filter[key]} onChange={change(key)}><option value="">{title}</option>{items.map(([value,text])=><option key={value} value={value}>{text}</option>)}</select></label>;
  return <Panel title={t.findings} action={<span className="muted">{rows.length} {t.total}</span>}>
    <div className="filters">{dropdown('tool',Object.entries(tools),t.allTools)}{dropdown('severity',levels.map(x=>[x,x]),t.allSeverities)}
      {dropdown('category',Object.entries(categories),t.allCategories)}<label className="field compact">{t.file}<input placeholder={t.filterFile} value={filter.file} onChange={change('file')}/></label>
      <label className="field compact search-field">{t.search}<input ref={focusSearch} type="search" placeholder={t.keyboardSearch} value={filter.text} onChange={change('text')}/></label></div>
    {!report?<p className="muted">{t.noData}</p>:!rows.length?<p className="muted">{t.noMatches}</p>:<div className="table-wrap"><table><thead><tr>{[t.rule,t.tool,t.severity,t.category,t.file,t.status].map(item=><th key={item}>{item}</th>)}</tr></thead>
      <tbody>{rows.map(row=><tr key={row.id}><td><button className="text-button" onClick={()=>choose(row)}>{row.category==='secret'?row.rule:row.title||row.rule}</button></td><td>{label(row.tool)}</td><td><Badge severity value={row.severity}/></td><td>{categories[row.category]}</td><td className="file-cell">{location(row)}</td><td>{row.allowlisted?t.exception:row.blocking?t.blocked:t.advisory}</td></tr>)}</tbody></table></div>}
  </Panel>;
}

export function History({rows,projects,project,setProject,range,setRange,api,open,choose,notify}) {
  const [before,setBefore]=useState(''),[after,setAfter]=useState(''),[comparison,setComparison]=useState(null);
  const visible=rows.filter(row=>!project||row.project===project);
  const completed=visible.filter(row=>row.report);
  useEffect(()=>{setBefore(completed[1]?.id||'');setAfter(completed[0]?.id||'');setComparison(null);},[project,completed[0]?.id,completed[1]?.id]);
  async function compare(){
    try{
      const [a,b]=await Promise.all([api('/report/'+before),api('/report/'+after)]);
      const left=new Set(a.findings.map(row=>row.id)), right=new Set(b.findings.map(row=>row.id));
      setComparison({new:b.findings.filter(row=>!left.has(row.id)),fixed:a.findings.filter(row=>!right.has(row.id)),
        unchanged:b.findings.filter(row=>left.has(row.id))});
    }catch(error){notify(error.message);}
  }
  const canCompare=before&&after&&before!==after&&completed.find(r=>r.id===before)?.project===completed.find(r=>r.id===after)?.project;
  return <div className="screen-grid">
    <Trend rows={visible} range={range} setRange={setRange}/>
    <Panel title={t.compare}><p className="muted">{t.compareHint}</p>
      {[['before',before,setBefore],['after',after,setAfter]].map(([key,value,apply])=><label className="field" key={key}>{t[key]}<select value={value} onChange={e=>{apply(e.target.value);setComparison(null);}}><option value="">{t.select}</option>{completed.map(row=><option value={row.id} key={row.id}>{row.name} · {time(row.started)}</option>)}</select></label>)}
      <button className="primary" disabled={!canCompare} onClick={compare}>{t.compare}</button>
    </Panel>
    {comparison&&<Panel title={t.compare} className="wide"><div className="compare-grid">{Object.entries(comparison).map(([key,items])=><section key={key}><h3>{t[key]} · {items.length}</h3>
      {items.length?<ul className="notes">{items.map(row=><li key={row.id}><button className="text-button" onClick={()=>choose(row)}>{row.rule}</button><small className="muted">{location(row)}</small></li>)}</ul>:<p className="muted">{t.noCompare}</p>}</section>)}</div></Panel>}
    <Panel title={t.scanHistory} className="wide" action={<select aria-label={t.projectFilter} value={project} onChange={e=>setProject(e.target.value)}><option value="">{t.allProjects}</option>{projects.map(row=><option key={row.project} value={row.project}>{row.name}</option>)}</select>}>
      {visible.length?<div className="table-wrap"><table><thead><tr>{[t.projects,t.time,t.status,t.blocking,t.report].map(item=><th key={item}>{item}</th>)}</tr></thead>
        <tbody>{visible.map(row=><tr key={row.id}><td>{row.name}</td><td>{time(row.started)}</td><td><Badge value={row.status}/></td><td>{row.blocking}</td><td>{row.report?<button className="text-button" onClick={()=>open(row)}>{t.report}</button>:t.none}</td></tr>)}</tbody></table></div>:<p className="muted">{t.noHistory}</p>}
    </Panel>
  </div>;
}

const blankException={tool:'semgrep',rule:'',fingerprint:'',file:'',reason:'',approver:'',expiry:''};
export function Settings({api,notify,project,setProject,browse,theme,setTheme,solid,setSolid,onSave}) {
  const [profile,setProfile]=useState(null),[token,setToken]=useState(''),[exclusions,setExclusions]=useState(''),[entries,setEntries]=useState([]),[loaded,setLoaded]=useState('');
  async function load(target=''){
    try {
      const data=await api('/settings'+(target?'?project='+encodeURIComponent(target):''));
      setProfile(old=>({...old,...data}));
      if(target){setLoaded(target);setExclusions((data.exclusions||[]).join('\n'));setEntries(data.allowlist||[]);}
    } catch(error){notify(error.message);}
  }
  useEffect(()=>{load(project);},[]);
  const save=async (path,body,message)=>{
    try{await api(path,{method:'PUT',body});notify(message);onSave();return true;}
    catch(error){notify(error.message);return false;}
  };
  if(!profile)return <Panel title={t.settings}><p className="muted">{t.loading}</p></Panel>;
  return <div className="screen-grid">
    <Panel title={t.connection}>
      <form onSubmit={async e=>{e.preventDefault();if(await save('/settings',{sonar_url:profile.sonar_url,retention:Number(profile.retention),...(token?{token}:{})},t.saved)){setToken('');load(loaded);}}}>
        <label className="field">{t.sonarUrl}<input type="url" value={profile.sonar_url} placeholder={t.sonarExample} onChange={e=>setProfile({...profile,sonar_url:e.target.value})}/></label>
        <p className="small muted">{t.activeUrl} · {profile.effective_url||t.none}</p>
        <label className="field">{t.token}<input type="password" autoComplete="off" value={token} onChange={e=>setToken(e.target.value)} /></label>
        <p className="small muted">{profile.token_set?t.tokenSet:t.tokenUnset} · {t.tokenHint}</p>
        <label className="field">{t.retention}<input type="number" min="2" max="500" required value={profile.retention} onChange={e=>setProfile({...profile,retention:e.target.value})}/></label>
        <label className="check"><input type="checkbox" checked={solid} onChange={event=>setSolid(event.target.checked)}/>{t.solid}</label>
        <div className="actions"><button className="primary">{t.save}</button><button type="button" aria-pressed={theme==='light'} className="secondary" onClick={setTheme}>{t.appearance}</button></div>
      </form>
    </Panel>
    <Panel title={t.readonly} action={<span className="muted small">{t.policy}</span>}>
      <ul className="notes policy">{Object.entries(profile.thresholds.blocking).map(([tool,rules])=><li key={tool}><strong>{label(tool)}</strong><span>{Object.entries(rules).map(([key,value])=>key+' · '+(Array.isArray(value)?value.join(', '):typeof value==='object'?value.severities.join(', ')+' ('+value.requires_fix.join(', ')+' requires fix)':value)).join(' / ')}</span></li>)}</ul>
      <details><summary>{t.mapping}</summary><div className="table-wrap"><table><thead><tr>{[t.tool,t.sourceSeverity,t.unifiedSeverity].map(item=><th key={item}>{item}</th>)}</tr></thead><tbody>{Object.entries(profile.severity).flatMap(([tool,values])=>Object.entries(values).map(([key,value])=><tr key={tool+key}><td>{label(tool)}</td><td>{key}</td><td><Badge severity value={value}/></td></tr>))}</tbody></table></div></details>
    </Panel>
    <Panel title={t.projectConfig} className="wide">
      <form onSubmit={e=>{e.preventDefault();load(project);}}><ProjectField id="settings-folder" value={project} setValue={setProject} browse={browse}/><button className="secondary">{t.loadProject}</button></form>
      {loaded&&loaded===project&&<form className="project-form" onSubmit={async e=>{e.preventDefault();if(await save('/project',{project,exclusions:exclusions.split('\n').map(x=>x.trim()).filter(Boolean),allowlist:entries},t.projectSaved))load(project);}}>
        <label className="field">{t.excludes}<textarea rows="3" value={exclusions} onChange={e=>setExclusions(e.target.value)}/></label>
        <h3>{t.allowlist}</h3><p className="muted">{t.allowlistHelp}</p>
        {entries.map((entry,index)=>{
          function set(key,value){setEntries(entries.map((row,i)=>i===index?{...row,[key]:value}:row));}
          return <fieldset key={index} className="exception"><legend>{t.exception} {index+1}</legend>
            <label className="field">{t.tool}<select value={entry.tool} onChange={e=>set('tool',e.target.value)}>{Object.entries(tools).map(([key,title])=><option value={key} key={key}>{title}</option>)}</select></label>
            {['rule','fingerprint','file','reason','approver','expiry'].map(key=><label key={key} className="field">{key==='file'?t.filePattern:t[key]}<input type={key==='expiry'?'date':'text'} value={entry[key]||''} required={['file','reason','approver','expiry'].includes(key)||(key==='fingerprint'&&entry.tool==='gitleaks')} onChange={e=>set(key,e.target.value)}/></label>)}
            <button type="button" className="secondary" onClick={()=>setEntries(entries.filter((_,i)=>i!==index))}><X size={15}/>{t.remove}</button>
          </fieldset>;
        })}
        <div className="actions"><button type="button" className="secondary" onClick={()=>setEntries([...entries,{...blankException}])}>{t.add}</button><button className="primary">{t.saveProject}</button></div>
      </form>}
    </Panel>
  </div>;
}
