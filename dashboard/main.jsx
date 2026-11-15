import React,{useEffect,useRef,useState} from 'react';
import {createRoot} from 'react-dom/client';
import {Bell, CircleCheck, Clock3, FileText, ListFilter, Moon, Plus, Search, Settings2, Shield, Star, Sun, X} from 'lucide-react';
import '@fontsource-variable/outfit/wght.css';
import './tokens.css';
import './style.css';
import {t,categories} from './strings';
import {Badge,IconButton,KPI,label,location,safeUrl} from './widgets';
import {Findings,History,Home,Results,Run,Settings,Setup} from './screens';

const pages=['home','setup','run','results','findings','history','settings'];
const titles={home:t.title,setup:t.scanSetup,run:t.runTitle,results:t.results,findings:t.findings,history:t.history,settings:t.settings};
const initialPage=()=>pages.includes(locationHash())?locationHash():'home';
function locationHash(){return window.location.hash.slice(1);}
async function api(path,{method='GET',body}={}){
  const response=await fetch('/api'+path,{method,...(body?{headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{})});
  if(!response.ok){
    const failure=await response.json().catch(()=>null);
    throw new Error(failure?.detail||response.statusText);
  }
  return response.json();
}

function Drawer({finding,close}){
  const dialog=useRef(null);
  useEffect(()=>{
    if(finding&&!dialog.current.open)dialog.current.showModal();
    if(!finding&&dialog.current.open)dialog.current.close();
  },[finding]);
  return <dialog className="drawer" ref={dialog} aria-labelledby="drawer-title" onClose={close}>{finding&&<>
    <div className="panel-head"><span className="muted">{label(finding.tool)}</span><IconButton title={t.closeDetails} icon={X} onClick={close}/></div>
    <h2 id="drawer-title">{finding.category==='secret'?finding.rule:finding.title||finding.rule}</h2>
    <div className="actions"><Badge severity value={finding.severity}/><span>{categories[finding.category]}</span></div>
    <p className="file-cell">{location(finding)}</p>
    {finding.category!=='secret'&&<><p>{finding.description}</p><h3>{t.guidance}</h3><p>{finding.fix||t.none}</p>
      {safeUrl(finding.reference)&&<a href={finding.reference} target="_blank" rel="noreferrer">{t.reference}</a>}</>}
  </>}</dialog>;
}
function App(){
  const [page,setPage]=useState(initialPage),[theme,setTheme]=useState(()=>localStorage.getItem('secscan-theme')||'dark');
  const [solid,setSolid]=useState(()=>localStorage.getItem('secscan-solid')==='true');
  const [state,setState]=useState({history:[],current:null,developer:''}),[project,setProject]=useState('');
  const [selectedRecord,setRecord]=useState(null),[loadedReport,setLoadedReport]=useState(null),[range,setRange]=useState(7);
  const [build,setBuild]=useState(false),[selected,setSelected]=useState(null),[notice,setNotice]=useState('');
  const [starred,setStarred]=useState(false),[historyProject,setHistoryProject]=useState('');
  const [expiry,setExpiry]=useState([]),[showExpiry,setShowExpiry]=useState(false),[searchFocus,setSearchFocus]=useState(false);
  const [starting,setStarting]=useState(false);
  const latestReport=state.history.find(row=>row.report);
  const overviewProject=selectedRecord?.project||latestReport?.project;
  const overviewRecord=state.history.find(row=>row.project===overviewProject&&row.report);
  const record=page==='home'?overviewRecord:selectedRecord||latestReport;
  const report=loadedReport?.id===record?.id?loadedReport?.data:null;
  const search=useRef(null);
  const notify=message=>setNotice(String(message));
  const refresh=()=>api('/state').then(setState);
  function go(next,row){
    if(row)setRecord(row);
    else if(page==='home'&&['results','findings'].includes(next))setRecord(overviewRecord);
    setPage(next);window.location.hash=next;setNotice('');setShowExpiry(false);
  }
  function toggleTheme(){setTheme(theme==='dark'?'light':'dark');}
  useEffect(()=>{document.documentElement.dataset.theme=theme;localStorage.setItem('secscan-theme',theme);},[theme]);
  useEffect(()=>{document.documentElement.dataset.solid=String(solid);localStorage.setItem('secscan-solid',String(solid));},[solid]);
  useEffect(()=>{
    const listener=()=>setPage(initialPage());
    window.addEventListener('hashchange',listener);
    refresh().catch(err=>notify(err.message));
    const timer=setInterval(()=>refresh().catch(()=>{}),900);
    return()=>{clearInterval(timer);window.removeEventListener('hashchange',listener);};
  },[]);
  useEffect(()=>{
    if(!project&&state.history.length){
      setProject((latestReport||state.history[0]).project);
    }
  },[state.history,project]);
  useEffect(()=>{
    let live=true;
    if(record?.report)api('/report/'+record.id).then(data=>{if(live)setLoadedReport({id:record.id,data});}).catch(err=>{if(live)notify(err.message);});
    return()=>{live=false;};
  },[record?.id]);
  const updateExpiry=async()=>{
    if(!project){setExpiry([]);return;}
    try{setExpiry((await api('/settings?project='+encodeURIComponent(project))).expiry||[]);}
    catch{setExpiry([]);}
  };
  const reportPath=record?.project;
  useEffect(()=>{updateExpiry();},[project,reportPath]);
  useEffect(()=>{if(page==='findings'&&searchFocus){search.current?.focus();setSearchFocus(false);}},[page,searchFocus]);
  const previous=useRef(null);
  useEffect(()=>{
    if(previous.current?.active&&state.current&&!state.current.active&&previous.current.id===state.current.id){
      const row=state.history.find(row=>row.id===state.current.id);
      if(row?.report){setRecord(row);setProject(row.project);}
    }
    previous.current=state.current;
  },[state.current,state.history]);

  const projects=[...new Map([...state.history].reverse().map(row=>[row.project,row])).values()].reverse();
  const projectHistory=state.history.filter(row=>row.project===overviewProject);
  async function browse(){try{const result=await api('/picker',{method:'POST'});if(result.project)setProject(result.project);}catch(error){notify(error.message);}}
  async function start(){
    if(starting)return;
    setStarting(true);
    try{const current=await api('/runs',{method:'POST',body:{project,build}});setState(old=>({...old,current}));go('run');}
    catch(error){notify(error.message);}finally{setStarting(false);}
  }
  async function cancel(){try{const current=await api('/cancel',{method:'POST'});setState(old=>({...old,current}));}catch(error){notify(error.message);}}
  async function star(row){try{await api('/star',{method:'POST',body:{project:row.project,starred:!row.starred}});await refresh();}catch(error){notify(error.message);}}
  function open(row){setProject(row.project);go('results',row);}
  function run(path){setProject(path);go('run');}
  const initials=state.developer.trim().slice(0,2).toUpperCase()||'SC';
  const current=state.current;
  return <div className="shell">
    <a className="skip-link" href="#content">{t.skip}</a>
    <header className="topbar">
      <a className="brand" href="#home" onClick={()=>{setStarred(false);go('home');}}><span><Shield size={19} strokeWidth={2.7}/></span>{t.brand}</a>
      <nav className="top-nav" aria-label={t.local}>{pages.map(key=><button key={key} aria-current={page===key?'page':undefined} onClick={()=>{if(key==='home')setStarred(false);go(key);}}>{t[key]}</button>)}</nav>
      <div className="top-actions">
        <div className="notice-anchor"><IconButton title={t.notices} icon={Bell} active={showExpiry} onClick={()=>{updateExpiry();setShowExpiry(!showExpiry);}}/>{expiry.length>0&&<span className="unread"/>}
          {showExpiry&&<aside className="notice-panel panel"><h2>{t.notices}</h2>{expiry.length?<ul className="notes">{expiry.map((item,i)=><li key={i}><span>{item.rule||item.fingerprint}</span><small>{item.expired?t.expired:t.expiring} · {item.expiry}</small></li>)}</ul>:<p className="muted">{t.noNotices}</p>}</aside>}
        </div>
        <div className="avatar" aria-label={state.developer} title={state.developer}>{initials}</div>
      </div>
    </header>
    <aside className="rail" aria-label={t.local}>
      <IconButton title={t.search} icon={Search} onClick={()=>{setSearchFocus(true);go('findings');}}/>
      <IconButton title={t.newScan} icon={Plus} onClick={()=>go('run')}/>
      <IconButton title={t.starred} icon={Star} active={page==='home'&&starred} onClick={()=>{setStarred(!starred);go('home');}}/>
      <IconButton title={t.results} icon={FileText} onClick={()=>go('results')}/>
      <IconButton title={t.history} icon={Clock3} onClick={()=>go('history')}/>
      <hr/>
      <IconButton title={t.settings} icon={Settings2} onClick={()=>go('settings')}/>
      <IconButton title={t.appearance} icon={theme==='dark'?Sun:Moon} onClick={toggleTheme}/>
    </aside>
    <main id="content" tabIndex="-1">
      <div className="page-heading"><h1>{titles[page]}</h1>
        {['home','results','findings'].includes(page)&&<div className="kpis">
          <KPI icon={Shield} name={t.overall}>{report?<Badge value={report.overall_status}/>:t.none}</KPI>
          <KPI icon={ListFilter} name={t.blocking}>{report?.blocking_findings?.length??t.none}</KPI>
          <KPI icon={CircleCheck} name={t.gate}>{report?<Badge value={report.quality_gate.status}/>:t.none}</KPI>
        </div>}
        {page==='home'&&<button className="primary header-run" onClick={()=>go('run')}><Plus size={18}/>{t.newScan}</button>}
      </div>
      {notice&&<div className="toast" role="status"><span>{notice}</span><IconButton title={t.close} icon={X} onClick={()=>setNotice('')}/></div>}
      {page==='home'&&<Home rows={projectHistory} projects={projects} report={report} range={range} setRange={setRange} choose={setSelected} go={go} open={open} star={star} starred={starred} run={run}/>}
      {page==='setup'&&<Setup api={api} notify={notify}/>}
      {page==='run'&&<Run project={project} setProject={setProject} browse={browse} build={build} setBuild={setBuild} start={start} current={current} cancel={cancel} open={job=>{const row=state.history.find(x=>x.id===job.id);if(row)open(row);}}/>}
      {page==='results'&&<Results report={report} record={record} choose={setSelected} go={go}/>}
      {page==='findings'&&<Findings report={report} choose={setSelected} focusSearch={search}/>}
      {page==='history'&&<History rows={state.history} projects={projects} project={historyProject} setProject={setHistoryProject} range={range} setRange={setRange} api={api} open={open} choose={setSelected} notify={notify}/>}
      {page==='settings'&&<Settings api={api} notify={notify} project={project} setProject={setProject} browse={browse} theme={theme} setTheme={toggleTheme} solid={solid} setSolid={setSolid} onSave={updateExpiry}/>}
    </main>
    <Drawer finding={selected} close={()=>setSelected(null)}/>
  </div>;
}

createRoot(document.getElementById('root')).render(<App/>);
