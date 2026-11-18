"use client";
import {useEffect,useState} from "react";
export type AgentSpan = {trace_id:string;span_id:string;parent_span_id:string|null;agent_ref:string;phase:string;outcome:string;elapsed_us:number;occurred_at:string;received_at:string};
export function AgentTraceLive({initial}: {initial:AgentSpan[]}) {
  const [spans,setSpans]=useState(initial);
  const [feed,setFeed]=useState<"active"|"unavailable">("active");
  useEffect(()=>{
    let stopped=false;
    let busy=false;
    const poll=async()=>{
      if(busy||document.visibilityState!=="visible")return;
      busy=true;
      const controller=new AbortController();
      const timeout=setTimeout(()=>controller.abort(),4000);
      try{
        const r=await fetch("/api/security/ai/agent-traces",{cache:"no-store",headers:{Accept:"application/json"},signal:controller.signal});
        if(!r.ok)throw new Error("Trace API not available");
        const data:unknown=await r.json();
        if(!Array.isArray(data))throw new Error("Invalid trace response");
        if(!stopped){setSpans(data as AgentSpan[]);setFeed("active");}
      }catch{if(!stopped)setFeed("unavailable");}
      finally{clearTimeout(timeout);busy=false;}
    };
    const timer=setInterval(poll,2000);
    return ()=>{stopped=true;clearInterval(timer);controllerSafeNoop();};
    function controllerSafeNoop(){}
  },[]);
  return <section className="panel" aria-label="AI agent execution spans">
    <div className="panel-heading"><div><h2>Agent execution paths</h2>
      <p>Authorized execution metadata polled every two seconds while visible.</p></div>
      <span role="status" className="label-pill">{feed==="active"?"Feed active":"Feed unavailable"}</span></div>
    <p className="info-text">Reported timings are agent-supplied, not verified host overhead. Raw prompts, tool arguments and credentials are never collected.</p>
    {spans.length?<div className="table-wrap"><table><thead><tr>
      <th scope="col">Agent</th><th scope="col">Trace</th><th scope="col">Span / parent</th>
      <th scope="col">Phase</th><th scope="col">Outcome</th><th scope="col">Duration</th><th scope="col">Occurred UTC</th>
    </tr></thead><tbody>{spans.map(x=><tr key={x.span_id}>
      <td>{x.agent_ref}</td><td className="mono">{x.trace_id.slice(0,8)}</td>
      <td className="mono">{x.span_id.slice(0,8)} / {x.parent_span_id?.slice(0,8)||"root"}</td>
      <td>{x.phase}</td><td>{x.outcome}</td><td>{(x.elapsed_us/1000).toFixed(2)} ms</td>
      <td>{new Date(x.occurred_at).toLocaleString("en-GB",{timeZone:"UTC"})}</td>
    </tr>)}</tbody></table></div>
    :<div className="info-text">No instrumented AI agent spans have been reported. An empty feed does not establish safety.</div>}
  </section>;
}
