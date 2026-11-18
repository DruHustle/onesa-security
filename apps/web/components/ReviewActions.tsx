"use client";
import {useState} from "react";
import {useRouter} from "next/navigation";

export function FindingAction({id}: {id: string}) {
  const router = useRouter();
  const [verification,setVerification] = useState("false_positive");
  const [evidence,setEvidence] = useState("");
  const [note,setNote] = useState("");
  const [error,setError] = useState("");
  const [busy,setBusy] = useState(false);
  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault(); setBusy(true); setError("");
    try {
      const res = await fetch(`/api/security/findings/${id}/resolve`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({verification,evidence_ref:evidence,note})});
      if (!res.ok) {setError("Analyst permission, evidence or verification missing");return;}
      router.refresh();setEvidence("");setNote("");
    } catch {setError("Security API unavailable");} finally {setBusy(false);}
  }
  return <form className="alert-action" onSubmit={submit}>
    <label htmlFor={`review-${id}`} className="micro">Analyst review</label><select id={`review-${id}`} value={verification} onChange={e=>setVerification(e.target.value)}>
      <option value="false_positive">False positive</option><option value="accepted_risk">Risk accepted (requires organizational review)</option><option value="verified_resolved">Resolved — independent evidence required</option>
    </select>
    <label htmlFor={`evidence-${id}`} className="micro">Evidence reference</label><input id={`evidence-${id}`} value={evidence} onChange={e=>setEvidence(e.target.value)} required minLength={8} maxLength={120} pattern="[A-Za-z0-9_.:-]+" placeholder="approved-review-0001" />
    <label htmlFor={`f-note-${id}`} className="micro">Review note</label><input id={`f-note-${id}`} value={note} onChange={e=>setNote(e.target.value)} required minLength={15} maxLength={300} placeholder="Describe verified evidence" />
    <button disabled={busy || evidence.length < 8 || note.length < 15} type="submit">Record review</button>
    {error && <p role="alert" className="form-error">{error}</p>}
  </form>;
}

export function ProposalCreator({findings}: {findings: {id: string;title:string}[]}) {
  const router = useRouter();
  const [findingId,setFindingId] = useState(findings[0]?.id || "");
  const [action,setAction] = useState("configuration_hardening");
  const [summary,setSummary] = useState("");
  const [impact,setImpact] = useState("");
  const [rollback,setRollback] = useState("");
  const [busy,setBusy] = useState(false);
  const [error,setError] = useState("");
  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();setBusy(true);setError("");
    try {
      const res = await fetch("/api/security/remediation-proposals",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({finding_id:findingId,action_type:action,action_summary:summary,impact_summary:impact,rollback_plan:rollback,dry_run:true})});
      if (!res.ok) {setError("A valid finding, analyst permission and complete plan are required");return;}
      setSummary("");setImpact("");setRollback("");router.refresh();
    } catch {setError("Security API unavailable");} finally {setBusy(false);}
  }
  return <section className="panel"><div className="panel-heading"><div><h2>Propose a security change</h2><p>Reviewable plan only. No execution credentials are accepted.</p></div><span className="label-pill">DRY RUN</span></div>
    {findings.length ? <form className="test-form" onSubmit={submit}>
      <label htmlFor="proposal-finding">Reported finding</label><select id="proposal-finding" value={findingId} onChange={e=>setFindingId(e.target.value)}>{findings.map(f=><option key={f.id} value={f.id}>{f.title}</option>)}</select>
      <label htmlFor="proposal-action">Proposed action</label><select id="proposal-action" value={action} onChange={e=>setAction(e.target.value)}><option value="patch_plan">Patch plan</option><option value="configuration_hardening">Configuration hardening</option><option value="credential_rotation">Credential rotation</option><option value="firewall_review">Firewall review</option></select>
      <label htmlFor="proposal-summary">What would change</label><textarea id="proposal-summary" minLength={15} maxLength={500} rows={2} value={summary} onChange={e=>setSummary(e.target.value)} required/>
      <label htmlFor="proposal-impact">Impact and maintenance procedure</label><textarea id="proposal-impact" minLength={15} maxLength={500} rows={2} value={impact} onChange={e=>setImpact(e.target.value)} required/>
      <label htmlFor="proposal-rollback">Rollback / recovery plan</label><textarea id="proposal-rollback" minLength={15} maxLength={500} rows={2} value={rollback} onChange={e=>setRollback(e.target.value)} required/>
      <button disabled={busy} type="submit">Submit for independent owner review</button>{error && <p role="alert" className="form-error">{error}</p>}
    </form> : <p>No reported findings available for a change proposal.</p>}
  </section>;
}

export function ProposalDecision({id,status,ownRequest}: {id:string;status:string;ownRequest:boolean}) {
  const router = useRouter();const [note,setNote] = useState("");const [busy,setBusy] = useState(false);const [error,setError] = useState("");
  async function decide(decision:"approve"|"reject") {
    setBusy(true);setError("");
    try {
      const r=await fetch(`/api/security/remediation-proposals/${id}/decision`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({decision,note})});
      if (!r.ok) {setError("Separate organization owner approval required");return;}
      setNote("");router.refresh();
    } catch {setError("Security API unavailable");} finally {setBusy(false);}
  }
  if(status!=="pending") return <small>Decision recorded; execution still disabled</small>;
  if(ownRequest) return <small>A different organization owner must review this request.</small>;
  return <div className="alert-action"><label className="micro" htmlFor={`decision-${id}`}>Independent owner decision note</label><input id={`decision-${id}`} value={note} onChange={e=>setNote(e.target.value)} minLength={15} maxLength={300} placeholder="Document evidence and approval scope"/><div className="button-pair"><button type="button" disabled={busy || note.length < 15} onClick={()=>decide("approve")}>Approve plan</button><button type="button" className="secondary" disabled={busy || note.length < 15} onClick={()=>decide("reject")}>Reject</button></div>{error && <p role="alert" className="form-error">{error}</p>}</div>;
}
