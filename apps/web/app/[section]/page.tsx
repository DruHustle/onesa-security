import {notFound, redirect} from "next/navigation";
import {auth0} from "../../lib/auth0";
import {securityApi} from "../../lib/server-api";
import {sections} from "../../lib/nav";
import {Shell, SectionHeader, EmptyState, Warning} from "../../components/Shell";
import {GuardrailTester} from "../../components/GuardrailTester";
import {AlertAction} from "../../components/AlertAction";
import {FindingAction, ProposalCreator, ProposalDecision} from "../../components/ReviewActions";

type Asset = {id: string; label: string; category: string; os_family: string|null; external_ref: string; last_seen: string};
type Event = {id: string; event_type: string; subject_ref: string; occurred_at: string};
type Alert = {id: string; rule_id: string; title: string; explanation: string; severity: string; status: string; subject_ref: string; event_ids: string[]; assigned_to: string|null; disposition: string|null; created_at: string};
type Finding = {id: string; title: string; category: string; severity: string; asset_ref: string; status: string; cve_id: string|null; evidence_ref: string; source: string; last_seen: string; verified_by: string|null};
type Proposal = {id: string; finding_id: string; action_type: string; action_summary: string; impact_summary: string; rollback_plan: string; requested_by: string; approved_by: string|null; status: string; execution_supported: boolean; created_at: string};
type Readiness = {classification: string; frameworks: string[]; evidence: Record<string,number>; verified_control_count: number; limitations: string};
type AgentSpan = {trace_id:string; span_id:string; parent_span_id:string|null; agent_ref:string; phase:string; outcome:string; elapsed_us:number; occurred_at:string; received_at:string};
type Policy = {version: number; block_injection: boolean; redact_pii: boolean; description: string};

function date(value: string) {const d = new Date(value);return Number.isNaN(d.valueOf()) ? "Unknown" : d.toLocaleString("en-GB", {dateStyle:"medium", timeStyle:"short", timeZone: "UTC"}) + " UTC";}

export default async function SectionPage({params}: {params: Promise<{section: string}>}) {
  const {section} = await params;
  const found = sections.find(x=>x.slug === section);
  if (!found || !section) notFound();
  const session = await auth0.getSession();
  if (!session) redirect("/auth/login");
  const descriptions: Record<string,string> = {
    "ai-security": "Inspect authorized AI content with deterministic guardrails. The evaluation result is not a guarantee of safety.",
    "ai-agent-traces": "Agent execution metadata reported by authorized instrumentation. Refresh to retrieve recent spans; raw arguments and prompts are never retained.",
    "threat-detection": "Real normalized security events from authorized sources. No simulated event counts.",
    "security-operations": "Explainable security alerts, evidence and analyst-driven case status changes.",
    "assets-endpoints": "Read-only inventory of systems actually reported by enrolled collectors.",
    "vulnerabilities": "Source-attributed, collector-reported security findings; never proof of exploitation.",
    "security-upgrades": "Documented mitigation proposals, separation of duties and non-executing approvals.",
    "compliance-reports": "Observed engineering evidence and gaps, not legal compliance or certification.",
  };
  return <Shell active={section} name={session.user.name}><SectionHeader kicker={`${found.group.toUpperCase()} / ${found.live ? "WORKING FOUNDATION" : "PLANNED MODULE"}`} title={found.title} description={descriptions[section] || "This module is part of the Onesa Security roadmap. It is intentionally inactive until it can produce evidence-backed results."}/>
    {!found.live && <><Warning>Not enabled. No claims of protection, integration, compliance or successful remediation are made for this module.</Warning><div className="panel"><EmptyState heading="Module not commissioned" body="Implementation requires validated integration permissions, product authorization and independent acceptance tests. Current data is not simulated."/></div></>}
    {section === "ai-security" && <AIPage/>}
    {section === "ai-agent-traces" && <AgentTracesPage/>}
    {section === "threat-detection" && <ThreatPage/>}
    {section === "security-operations" && <OperationsPage/>}
    {section === "assets-endpoints" && <AssetsPage/>}
    {section === "vulnerabilities" && <FindingsPage/>}
    {section === "security-upgrades" && <UpgradesPage subject={session.user.sub || ""}/>}
    {section === "compliance-reports" && <CompliancePage/>}
  </Shell>;
}

async function AIPage() {
  const response = await securityApi<Policy>("/v1/ai/policy");
  return <><Warning>Limited deterministic checks: known injection patterns, credential patterns, email masking and unconditional tool-execution denial. Indirect injection, multimodal and comprehensive RAG defenses are not yet qualified.</Warning>
    <div className="panel-grid"><div className="panel"><div className="panel-heading"><div><h2>Guardrail policy</h2><p>Effective settings for the selected organization.</p></div></div>{response.ok ? <div className="info-list"><div><strong>Policy version</strong><span>{response.data.version || "Default"}</span></div><div><strong>Injection heuristics</strong><span>{response.data.block_injection ? "Enabled" : "Disabled by policy"}</span></div><div><strong>Email redaction</strong><span>{response.data.redact_pii ? "Enabled" : "Disabled by policy"}</span></div><div><strong>Tool execution</strong><span>Blocked by this foundation release</span></div></div> : <Warning>{response.error}</Warning>}</div>
    <div className="panel"><div className="panel-heading"><div><h2>Gateway capabilities</h2><p>Declared deployment boundaries.</p></div></div><div className="info-list"><div><strong>Content inspection</strong><span>Enabled for authorized users</span></div><div><strong>Provider request proxy</strong><span>Requires explicit approved provider configuration</span></div><div><strong>Streaming and tool execution</strong><span>Not implemented</span></div><div><strong>Guarantee of complete blocking</strong><span>Not claimed</span></div></div></div></div>
    <GuardrailTester/>
  </>;
}

async function ThreatPage() {
  const response = await securityApi<Event[]>("/v1/events");
  if (!response.ok) return <Warning>{response.error}</Warning>;
  return <section className="panel"><div className="panel-heading"><div><h2>Event stream</h2><p>Most recent 100 persisted normalized events. Refresh to retrieve new records.</p></div><span className="label-pill">{response.data.length} events shown</span></div>
    {response.data.length ? <div className="table-wrap"><table><thead><tr><th scope="col">Event type</th><th scope="col">Subject reference</th><th scope="col">Occurred</th><th scope="col">Event ID</th></tr></thead><tbody>{response.data.map(e=><tr key={e.id}><td><span className="type-label">{e.event_type}</span></td><td>{e.subject_ref}</td><td>{date(e.occurred_at)}</td><td className="mono">{e.id.slice(0,8)}…</td></tr>)}</tbody></table></div> : <EmptyState heading="No events collected" body="Only verified collector ingestions appear here. A blank stream does not mean an environment is protected."/>}</section>;
}

async function OperationsPage() {
  const response = await securityApi<Alert[]>("/v1/alerts");
  if (!response.ok) return <Warning>{response.error}</Warning>;
  return <section className="panel"><div className="panel-heading"><div><h2>Investigation queue</h2><p>Events create explainable alerts based on versioned detection logic.</p></div><span className="label-pill">{response.data.length} alerts shown</span></div>
    {response.data.length ? <div className="case-list">{response.data.map(a=><article className="case" key={a.id}><div className="case-info"><div className="case-tags"><span className={`severity ${a.severity}`}>{a.severity.toUpperCase()}</span><span className="type-label">{a.rule_id}</span><span className="status-tag">{a.status}</span></div><h3>{a.title}</h3><p>{a.explanation}</p><div className="case-meta"><span>Subject: {a.subject_ref}</span><span>{date(a.created_at)}</span><span>{a.event_ids.length} evidence event(s)</span></div>{a.disposition && <p className="disposition"><strong>Disposition:</strong> {a.disposition}</p>}</div><AlertAction id={a.id} status={a.status}/></article>)}</div> : <EmptyState heading="No detection alerts" body="New rule hits from real events will appear in this queue. An empty queue is not evidence that no threats exist."/>}</section>;
}

async function AssetsPage() {
  const response = await securityApi<Asset[]>("/v1/assets");
  if (!response.ok) return <Warning>{response.error}</Warning>;
  return <section className="panel"><div className="panel-heading"><div><h2>Authorized asset inventory</h2><p>Latest 100 records, reported by a tenant-scoped collector.</p></div><span className="label-pill">{response.data.length} assets shown</span></div>
    {response.data.length ? <div className="table-wrap"><table><thead><tr><th scope="col">Asset</th><th scope="col">Category</th><th scope="col">Operating system</th><th scope="col">Last reported</th></tr></thead><tbody>{response.data.map(a=><tr key={a.id}><td><strong>{a.label}</strong><small className="table-sub">{a.external_ref}</small></td><td>{a.category}</td><td>{a.os_family || "Unknown"}</td><td>{date(a.last_seen)}</td></tr>)}</tbody></table></div> : <EmptyState heading="No enrolled assets" body="This is an empty real inventory. Install and authorize the development collector to report a Linux host; production agent requirements remain open."/>}</section>;
}


async function FindingsPage() {
  const response = await securityApi<Finding[]>("/v1/findings");
  if (!response.ok) return <Warning>{response.error}</Warning>;
  return <><Warning>Only reports from enrolled collectors appear here. A finding is not evidence of exploitation, confirmed CVE applicability, or proof that any asset is protected.</Warning>
    <section className="panel"><div className="panel-heading"><div><h2>Exposure and vulnerability review</h2><p>Most recent 100 source-attributed records.</p></div><span className="label-pill">{response.data.length} findings</span></div>
    {response.data.length ? <div className="case-list">{response.data.map(f=><article className="case" key={f.id}><div className="case-info"><div className="case-tags"><span className={`severity ${f.severity}`}>{f.severity.toUpperCase()}</span><span className="type-label">{f.category}</span><span className="status-tag">{f.status.replaceAll("_", " ")}</span></div><h3>{f.title}</h3><div className="case-meta"><span>Asset {f.asset_ref}</span><span>{f.cve_id || "No CVE claim"}</span><span>Evidence {f.evidence_ref}</span><span>{date(f.last_seen)}</span></div><small>{f.source}</small></div><FindingAction id={f.id}/></article>)}</div>
    : <EmptyState heading="No reported weaknesses" body="Enrolled collectors must report real asset-scoped findings before the review queue is populated."/>}</section></>;
}

async function UpgradesPage({subject}: {subject: string}) {
  const [findings, proposals] = await Promise.all([securityApi<Finding[]>("/v1/findings"), securityApi<Proposal[]>("/v1/remediation-proposals")]);
  if (!findings.ok || !proposals.ok) return <Warning>{!findings.ok ? findings.error : !proposals.ok ? proposals.error : "Unavailable"}</Warning>;
  return <><Warning>Remediation execution is disabled. Approving a proposal does not patch machines, change firewalls, rotate production credentials or alter industrial control systems.</Warning>
    <ProposalCreator findings={findings.data.filter(f=>f.status === "reported").map(f=>({id:f.id,title:f.title}))}/>
    <section className="panel"><div className="panel-heading"><div><h2>Reviewed change queue</h2><p>Two-person approvals and auditable planning only.</p></div><span className="label-pill">{proposals.data.length} proposals</span></div>
    {proposals.data.length ? <div className="case-list">{proposals.data.map(p=><article className="case" key={p.id}><div className="case-info"><div className="case-tags"><span className="type-label">{p.action_type.replaceAll("_"," ")}</span><span className="status-tag">{p.status}</span></div><h3>{p.action_summary}</h3><p><strong>Impact:</strong> {p.impact_summary}</p><p><strong>Rollback:</strong> {p.rollback_plan}</p><div className="case-meta"><span>Requested by {p.requested_by}</span><span>{date(p.created_at)}</span></div><small>No remote command execution</small></div><ProposalDecision id={p.id} status={p.status} ownRequest={p.requested_by === subject}/></article>)}</div>
    : <EmptyState heading="No upgrade plans" body="Create a documented proposal linked to a reported finding. A different owner must review it."/>}</section></>;
}

async function CompliancePage() {
  const response = await securityApi<Readiness>("/v1/compliance/readiness");
  if (!response.ok) return <Warning>{response.error}</Warning>;
  return <><Warning>{response.data.classification}. {response.data.limitations}</Warning><section className="panel"><div className="panel-heading"><div><h2>Technical evidence register</h2><p>These are source counts only, not control-effectiveness assessments.</p></div></div>
  <div className="info-list">{Object.entries(response.data.evidence).map(([key,value])=><div key={key}><strong>{key.replaceAll("_"," ")}</strong><span>{value}</span></div>)}<div><strong>Verified controls</strong><span>{response.data.verified_control_count} — not audited</span></div></div>
  <h3>Frameworks to assess</h3><p>{response.data.frameworks.join(" · ")}</p><p className="info-text">An independent assessment and documented evidence mapping are required before making any compliance statements.</p></section></>;
}


async function AgentTracesPage() {
  const response = await securityApi<AgentSpan[]>("/v1/ai/agent-traces");
  if (!response.ok) return <Warning>{response.error}</Warning>;
  return <section className="panel">
    <div className="panel-heading"><div><h2>Agent execution paths</h2>
      <p>Metadata-only trace view. Reload to fetch up to 100 most recent spans; this is not a continuous live stream.</p></div>
      <span className="label-pill">{response.data.length} spans</span></div>
    {response.data.length ? <div className="table-wrap"><table>
      <thead><tr><th>Agent</th><th>Trace</th><th>Span / parent</th><th>Phase</th><th>Outcome</th><th>Duration</th><th>Reported</th></tr></thead>
      <tbody>{response.data.map(x=><tr key={x.span_id}>
      <td>{x.agent_ref}</td><td className="mono">{x.trace_id.slice(0,8)}</td>
      <td className="mono">{x.span_id.slice(0,8)} / {x.parent_span_id?.slice(0,8) || "root"}</td>
      <td>{x.phase}</td><td>{x.outcome}</td><td>{(x.elapsed_us / 1000).toFixed(2)} ms</td>
      <td>{date(x.occurred_at)}</td></tr>)}</tbody></table></div>
      : <EmptyState heading="No agent execution spans" body="Only instrumented agents authorized for this organization are represented. Absence of traces does not prove agent safety."/>}
  </section>;
}
