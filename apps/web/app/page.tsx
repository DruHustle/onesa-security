import {auth0} from "../lib/auth0";
import {securityApi} from "../lib/server-api";
import {Shell, SectionHeader, WorkspaceAccess, EmptyState} from "../components/Shell";
import {SecurityWelcome} from "../components/SecurityWelcome";

interface Summary {organization_id: string; role: string; assets: number; events: number; alerts: number; collectors: number; findings: number; remediation_proposals: number; real_data: boolean; source: string}

export default async function Overview() {
  const session = await auth0.getSession();
  if (!session) return <SecurityWelcome/>;
  const response = await securityApi<Summary>("/v1/overview");
  if (!response.ok) return <WorkspaceAccess message={response.error}/>;
  const cards = [
    {name: "Managed assets", value: response.data.assets, text: "Reporting through enrolled collectors"},
    {name: "Security events", value: response.data.events, text: "Persisted normalized events"},
    {name: "Detection alerts", value: response.data.alerts, text: "Explainable rule-based findings"},
    {name: "Collectors", value: response.data.collectors, text: "Registered collection identities"},
    {name: "Reported findings", value: response.data.findings, text: "Not confirmed exploitation"},
    {name: "Remediation proposals", value: response.data.remediation_proposals, text: "Planning and approvals; execution disabled"},
  ];
  return <Shell active="" name={session.user.name} role={response.data.role}><SectionHeader kicker="SECURITY OVERVIEW / FOUNDATION" title="Security command center" description="Organization-scoped defensive operations backed by authorized sources. No synthetic findings or fabricated threat scores."/>
    <div className="header-trailing"><span className="data-chip"><span className="status-dot"/> Live database view</span><span>Role: {response.data.role}</span></div>
      <div className="stats">{cards.map(card=><article className="metric" key={card.name}><p>{card.name}</p><strong>{card.value.toLocaleString("en")}</strong><span>{card.text}</span></article>)}</div>
      <div className="panel-grid"><section className="panel"><div className="panel-heading"><div><h2>Collection coverage</h2><p>Visibility only into systems that report to this tenant.</p></div></div>{response.data.assets === 0 ? <EmptyState heading="No endpoints are reporting" body="Enroll an authorized collector using the API before counting an asset as monitored."/> : <p className="info-text">{response.data.assets} inventory records are stored. This does not establish continuous endpoint protection.</p>}</section>
      <section className="panel"><div className="panel-heading"><div><h2>Response posture</h2><p>Incidents must be triaged based on evidence.</p></div></div><div className="info-list"><div><strong>AI guardrails</strong><span>Deterministic baseline inspection</span></div><div><strong>Threat detection</strong><span>Version 1 rules for sign-in failures and privileged changes</span></div><div><strong>Remediation</strong><span>Approval workflow and execution not enabled</span></div></div></section></div>
  </Shell>;
}
