"use client";
import {useState} from "react";

type Inspection = {decision: "Allow"|"Block"|"Redact"|"Review"|"Escalate"; reason_code: string; effective_text: string|null; policy_version: number};
export function GuardrailTester() {
  const [text, setText] = useState("");
  const [actionType, setActionType] = useState<"message" | "tool">("message");
  const [result, setResult] = useState<Inspection | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();setBusy(true);setError("");setResult(null);
    try {
      const res = await fetch("/api/security/ai/inspect", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({text, action_type: actionType})});
      if (!res.ok) {setError("Inspection unavailable or access denied");return;}
      setResult(await res.json() as Inspection);
    } catch {setError("Security API unavailable");} finally {setBusy(false);}
  }
  return <div className="panel"><div className="panel-heading"><div><h2>Evaluate a request</h2><p>Test the configured deterministic baseline. Input is not sent to a model.</p></div><span className="label-pill">LIVE POLICY</span></div>
    <form className="test-form" onSubmit={submit}>
      <label htmlFor="inspection-input">Request or retrieved content</label>
      <textarea id="inspection-input" maxLength={20000} minLength={1} required value={text} onChange={e=>setText(e.target.value)} placeholder="Enter text for policy inspection. Avoid real customer secrets." rows={5}/>
      <div className="form-row"><label htmlFor="action-type">Action type<select id="action-type" value={actionType} onChange={e=>setActionType(e.target.value as "message"|"tool")}><option value="message">AI message</option><option value="tool">Agent tool execution</option></select></label><button disabled={busy || text.length === 0} type="submit">{busy?"Evaluating…":"Run inspection"}</button></div>
    </form>
    {error && <p role="alert" className="form-error">{error}</p>}
    {result && <div aria-live="polite" className="inspection-result"><span className={`decision ${result.decision.toLowerCase()}`}>{result.decision.toUpperCase()}</span><strong>{result.reason_code.replaceAll("_", " ")}</strong><small>Policy version {result.policy_version || "default"}</small>{result.effective_text !== null && <div className="output-preview"><span className="muted micro">EFFECTIVE TEXT</span><p>{result.effective_text}</p></div>}</div>}
  </div>;
}
