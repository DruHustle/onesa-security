"use client";
import {useState} from "react";
import {useRouter} from "next/navigation";

export function AlertAction({id, status}: {id: string; status: string}) {
  const router = useRouter();
  const [disposition, setDisposition] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function update(next: string) {
    setError("");setBusy(true);
    try {
      const res = await fetch(`/api/security/alerts/${id}`, {method: "PATCH", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({status: next, disposition: next === "closed" ? disposition : null})});
      if (!res.ok) {setError("Update refused. Analyst or administrator permissions are required."); return;}
      setDisposition("");router.refresh();
    } catch {setError("Security API unavailable");} finally {setBusy(false);}
  }
  return <div className="alert-action"><label htmlFor={`note-${id}`} className="micro">Disposition / case note</label><input id={`note-${id}`} type="text" maxLength={300} value={disposition} onChange={e=>setDisposition(e.target.value)} placeholder="Required to close"/>
    <div className="button-pair">{status !== "investigating" && <button disabled={busy} type="button" className="secondary" onClick={()=>update("investigating")}>Investigate</button>}{status !== "closed" && <button disabled={busy || !disposition.trim()} type="button" onClick={()=>update("closed")}>Close case</button>}</div>
    {error && <p role="alert" className="form-error">{error}</p>}</div>;
}
