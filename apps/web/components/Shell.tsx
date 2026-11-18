import Link from "next/link";
import { sections } from "../lib/nav";

export function Shell({children, active, name}: {children: React.ReactNode; active: string; name?: string}) {
  return (
    <div className="shell">
      <aside className="sidebar">
        <Link className="brand" href="/" aria-label="Onesa Security home"><span className="brand-icon">O</span><span><strong>ONESA</strong><small>SECURITY</small></span></Link>
        <div className="tenant-box"><span className="muted micro">ORGANIZATION</span><strong>Configured organization</strong><span className="tenant-verified"><span className="status-dot"/> Authenticated workspace</span></div>
        <nav aria-label="Security navigation">
          {sections.map((s, i) => <div key={s.slug}>
            {(i === 0 || sections[i - 1].group !== s.group) && <p className="nav-group">{s.group}</p>}
            <Link href={s.slug ? `/${s.slug}` : "/"} className={`nav-item ${active === s.slug ? "active" : ""}`} aria-current={active === s.slug ? "page" : undefined}>
              <span>{s.short}</span>{!s.live && <span className="small-label">Planned</span>}
            </Link>
          </div>)}
        </nav>
        <div className="sidebar-bottom"><span>Onesa UG · Foundation build</span><span>Security results require real telemetry.</span></div>
      </aside>
      <div className="workspace">
        <header className="topbar"><div className="topbar-left"><span className="eyebrow">ONESA / SECURITY CONTROL PLANE</span></div><div className="topbar-right"><span className="avatar" aria-hidden="true">{name?.slice(0,1).toUpperCase() || "U"}</span><span className="session-name">{name || "Signed-in user"}</span><a href="/auth/logout" className="signout">Sign out</a></div></header>
        <main className="content" id="main-content">{children}</main>
        <footer className="footer">Onesa Security · Real data only · Missing capabilities are explicitly labeled · <a href="https://docs.onesa.eu">Documentation</a></footer>
      </div>
    </div>
  );
}

export function SectionHeader({kicker, title, description}: {kicker: string; title: string; description: string}) {
  return <div className="section-head"><div className="eyebrow">{kicker}</div><h1>{title}</h1><p className="description">{description}</p></div>;
}

export function EmptyState({heading, body}: {heading: string; body: string}) {
  return <div className="empty-state"><span aria-hidden="true" className="empty-symbol">◎</span><h3>{heading}</h3><p>{body}</p></div>;
}

export function Warning({children}: {children: React.ReactNode}) {return <div className="notice" role="status">{children}</div>}
