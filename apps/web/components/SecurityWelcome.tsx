import { identityConfigured } from "../lib/auth0";
import { featureSignInPath } from "../lib/nav";

const features = [
  {
    slug: "ai-security",
    name: "AI security",
    description: "Inspect authorized AI content against your organization’s guardrail policy.",
    example: "Review whether an example prompt contains information that should be redacted.",
  },
  {
    slug: "assets-endpoints",
    name: "Asset inventory",
    description: "See which systems enrolled collectors have reported to your organization.",
    example: "Check when a sample workstation last reported inventory.",
  },
  {
    slug: "security-operations",
    name: "Alert investigation",
    description: "Follow an alert back to its source events and record what the investigation found.",
    example: "Review a sample alert for repeated sign-in failures.",
  },
  {
    slug: "security-upgrades",
    name: "Remediation review",
    description: "Document a proposed change, its impact and its rollback plan for a second reviewer.",
    example: "Prepare a sample update proposal for approval.",
  },
] as const;

export function SecurityWelcome() {
  return (
    <main className="welcome" id="main-content">
      <div className="welcome-inner welcome-tour">
        <div className="brand-icon big" aria-hidden="true">O</div>
        <h1>Onesa Security</h1>
        <p>Investigate security events, track reported assets and review proposed remediation. Sign in with an approved Onesa Security account to access your organization’s workspace.</p>
        <div className="welcome-actions">
          {identityConfigured && <a className="primary-link" href="/auth/login">Sign in with Onesa</a>}
          <a href="https://account.onesa.eu/register?product=security&amp;platform=web&amp;audience=user">Create an Onesa account</a>
        </div>
        {!identityConfigured && (
          <div className="notice" role="status">Secure sign-in is not yet configured.</div>
        )}
        <section aria-labelledby="welcome-features">
          <h2 id="welcome-features">Features</h2>
          <div className="panel-grid">
            {features.map(({ slug, name, description, example }) => (
              <article className="panel welcome-feature" key={slug}>
                <h3>{name}</h3>
                <p>{description}</p>
                <p className="muted"><strong>Example</strong> {example}</p>
                {identityConfigured && <a href={featureSignInPath(slug)}>Sign in to use {name.toLowerCase()}</a>}
              </article>
            ))}
          </div>
        </section>
      </div>
    </main>
  );
}
