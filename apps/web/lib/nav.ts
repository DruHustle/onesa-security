export const sections = [
  {slug: "", title: "Security Overview", short: "Overview", group: "Monitor", live: true},
  {slug: "ai-security", title: "AI Security", short: "AI Security", group: "Monitor", live: true},
  {slug: "threat-detection", title: "Threat Detection", short: "Threat Detection", group: "Monitor", live: true},
  {slug: "security-operations", title: "Security Operations", short: "Security Operations", group: "Respond", live: true},
  {slug: "assets-endpoints", title: "Assets & Endpoints", short: "Assets & Endpoints", group: "Respond", live: true},
  {slug: "vulnerabilities", title: "Vulnerabilities", short: "Vulnerabilities", group: "Respond", live: true},
  {slug: "cloud-app-security", title: "Cloud & App Security", short: "Cloud & App Security", group: "Assess", live: false},
  {slug: "security-upgrades", title: "Security Upgrades", short: "Security Upgrades", group: "Assess", live: true},
  {slug: "compliance-reports", title: "Compliance & Reports", short: "Compliance & Reports", group: "Assess", live: true},
  {slug: "integrations", title: "Integrations", short: "Integrations", group: "Manage", live: false},
  {slug: "administration", title: "Administration", short: "Administration", group: "Manage", live: false},
] as const;
