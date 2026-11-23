// Real Next.js server smoke test with no external identity or customer credentials.
// Explicitly verifies deployment fails CLOSED. Does not establish production GO.
import assert from "node:assert/strict";
import {spawn} from "node:child_process";
import {setTimeout as sleep} from "node:timers/promises";
import {existsSync} from "node:fs";
import {canOpenSection, hasAnalystAccess, sections} from "../lib/nav.ts";

assert.ok(existsSync(".next/BUILD_ID"), "Run npm run build before the smoke test");
const management = sections.find(section => section.slug === "administration");
assert.ok(management);
assert.equal(canOpenSection(management, "viewer"), false);
assert.equal(canOpenSection(management, "analyst"), false);
assert.equal(canOpenSection(management, "admin"), true);
assert.equal(canOpenSection(management, "owner"), true);
const traces = sections.find(section => section.slug === "ai-agent-traces");
assert.ok(traces);
assert.equal(canOpenSection(traces, "viewer"), false);
assert.equal(canOpenSection(traces, "analyst"), true);
assert.equal(hasAnalystAccess("viewer"), false);
assert.equal(hasAnalystAccess("analyst"), true);
const port=String(30000+Math.floor(Math.random()*2000));
const root="http://127.0.0.1:"+port;
const env={...process.env, NODE_ENV:"production"};
for(const key of ["AUTH0_DOMAIN","AUTH0_CLIENT_ID","AUTH0_CLIENT_SECRET","AUTH0_SECRET","APP_BASE_URL",
  "OIDC_AUDIENCE","ONESA_API_ORIGIN","ONESA_ORGANIZATION_ID"]) delete env[key];
const child=spawn(process.execPath, ["node_modules/next/dist/bin/next","start","--hostname","127.0.0.1","--port",port], {
  env, stdio:["ignore","pipe","pipe"]
});
let output="";
for (const channel of [child.stdout,child.stderr]) {
  channel.on("data", chunk=>{output=(output+chunk.toString()).slice(-4000);});
}
async function get(path) {
  return fetch(root+path,{redirect:"manual",signal:AbortSignal.timeout(3000),headers:{"Accept":"application/json"}});
}
try {
  let ready=false;
  for(let attempt=0;attempt<50;attempt++){
    if(child.exitCode!==null)break;
    try{const r=await get("/api/healthz");if(r.status===200){ready=true;break;}}catch{}
    await sleep(150);
  }
  assert.ok(ready,"Next.js server did not start");
  const health=await get("/api/healthz");
  assert.equal(health.status,200);
  const live=await health.json();
  assert.equal(live.status,"alive");
  assert.equal(live.readiness,"unverified");
  const readiness=await get("/api/readyz");
  assert.equal(readiness.status,503,"Missing security dependencies must fail readiness");
  const state=await readiness.json();
  assert.equal(state.status,"not_ready");
  assert.equal(state.identity,"unconfigured");
  assert.equal(readiness.headers.get("cache-control")?.includes("no-store"),true);
  const signIn=await get("/auth/login");
  assert.equal(signIn.status,503,"Unconfigured Auth0 must never create a session");
  const privateApi=await get("/api/security/ai/agent-traces");
  assert.equal(privateApi.status,503,"Protected data API must fail closed");
  const page=await get("/");
  assert.equal(page.status,200);
  const html=await page.text();
  assert.match(html, /Secure sign-in is not yet configured/);
  assert.match(html, /<h1>Onesa Security<\/h1>/);
  assert.match(html, /<h3>Alert investigation<\/h3>/);
  assert.match(html, /https:\/\/account\.onesa\.eu\/register\?product=security&amp;platform=web&amp;audience=user/);
  assert.doesNotMatch(html, /<h1>Security command center<\/h1>/);
  const restricted=await get("/ai-agent-traces");
  assert.ok([302,303,307,308].includes(restricted.status));
  const signInLocation=new URL(restricted.headers.get("location"),root);
  assert.equal(signInLocation.pathname,"/auth/login");
  assert.equal(signInLocation.searchParams.get("returnTo"),"/ai-agent-traces");
  const admin = await get("/administration");
  assert.ok([302,303,307,308].includes(admin.status));
  const adminSignIn = new URL(admin.headers.get("location"),root);
  assert.equal(adminSignIn.pathname,"/auth/login");
  assert.equal(adminSignIn.searchParams.get("returnTo"),"/administration");
  assert.equal(page.headers.get("x-frame-options"),"DENY");
  console.log("7 runtime checks PASS: health, fail-closed readiness, no sign-in, denied data API, safe landing, protected page, headers");
}catch(error){
  console.error("Next.js runtime smoke failed:", error?.message ?? error);
  console.error("Server diagnostics (scrub before sharing):", output.slice(-1500));
  process.exitCode=1;
}finally{
  child.kill("SIGTERM");
}
