import { Link } from "wouter";
import { ArrowLeft, ChevronRight, LockKeyhole, ShieldCheck } from "lucide-react";

const sections = [
  ["01", "Transport and browser safety", "The hosted application uses HTTPS. Security response headers reduce framing, MIME-sniffing, and unsafe cross-origin behavior. The browser does not receive provider secrets."],
  ["02", "Evidence handling", "Uploaded RFC822 emails are validated, stored as private evidence, and parsed on the server. The application does not execute attachments or follow instructions found inside an email."],
  ["03", "IP location boundaries", "An email address or domain is not an IP address. Location lookup requires an eligible public IP extracted from trusted headers and returns an approximate network, ISP, or relay area—not a person or device location."],
  ["04", "External intelligence", "AbuseIPDB, VirusTotal, PhishTank, and geolocation checks require an analyst approval action. Only the minimum selected indicator is sent through the approved provider path."],
  ["05", "Authentication and access", "OAuth protects the workspace. Case, evidence, intelligence, notes, reports, and administration procedures are protected by the signed-in account and server-side authorization checks."],
];

export default function Documentation() {
  return <main className="docs-page"><header className="docs-header"><Link href="/"><span className="docs-brand"><ShieldCheck size={20} /> Signal Furnace</span></Link><Link href="/" className="docs-back"><ArrowLeft size={15} /> Back to app</Link></header><section className="docs-hero"><span className="docs-kicker">SECURITY DOCUMENTATION</span><h1>Understand how Signal Furnace handles <em>evidence.</em></h1><p>This page explains the important security controls and investigation limits in simple English. It is a product guide, not a promise that an IP address identifies a person.</p></section><section className="docs-grid">{sections.map(([number, title, copy]) => <article key={number} className="docs-card"><span>{number}</span><LockKeyhole size={18} /><h2>{title}</h2><p>{copy}</p><ChevronRight size={16} /></article>)}</section><footer className="docs-footer"><span>SIH26106 · Evidence-first email investigation</span><Link href="/">Open Signal Furnace <ChevronRight size={15} /></Link></footer></main>;
}
