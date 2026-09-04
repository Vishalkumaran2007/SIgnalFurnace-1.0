/**
 * Signal Furnace design reminder: technical neo-brutalism with evidence-led hierarchy,
 * graphite surfaces, restrained Furnace Orange priority signals, and asymmetric command flow.
 */
import { useAuth } from "@/_core/hooks/useAuth";
import { startLogin } from "@/const";
import { useTheme } from "@/contexts/ThemeContext";
import { trpc } from "@/lib/trpc";
import { downloadCaseCsv, downloadCasePdf } from "@/lib/reportExport";
import { MapView } from "@/components/Map";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  Bot,
  BriefcaseBusiness,
  Check,
  ChevronRight,
  CircleAlert,
  Clock3,
  Database,
  Download,
  FileSearch,
  FileText,
  Globe2,
  Grid2X2,
  ListFilter,
  LoaderCircle,
  LogOut,
  MailWarning,
  MapPin,
  Menu,
  MessageSquareText,
  MoreHorizontal,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Radar,
  ScanSearch,
  Send,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Moon,
  Sun,
  Target,
  TerminalSquare,
  Upload,
  X,
} from "lucide-react";
import { ChangeEvent, FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";

type View =
  | "dashboard"
  | "analyzer"
  | "intelligence"
  | "geolocation"
  | "forensics"
  | "assistant"
  | "reports"
  | "settings"
  | "requirements";

type WorkspaceMode = "landing" | "auth" | "workspace";

const navItems: { id: View; label: string; icon: typeof Grid2X2 }[] = [
  { id: "dashboard", label: "Dashboard", icon: Grid2X2 },
  { id: "analyzer", label: "Check an email", icon: ScanSearch },
  { id: "intelligence", label: "Known threats", icon: Radar },
  { id: "geolocation", label: "Location map", icon: Globe2 },
  { id: "forensics", label: "Case details", icon: FileSearch },
  { id: "assistant", label: "AI help", icon: Bot },
  { id: "reports", label: "Reports", icon: FileText },
  { id: "settings", label: "Settings", icon: Settings },
  { id: "requirements", label: "Requirements", icon: ListFilter },
];

function isExternallyEnrichableIpv4(ip: string | null | undefined) {
  if (!ip) return false;
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [first, second, third] = parts;
  if (first === 0 || first === 10 || first === 127 || first >= 224) return false;
  if (first === 169 && second === 254) return false;
  if (first === 172 && second >= 16 && second <= 31) return false;
  if (first === 192 && second === 168) return false;
  return !((first === 192 && second === 0 && third === 2) || (first === 198 && second === 51 && third === 100) || (first === 203 && second === 0 && third === 113));
}

type RequirementStatus = "available" | "waiting" | "missing";
type RequirementItem = { id: string; module: string; title: string; detail: string; status: RequirementStatus; action?: View };

const requirementChecklist: RequirementItem[] = [
  { id: "email-upload", module: "01", title: "Email upload (.eml and .msg)", detail: "Secure .eml upload, evidence storage, and case creation are available. .msg parsing is still not connected.", status: "available", action: "analyzer" },
  { id: "email-parsing", module: "01", title: "Email parsing and metadata", detail: "Available for uploaded .eml files: sender, recipient, subject, message ID, headers, body text, and attachment names are saved with the case.", status: "available", action: "analyzer" },
  { id: "header-forensics", module: "02", title: "Header forensics", detail: "Available for uploaded .eml files: SPF, DKIM, DMARC result text, reply-to, return-path, received headers, and extracted IPs are recorded. Live DNS validation is not connected.", status: "available", action: "analyzer" },
  { id: "spoofing", module: "02", title: "Spoofing detection", detail: "Basic reply-to and sender-domain mismatch detection is available from parsed email headers. Domain reputation checks still need an external source.", status: "available", action: "analyzer" },
  { id: "url-analysis", module: "03", title: "URL extraction and local risk checks", detail: "Available for uploaded .eml files. URLs are extracted and checked locally for raw IP links, shorteners, unusual ports, embedded user information, and non-HTTPS links. Live reputation remains separate.", status: "available", action: "intelligence" },
  { id: "attachment-analysis", module: "04", title: "Attachment detection and local risk checks", detail: "Available for uploaded .eml files. Attachment names and extensions are checked for executable, archive, macro-enabled, and double-extension patterns. No malware execution or reputation result is claimed.", status: "available", action: "intelligence" },
  { id: "ai-threat-detection", module: "05", title: "AI email threat detection", detail: "Available for uploaded .eml files through a bounded server-side content review. It uses only supplied evidence, keeps the AI Guide separate, and does not claim external reputation or malware results.", status: "available", action: "analyzer" },
  { id: "threat-scoring", module: "08", title: "Threat and confidence scoring", detail: "Available from completed .eml structural checks. The saved score explains header, link, attachment, and sender-domain signals; it is not a live reputation score.", status: "available", action: "dashboard" },
  { id: "geolocation", module: "06", title: "IP geolocation and threat map", detail: "Available with explicit analyst approval. A public extracted source IP is sent to the documented ipwho.is lookup service, then its approximate result is saved privately and shown on the map. Private IPs are rejected.", status: "available", action: "geolocation" },
  { id: "threat-intelligence", module: "07", title: "AbuseIPDB, VirusTotal, and PhishTank", detail: "AbuseIPDB and VirusTotal are available for separate analyst-approved public source-IP checks. PhishTank is available for analyst-approved extracted URL checks against its verified-online HTTPS public feed; each provider result is saved with the private case.", status: "available", action: "intelligence" },
  { id: "ioc", module: "09", title: "IOC extraction", detail: "Available from uploaded .eml files: IP addresses, URL hosts, URLs, email addresses, and the SHA-256 evidence hash are saved per case.", status: "available", action: "intelligence" },
  { id: "forensics", module: "10", title: "Evidence collection and timeline", detail: "Available for uploaded .eml files: the original evidence is stored, parsed metadata is saved, and upload and structural-analysis events are recorded.", status: "available", action: "forensics" },
  { id: "case-management", module: "11", title: "Case management and analyst notes", detail: "Available: each completed .eml analysis creates a private case with severity, score, evidence, timeline, IOCs, and analyst notes.", status: "available", action: "forensics" },
  { id: "cyber-assistant", module: "12", title: "AI cyber assistant", detail: "Available now as a protected AI Guide for explanations and approved page navigation only.", status: "available", action: "assistant" },
  { id: "reports", module: "13", title: "Reports, PDF, and CSV export", detail: "Available for saved private cases. CSV and PDF files include real stored scores, evidence metadata, AI review when present, IOCs, timeline events, and analyst notes.", status: "available", action: "reports" },
  { id: "dashboard", module: "14", title: "SOC dashboard", detail: "Available with the signed-in analyst's real uploaded-analysis case totals and risk counts. It remains empty until an email is checked.", status: "available", action: "dashboard" },
  { id: "admin", module: "15", title: "Admin panel", detail: "Available for administrator accounts. Admins can view signed-in users and assign user or administrator roles. Threat-feed credential management and alert delivery stay separate until approved integration details are supplied.", status: "available", action: "settings" },
  { id: "similar-attacks", module: "BONUS", title: "Similar attack detection", detail: "Available for saved private cases. The comparison finds shared extracted URLs, domains, IPs, and email indicators within the signed-in analyst's own cases.", status: "available", action: "intelligence" },
  { id: "heatmap", module: "BONUS", title: "Threat heatmap", detail: "Available when approved IP lookups have saved more than one real location. It renders only the signed-in analyst's private completed-case coordinates.", status: "available", action: "geolocation" },
  { id: "realtime-alerts", module: "BONUS", title: "Real-time alerting", detail: "Available for completed high-risk email checks. A project-owner notification is sent when the saved score reaches 60 or more, and delivery status is written to the case timeline. Custom recipient channels are not configured.", status: "available", action: "settings" },
  { id: "auth", module: "FOUNDATION", title: "Real user authentication", detail: "Available now through the secure OAuth sign-in and sign-out flow.", status: "available", action: "settings" },
  { id: "themes", module: "FOUNDATION", title: "Light and dark themes", detail: "Available now and saved across page reloads.", status: "available", action: "dashboard" },
];

function BrandMark({ compact = false }: { compact?: boolean }) {
  return (
    <div className="brand-lockup" aria-label="Signal Furnace">
      <img className="brand-mark" src="/manus-storage/origin-tracker-logo_395a06a4.png" alt="Origin Tracker intelligence mark" />
      {!compact && (
        <span className="brand-wordmark">
          <b>Signal</b>
          <i>Furnace</i>
        </span>
      )}
    </div>
  );
}

function ScoreRing({ value = 92, label = "Threat score", small = false }: { value?: number; label?: string; small?: boolean }) {
  const size = small ? 58 : 142;
  const radius = small ? 22 : 56;
  const circumference = 2 * Math.PI * radius;
  const dash = (value / 100) * circumference;
  return (
    <div className={`score-ring ${small ? "score-ring--small" : ""}`} style={{ width: size, height: size }}>
      <svg viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <circle className="score-ring__track" cx={size / 2} cy={size / 2} r={radius} />
        <circle
          className="score-ring__value"
          cx={size / 2}
          cy={size / 2}
          r={radius}
          strokeDasharray={`${dash} ${circumference - dash}`}
        />
      </svg>
      <div className="score-ring__content">
        <strong>{value}</strong>
        {!small && <span>{label}</span>}
      </div>
    </div>
  );
}

function SectionLabel({ children }: { children: string }) {
  return <p className="section-label"><span />{children}</p>;
}

function ThemeToggle({ compact = false }: { compact?: boolean }) {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === "dark";
  return <button className={`theme-toggle ${compact ? "theme-toggle--compact" : ""}`} onClick={toggleTheme} aria-label={`Switch to ${isDark ? "light" : "dark"} theme`} title={`Switch to ${isDark ? "light" : "dark"} theme`}><span className="theme-toggle__icon">{isDark ? <Sun size={15} /> : <Moon size={15} />}</span>{!compact && <span>{isDark ? "Light" : "Dark"}</span>}</button>;
}

function MetricCard({ label, value, change, tone = "orange", icon: Icon }: { label: string; value: string; change: string; tone?: "orange" | "cyan" | "safe" | "red"; icon: typeof Activity }) {
  return (
    <article className={`metric-card metric-card--${tone}`}>
      <div className="metric-card__top"><span>{label}</span><Icon size={17} /></div>
      <p>{value}</p>
      <small>{value === "—" ? <Database size={13} /> : <ArrowUpRight size={13} />}{change}{value !== "—" && <em>from last time</em>}</small>
    </article>
  );
}

function EmptyData({ icon: Icon, title, copy, action, onAction, compact = false }: { icon: typeof Activity; title: string; copy: string; action?: string; onAction?: () => void; compact?: boolean }) {
  return <div className={`empty-data ${compact ? "empty-data--compact" : ""}`}><span className="empty-data__icon"><Icon size={compact ? 17 : 24} /></span><div><strong>{title}</strong><p>{copy}</p>{action && onAction && <button onClick={onAction}>{action} <ChevronRight size={14} /></button>}</div></div>;
}

function SeverityBadge({ value }: { value: string }) {
  return <span className={`severity severity--${value.toLowerCase()}`}>{value}</span>;
}

function FeatureCard({ index, icon: Icon, title, copy }: { index: string; icon: typeof Activity; title: string; copy: string }) {
  return (
    <article className="feature-card">
      <div className="feature-card__head"><span>{index}</span><Icon size={24} /></div>
      <h3>{title}</h3>
      <p>{copy}</p>
      <button onClick={() => toast.info(`${title} is ready to explore in this sample website.`)} className="text-button">Learn more <ArrowUpRight size={15} /></button>
    </article>
  );
}

function Landing({ launchWorkspace }: { launchWorkspace: (view?: View) => void }) {
  return (
    <main className="landing-shell">
      <header className="landing-nav">
        <BrandMark />
        <nav aria-label="Primary navigation">
          <a href="#capabilities">Capabilities</a>
          <a href="#workflow">How it works</a>
          <a href="#team">Team</a>
        </nav>
        <div className="landing-nav__actions"><ThemeToggle /><Button onClick={() => launchWorkspace("dashboard")} className="nav-cta">Open dashboard <ArrowUpRight size={16} /></Button></div>
      </header>

      <section className="hero-section">
        <div className="hero-backdrop" />
        <div className="hero-overlay" />
        <div className="hero-grid" />
        <div className="hero-content">
          <div className="hero-kicker"><span className="status-dot" />SIH26106 • EMAIL SAFETY TOOL</div>
          <h1>Check a suspicious email<br />before you <span>trust it.</span></h1>
          <p>This tool helps you spot risky emails, unsafe links, and fake senders. It also gives you clear next steps.</p>
          <div className="hero-actions">
            <Button onClick={() => launchWorkspace("analyzer")} className="hero-primary">Analyze an email <ArrowDownRight size={18} /></Button>
            <button onClick={() => document.getElementById("workflow")?.scrollIntoView({ behavior: "smooth" })} className="hero-secondary">See how it works <ChevronRight size={18} /></button>
          </div>
          <div className="hero-meta"><span><Check size={14} /> Check the sender</span><span><Check size={14} /> Find unsafe links</span><span><Check size={14} /> Save a clear report</span></div>
        </div>

        <aside className="hero-case-card hero-case-card--empty">
          <div className="case-card__top"><span>LIVE CASES</span><MoreHorizontal size={17} /></div>
          <div className="case-card__case"><div><small>STATUS</small><strong>No live data</strong></div></div>
          <p>Connect a safe data source to show real alerts, cases, and warning details here.</p>
          <button onClick={() => launchWorkspace("settings")} className="case-card__open">Open data settings <ChevronRight size={16} /></button>
        </aside>

        <div className="hero-statusbar"><span><i className="live-pulse" /> DATA CONNECTION NEEDED</span><span>TIME RANGE <b>NOT AVAILABLE</b></span><span>VERSION <b>0.9.6</b></span></div>
      </section>

      <section id="capabilities" className="capabilities-section section-wrap">
        <div className="section-intro"><div><SectionLabel>What this tool can do</SectionLabel><h2>One simple place<br /><span>to check emails safely.</span></h2></div><p>Upload an email, see what looks risky, and get clear steps for what to do next.</p></div>
        <div className="feature-grid">
          <FeatureCard index="01" icon={MailWarning} title="Check emails" copy="Check who sent the email, what it says, and where its links lead." />
          <FeatureCard index="02" icon={Globe2} title="See the location" copy="See where suspicious activity may be coming from." />
          <FeatureCard index="03" icon={Radar} title="Understand the risk" copy="Get a simple risk score and a short explanation." />
          <FeatureCard index="04" icon={Bot} title="Ask for help" copy="Ask why an email was flagged and what you should do." />
          <FeatureCard index="05" icon={FileText} title="Make a report" copy="Create a simple report that you can share with your team." />
          <FeatureCard index="06" icon={FileSearch} title="See the details" copy="Keep the email, links, files, and notes together in one place." />
        </div>
      </section>

      <section id="workflow" className="workflow-section">
        <div className="workflow-splash" />
        <div className="workflow-scrim" />
        <div className="workflow-content section-wrap">
          <div><SectionLabel>How it works</SectionLabel><h2>Four simple steps<br /><span>to check an email.</span></h2></div>
          <div className="workflow-list">
            {[
              ["01", "Upload", "Add an .eml or .msg email file."],
              ["02", "Check", "Check the sender, links, and message."],
              ["03", "See the result", "See what looks unsafe and where it may come from."],
              ["04", "Take action", "Save the result and follow the suggested next step."],
            ].map(([number, title, copy], index) => <div key={title} className="workflow-item"><span>{number}</span><div><h3>{title}</h3><p>{copy}</p></div>{index < 3 && <ArrowDownRight size={22} />}</div>)}
          </div>
        </div>
      </section>

      <section className="evidence-section section-wrap">
        <div className="evidence-visual" role="img" aria-label="Saved email details"><img src="/manus-storage/signal-furnace-evidence_b9c4e457.jpg" alt="Saved email details" /><div className="evidence-visual__caption"><span>DETAILS SAVED</span><strong>FILE CHECK</strong><i /></div></div>
        <div className="evidence-copy"><SectionLabel>Clear details</SectionLabel><h2>Know what was found<br />and <span>why it matters.</span></h2><p>This tool does more than show a score. It keeps the email details and explains what looks unsafe in simple words.</p><ul><li><Check /> A clear list of what happened</li><li><Check /> An easy list of unsafe links and files</li><li><Check /> A simple explanation for every score</li></ul><Button onClick={() => launchWorkspace("forensics")} className="outline-cta">View case details <ChevronRight size={17} /></Button></div>
      </section>

      <section id="team" className="team-section section-wrap">
        <div><SectionLabel>SIH26106 team</SectionLabel><h2>Meet the<br /><span>project team.</span></h2></div>
        <div className="team-list">
          <article className="team-profile">
            <span>01</span>
            <div>
              <strong>Vishalkumaran V</strong>
              <p>Electrical and Electronics Engineering student who explores AI, software, and electronics through hands-on projects.</p>
              <div className="team-profile__tags"><b>AI</b><b>Software</b><b>Electronics</b></div>
            </div>
            <a href="https://vishalkumaran2007.github.io/Portfolio/" target="_blank" rel="noreferrer">View portfolio <ArrowUpRight size={15} /></a>
          </article>
          {["Sayasree", "Rohini", "Sankarprasath", "Surya", "Radhi Devi"].map((member, index) => <div key={member} className="team-member"><span>0{index + 2}</span><strong>{member}</strong><i /></div>)}
        </div>
      </section>

      <footer className="landing-footer"><BrandMark /><p>A simple tool for checking suspicious emails.</p><button onClick={() => launchWorkspace("dashboard")}>Open dashboard <ArrowUpRight size={15} /></button></footer>
    </main>
  );
}

function WorkspaceSidebar({ activeView, setActiveView, compact, setCompact, userName, signOut }: { activeView: View; setActiveView: (view: View) => void; compact: boolean; setCompact: (compact: boolean) => void; userName: string; signOut: () => void }) {
  return (
    <aside className={`workspace-sidebar ${compact ? "workspace-sidebar--compact" : ""}`}>
      <div className="sidebar-brand"><div className="terminal-brand"><img className="terminal-brand__mark" src="/manus-storage/origin-tracker-logo_395a06a4.png" alt="Origin Tracker" /><div><strong>Origin Tracker</strong><small>Private security workspace</small></div></div><button aria-label="Toggle sidebar" onClick={() => setCompact(!compact)}>{compact ? <PanelLeftOpen size={17} /> : <PanelLeftClose size={17} />}</button></div>
      {!compact && <div className="case-switcher"><span>CASE STATUS</span><button onClick={() => setActiveView("forensics")}><i /> NO CASE SELECTED <ChevronRight size={14} /></button></div>}
      <nav className="workspace-nav" aria-label="Command center sections">
        {navItems.map(({ id, label, icon: Icon }) => <button key={id} onClick={() => setActiveView(id)} className={activeView === id ? "active" : ""} title={compact ? label : undefined}><Icon size={18} /><span>{label}</span></button>)}
      </nav>
      <div className="sidebar-bottom"><button onClick={signOut}><LogOut size={18} /><span>Sign out</span></button><div className="sidebar-user"><span>{userName.slice(0, 1).toUpperCase()}</span>{!compact && <div><strong>{userName}</strong><small>Signed-in user</small></div>}</div></div>
    </aside>
  );
}

function Topbar({ activeView, setMobileOpen, openGuide }: { activeView: View; setMobileOpen: (value: boolean) => void; openGuide: () => void }) {
  const current = navItems.find((item) => item.id === activeView)!;
  return <header className="workspace-topbar"><button className="mobile-menu" aria-label="Open menu" onClick={() => setMobileOpen(true)}><Menu size={20} /></button><div className="breadcrumb"><span>WORKSPACE</span><ChevronRight size={14} /><strong>{current.label}</strong></div><div className="topbar-actions"><ThemeToggle compact /><button title="Open AI guide" onClick={openGuide} className="guide-trigger"><Bot size={18} /></button><button title="Filter results" onClick={() => toast.info("Filters need live data.")}><ListFilter size={18} /></button><button title="Notifications" onClick={() => toast.info("There are no live notifications yet.")} className="notification-button"><Activity size={18} /><i /></button><Button onClick={() => toast.info("New cases will be available after real data is connected.")} className="new-case"><Plus size={17} /> New case</Button></div></header>;
}

function DashboardView({ setActiveView, selectInvestigation }: { setActiveView: (view: View) => void; selectInvestigation: (id: number) => void }) {
  const summary = trpc.analysis.dashboard.useQuery();
  const cases = summary.data?.cases || [];
  const openCase = (id: number) => { selectInvestigation(id); setActiveView("forensics"); };
  const hasCases = cases.length > 0;
  return <div className="page-content dashboard-view"><div className="page-title-row"><div><SectionLabel>Live case data</SectionLabel><h1>Safety <span>dashboard.</span></h1><p>{hasCases ? "These totals come from your saved email checks." : "Upload an .eml email to create your first private case."}</p></div><span className="time-chip"><Database size={15} /> {summary.isLoading ? "Loading" : hasCases ? "Live cases" : "No cases yet"}</span></div>{summary.isError ? <div className="data-connection-note"><CircleAlert size={16} /><span>Case data could not be loaded right now. Please refresh and try again.</span></div> : <div className="data-connection-note"><ShieldCheck size={16} /><span>{hasCases ? "Only your saved analysis cases are shown here." : "No example results are shown. Your data stays empty until you upload an .eml email."}</span></div>}<div className="metrics-grid"><MetricCard label="Warnings found" value={summary.isLoading ? "—" : String(summary.data?.highRisk ?? 0)} change={hasCases ? "high-risk cases" : "No data yet"} icon={ShieldAlert} tone="red" /><MetricCard label="Emails checked" value={summary.isLoading ? "—" : String(summary.data?.total ?? 0)} change={hasCases ? "saved analyses" : "No data yet"} icon={MailWarning} tone="orange" /><MetricCard label="High risk emails" value={summary.isLoading ? "—" : String(summary.data?.highRisk ?? 0)} change={hasCases ? "score 60 or higher" : "No data yet"} icon={CircleAlert} tone="orange" /><MetricCard label="Open cases" value={summary.isLoading ? "—" : String(summary.data?.open ?? 0)} change={hasCases ? "needs review" : "No data yet"} icon={BriefcaseBusiness} tone="cyan" /></div><div className="dashboard-main-grid"><section className="panel threat-volume-panel"><div className="panel-header"><div><span>EMAIL WARNINGS</span><h2>Saved risk scores</h2></div></div>{hasCases ? <div className="simple-record-list">{cases.slice(0, 5).map((item) => <button key={item.id} onClick={() => openCase(item.id)}><span>{item.caseNumber}</span><strong>{item.title}</strong><b>{item.threatScore}/100</b></button>)}</div> : <EmptyData icon={Activity} title="No risk scores yet" copy="A score will appear after a real .eml file completes the structural check." />}</section><section className="panel distribution-panel"><div className="panel-header"><div><span>RISK LEVELS</span><h2>What we found</h2></div></div>{hasCases ? <div className="simple-record-list">{cases.slice(0, 4).map((item) => <button key={item.id} onClick={() => openCase(item.id)}><SeverityBadge value={item.severity} /><strong>{item.caseNumber}</strong><span>{item.confidence}% confidence</span></button>)}</div> : <EmptyData icon={Radar} title="No warning types yet" copy="Real categories will appear after the first completed check." compact />}</section><section className="panel global-map-panel"><div className="panel-header"><div><span>LOCATION MAP</span><h2>Where alerts may come from</h2></div></div><EmptyData icon={Globe2} title="No location data yet" copy="IP geolocation needs an approved location source. Parsed source IPs are saved with each case when present." /></section><section className="panel activity-panel"><div className="panel-header"><div><span>RECENT CASES</span><h2>What changed</h2></div></div>{hasCases ? <div className="simple-record-list">{cases.slice(0, 3).map((item) => <button key={item.id} onClick={() => openCase(item.id)}><Clock3 size={15} /><strong>{item.title}</strong><span>{new Date(item.createdAt).toLocaleString()}</span></button>)}</div> : <EmptyData icon={Clock3} title="No recent updates" copy="Live activity will appear when a check creates a case." compact />}</section></div><section className="panel cases-panel"><div className="panel-header"><div><span>CASES TO CHECK</span><h2>Emails that need attention</h2></div>{hasCases && <Button onClick={() => setActiveView("analyzer")} className="outline-cta">Check another email <Upload size={15} /></Button>}</div>{hasCases ? <div className="simple-record-list">{cases.map((item) => <button key={item.id} onClick={() => openCase(item.id)}><SeverityBadge value={item.severity} /><div><strong>{item.title}</strong><span>{item.caseNumber} · score {item.threatScore}/100 · {item.confidence}% confidence</span></div><ChevronRight size={17} /></button>)}</div> : <EmptyData icon={BriefcaseBusiness} title="No cases yet" copy="Choose an .eml file to upload, check, and save your first private case." action="Check an email" onAction={() => setActiveView("analyzer")} />}</section></div>;
}

function AnalyzerView({ setActiveView, selectInvestigation }: { setActiveView: (view: View) => void; selectInvestigation: (id: number) => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [lastResult, setLastResult] = useState<{ investigationId: number; caseNumber: string; ownerAlert: "not_needed" | "delivered" | "unavailable"; parsed: { threatScore: number; confidence: number; severity: string; summary: string; reasons: string[]; findings: Array<{ kind: string; severity: string; value: string; detail: string }>; ai: { category: string; confidence: number; socialEngineering: string; recommendations: string[] } | null } } | null>(null);
  const utils = trpc.useUtils();
  const upload = trpc.analysis.ingestEml.useMutation({ onSuccess: (result) => { setLastResult(result); selectInvestigation(result.investigationId); utils.analysis.dashboard.invalidate(); utils.analysis.list.invalidate(); utils.analysis.indicators.invalidate(); toast.success(result.ownerAlert === "delivered" ? `Saved ${result.caseNumber}. A high-risk owner alert was sent.` : result.ownerAlert === "unavailable" ? `Saved ${result.caseNumber}. The high-risk alert could not be delivered; review the case.` : `Saved ${result.caseNumber}. Open the case details to review the evidence.`); }, onError: (error) => toast.error(error.message) });
  const chooseFile = () => input.current?.click();
  const onFile = (event: ChangeEvent<HTMLInputElement>) => { const chosen = event.target.files?.[0]; if (!chosen) return; if (!chosen.name.toLowerCase().endsWith(".eml")) { toast.error("Upload an .eml file. .msg parsing is not connected yet."); event.target.value = ""; return; } if (chosen.size > 4 * 1024 * 1024) { toast.error("Email files must be smaller than 4 MB."); event.target.value = ""; return; } setFile(chosen); setLastResult(null); toast.info(`${chosen.name} is ready for a secure server-side check.`); };
  const analyze = async () => { if (!file || upload.isPending) { if (!file) toast.info("Choose an .eml file first."); return; } const dataUrl = await new Promise<string>((resolve, reject) => { const reader = new FileReader(); reader.onerror = () => reject(new Error("The file could not be read.")); reader.onload = () => resolve(String(reader.result)); reader.readAsDataURL(file); }); upload.mutate({ filename: file.name, mimeType: file.type || "message/rfc822", base64: dataUrl.split(",")[1] || "" }); };
  return <div className="page-content analyzer-view">
    <div className="page-title-row"><div><SectionLabel>Start here</SectionLabel><h1>Check an <span>email.</span></h1><p>Upload an .eml email to check its sender, headers, links, and attachment names.</p></div><div className="file-formats"><FileText size={17} /><span>FILES</span><b>.EML</b><b>.MSG LATER</b></div></div>
    <div className="analyzer-layout"><section className="upload-panel"><div className="upload-panel__grid" /><input ref={input} onChange={onFile} type="file" accept=".eml,message/rfc822" className="sr-only" /><div className="upload-icon"><Upload size={27} /></div><h2>Add an .eml file.</h2><p>When you start the check, the file is uploaded to protected evidence storage and a private case is created for your account.</p><Button onClick={chooseFile} className="hero-primary">Choose .eml file <Upload size={17} /></Button><button className="upload-drop" onClick={chooseFile}>or choose a file here</button>{file && <div className="staged-file"><FileText size={18} /><span><strong>{file.name}</strong><small>{Math.ceil(file.size / 1024)} KB · ready for secure upload</small></span><button onClick={() => { setFile(null); setLastResult(null); if (input.current) input.current.value = ""; }}><X size={16} /></button></div>}</section><aside className="analysis-guide"><span>CHECK STATUS</span><ol><li><i>01</i><div><strong>Choose an .eml file</strong><p>The maximum file size is 4 MB.</p></div></li><li><i>02</i><div><strong>Run the evidence check</strong><p>Headers, links, attachment names, IPs, spoofing signals, and a bounded content review run on the server.</p></div></li><li><i>03</i><div><strong>Review the saved case</strong><p>Evidence, IOCs, a timeline, and notes stay in your signed-in workspace.</p></div></li></ol><Button onClick={analyze} disabled={!file || upload.isPending} className="analyze-button"><ScanSearch size={17} /> {upload.isPending ? "Checking email…" : "Start secure check"}</Button></aside></div><section className="analysis-result"><div className="analysis-result__head"><div><span>EMAIL CHECK RESULT</span><h2>{lastResult ? `Saved as ${lastResult.caseNumber}` : "No result yet"}</h2></div>{lastResult && <Button onClick={() => setActiveView("forensics")} className="outline-cta">Open case details <ChevronRight size={16} /></Button>}</div>{lastResult ? <div className="analysis-pending"><SeverityBadge value={lastResult.parsed.severity} /><strong>Score {lastResult.parsed.threatScore}/100 · {lastResult.parsed.confidence}% confidence</strong><p>{lastResult.parsed.summary}</p>{lastResult.parsed.ai && <p><strong>AI category: {lastResult.parsed.ai.category.replace(/_/g, " ")} · {lastResult.parsed.ai.confidence}% confidence</strong><br />{lastResult.parsed.ai.socialEngineering || "No social-engineering pattern was stated."}<br />Next step: {lastResult.parsed.ai.recommendations[0] || "Review the saved evidence."}</p>}<p>{lastResult.parsed.reasons.length ? `Signals: ${lastResult.parsed.reasons.join("; ")}.` : "No structural warning was found."}</p></div> : <p className="analysis-pending">No example result is shown. Start a secure check to upload a real .eml file and save the result.</p>}</section>
  </div>;
}

function IntelligenceViewLegacy() {
  const iocs = trpc.analysis.indicators.useQuery();
  const cases = trpc.analysis.list.useQuery();
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const activeId = selectedId || cases.data?.[0]?.id;
  const detail = trpc.analysis.detail.useQuery({ investigationId: activeId || 0 }, { enabled: Boolean(activeId) });
  const similar = trpc.analysis.similar.useQuery({ investigationId: activeId || 0 }, { enabled: Boolean(activeId) });
  const reputations = trpc.analysis.reputations.useQuery();
  const utils = trpc.useUtils();
  const enrichReputation = trpc.analysis.enrichReputation.useMutation({ onSuccess: () => { utils.analysis.reputations.invalidate(); utils.analysis.detail.invalidate(); toast.success("AbuseIPDB evidence was saved with this private case."); }, onError: (error) => toast.error(error.message) });
  const findings = useMemo(() => {
    try {
      const parsed = JSON.parse(detail.data?.artifact?.findingsJson || "[]");
      return Array.isArray(parsed) ? parsed as Array<{ kind: string; severity: string; value: string; detail: string }> : [];
    } catch { return []; }
  }, [detail.data?.artifact?.findingsJson]);
  const reputation = detail.data?.reputations?.[0];
  const sourceIp = detail.data?.artifact?.originatingIp;
  return <div className="page-content intelligence-view"><div className="page-title-row"><div><SectionLabel>Extracted indicators</SectionLabel><h1>Links, IPs, and <span>email traces.</span></h1><p>Local signals come from saved evidence. AbuseIPDB is available only after an analyst approves a public source-IP reputation check; VirusTotal and PhishTank remain unconnected.</p></div><span className="time-chip"><Database size={15} /> {iocs.isLoading ? "Loading" : `${iocs.data?.length || 0} saved`}</span></div>{iocs.data?.length ? <><section className="panel"><div className="panel-header"><div><span>ALL SAVED INDICATORS</span><h2>Private extracted data</h2></div></div><div className="simple-record-list">{iocs.data.map((ioc) => <div key={ioc.id}><SeverityBadge value={ioc.type} /><strong>{ioc.value}</strong><span>{ioc.source} · {new Date(ioc.createdAt).toLocaleString()}</span></div>)}</div></section><section className="panel" style={{ marginTop: 14 }}><div className="panel-header"><div><span>SELECT CASE</span><h2>Local risk and comparison</h2></div></div><div className="simple-record-list">{cases.data?.map((item) => <button key={item.id} onClick={() => setSelectedId(item.id)}><SeverityBadge value={item.severity} /><strong>{item.caseNumber}</strong><span>{item.title}</span></button>)}</div></section>{detail.data && <div className="dashboard-main-grid" style={{ marginTop: 14 }}><section className="panel"><div className="panel-header"><div><span>LOCAL RISK SIGNALS</span><h2>{detail.data.investigation.caseNumber}</h2></div></div>{findings.length ? <div className="simple-record-list">{findings.map((finding, index) => <div key={`${finding.kind}-${finding.value}-${index}`}><SeverityBadge value={finding.severity} /><strong>{finding.kind === "url" ? "Link review" : "Attachment review"}</strong><span>{finding.value} · {finding.detail}</span></div>)}</div> : <EmptyData icon={ShieldCheck} title="No local risk signal found" copy="This case may still contain indicators. No URL or attachment pattern matched the local rule set." compact />}</section><section className="panel"><div className="panel-header"><div><span>SIMILAR SAVED CASES</span><h2>Shared evidence patterns</h2></div></div>{similar.data?.length ? <div className="simple-record-list">{similar.data.map((item) => <div key={item.id}><SeverityBadge value={item.severity} /><strong>{item.caseNumber} · {item.matches.length} shared signal{item.matches.length === 1 ? "" : "s"}</strong><span>{item.matches.map((match) => `${match.type}: ${match.value}`).join("; ")}</span></div>)}</div> : <EmptyData icon={Network} title="No similar saved case" copy="A match appears only when another case in your account shares an extracted URL, domain, IP, or email indicator." compact />}</section><section className="panel"><div className="panel-header"><div><span>ABUSEIPDB REPUTATION</span><h2>Approved source-IP check</h2></div></div>{reputation ? <div className="analysis-pending"><SeverityBadge value={reputation.abuseConfidenceScore >= 60 ? "high" : reputation.abuseConfidenceScore >= 25 ? "medium" : "low"} /><strong>{reputation.ip} · {reputation.abuseConfidenceScore}/100 confidence of abuse</strong><p>{reputation.totalReports} reports from {reputation.numDistinctUsers} reporting user{reputation.numDistinctUsers === 1 ? "" : "s"} in the provider response. {reputation.isWhitelisted ? "The provider marks this IP as whitelisted." : "The provider does not mark this IP as whitelisted."}</p><p>{[reputation.usageType, reputation.isp, reputation.domain, reputation.countryCode].filter(Boolean).join(" · ") || "No additional provider metadata was returned."}</p></div> : <div className="analysis-pending"><strong>{sourceIp ? `Extracted source IP: ${sourceIp}` : "No source IP was extracted from this case."}</strong><p>When approved, only this public IP is sent to AbuseIPDB. No email body, attachment, or account details are sent.</p><Button className="outline-cta" disabled={!sourceIp || enrichReputation.isPending} onClick={() => enrichReputation.mutate({ investigationId: detail.data.investigation.id })}><Radar size={15} /> {enrichReputation.isPending ? "Checking AbuseIPDB…" : "Approve AbuseIPDB check"}</Button></div>}</section></div>}</> : <section className="panel empty-panel"><EmptyData icon={Radar} title="No indicators yet" copy="Upload and check an .eml file to extract your first URLs, domains, IPs, email addresses, and evidence hash." /></section>}</div>;
}

function ReputationEvidencePanel({ provider, result, sourceIp, busy, approve }: { provider: "AbuseIPDB" | "VirusTotal"; result: { ip: string; abuseConfidenceScore: number; totalReports: number; numDistinctUsers: number; isWhitelisted: number; malicious: number; suspicious: number; harmless: number; undetected: number; reputationScore: number | null; countryCode: string | null; asn: number | null; asOwner: string | null; network: string | null; usageType: string | null; isp: string | null; domain: string | null } | undefined; sourceIp: string | null | undefined; busy: boolean; approve: () => void }) {
  const isAbuse = provider === "AbuseIPDB";
  if (!result && sourceIp && !isExternallyEnrichableIpv4(sourceIp)) return <section className="panel"><div className="panel-header"><div><span>{provider.toUpperCase()} REPUTATION</span><h2>Approved source-IP check</h2></div></div><EmptyData icon={Radar} title="Source IP is not eligible for lookup" copy={`${sourceIp} is a private, reserved, or documentation-only address. It is kept as private evidence and is never sent to ${provider}.`} compact /></section>;
  return <section className="panel"><div className="panel-header"><div><span>{provider.toUpperCase()} REPUTATION</span><h2>Approved source-IP check</h2></div></div>{result ? isAbuse ? <div className="analysis-pending"><SeverityBadge value={result.abuseConfidenceScore >= 60 ? "high" : result.abuseConfidenceScore >= 25 ? "medium" : "low"} /><strong>{result.ip} · {result.abuseConfidenceScore}/100 confidence of abuse</strong><p>{result.totalReports} reports from {result.numDistinctUsers} reporting user{result.numDistinctUsers === 1 ? "" : "s"}. {result.isWhitelisted ? "The provider marks this IP as whitelisted." : "The provider does not mark this IP as whitelisted."}</p><p>{[result.usageType, result.isp, result.domain, result.countryCode].filter(Boolean).join(" · ") || "No additional provider metadata was returned."}</p></div> : <div className="analysis-pending"><SeverityBadge value={result.malicious > 0 ? "high" : result.suspicious > 0 ? "medium" : "low"} /><strong>{result.ip} · {result.malicious} malicious / {result.suspicious} suspicious provider detections</strong><p>{result.harmless} harmless and {result.undetected} undetected results. Community reputation: {result.reputationScore ?? "not recorded"}.</p><p>{[result.asOwner, result.network, result.countryCode, result.asn ? `ASN ${result.asn}` : null].filter(Boolean).join(" · ") || "No additional provider metadata was returned."}</p></div> : <div className="analysis-pending"><strong>{sourceIp ? `Extracted source IP: ${sourceIp}` : "No source IP was extracted from this case."}</strong><p>When approved, only this public IP is sent to {provider}. No email body, attachment, or account details are sent.</p><Button className="outline-cta" disabled={!sourceIp || busy} onClick={approve}><Radar size={15} /> {busy ? `Checking ${provider}…` : `Approve ${provider} check`}</Button></div>}</section>;
}

function IntelligenceViewWithIpOnly() {
  const iocs = trpc.analysis.indicators.useQuery();
  const cases = trpc.analysis.list.useQuery();
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const activeId = selectedId || cases.data?.[0]?.id;
  const detail = trpc.analysis.detail.useQuery({ investigationId: activeId || 0 }, { enabled: Boolean(activeId) });
  const similar = trpc.analysis.similar.useQuery({ investigationId: activeId || 0 }, { enabled: Boolean(activeId) });
  const utils = trpc.useUtils();
  const enrichAbuse = trpc.analysis.enrichReputation.useMutation({ onSuccess: () => { utils.analysis.reputations.invalidate(); utils.analysis.detail.invalidate(); toast.success("AbuseIPDB evidence was saved with this private case."); }, onError: (error) => toast.error(error.message) });
  const enrichVirusTotal = trpc.analysis.enrichVirusTotal.useMutation({ onSuccess: () => { utils.analysis.reputations.invalidate(); utils.analysis.detail.invalidate(); toast.success("VirusTotal evidence was saved with this private case."); }, onError: (error) => toast.error(error.message) });
  const findings = useMemo(() => { try { const parsed = JSON.parse(detail.data?.artifact?.findingsJson || "[]"); return Array.isArray(parsed) ? parsed as Array<{ kind: string; severity: string; value: string; detail: string }> : []; } catch { return []; } }, [detail.data?.artifact?.findingsJson]);
  const sourceIp = detail.data?.artifact?.originatingIp;
  const abuse = detail.data?.reputations?.find((item) => item.provider === "AbuseIPDB");
  const virusTotal = detail.data?.reputations?.find((item) => item.provider === "VirusTotal");
  return <div className="page-content intelligence-view"><div className="page-title-row"><div><SectionLabel>Extracted indicators</SectionLabel><h1>Links, IPs, and <span>email traces.</span></h1><p>Local signals come from saved evidence. AbuseIPDB and VirusTotal are available only after analyst approval for a public source IP. PhishTank remains unconnected.</p></div><span className="time-chip"><Database size={15} /> {iocs.isLoading ? "Loading" : `${iocs.data?.length || 0} saved`}</span></div>{iocs.data?.length ? <><section className="panel"><div className="panel-header"><div><span>ALL SAVED INDICATORS</span><h2>Private extracted data</h2></div></div><div className="simple-record-list">{iocs.data.map((ioc) => <div key={ioc.id}><SeverityBadge value={ioc.type} /><strong>{ioc.value}</strong><span>{ioc.source} · {new Date(ioc.createdAt).toLocaleString()}</span></div>)}</div></section><section className="panel" style={{ marginTop: 14 }}><div className="panel-header"><div><span>SELECT CASE</span><h2>Local risk and comparison</h2></div></div><div className="simple-record-list">{cases.data?.map((item) => <button key={item.id} onClick={() => setSelectedId(item.id)}><SeverityBadge value={item.severity} /><strong>{item.caseNumber}</strong><span>{item.title}</span></button>)}</div></section>{detail.data && <div className="dashboard-main-grid" style={{ marginTop: 14 }}><section className="panel"><div className="panel-header"><div><span>LOCAL RISK SIGNALS</span><h2>{detail.data.investigation.caseNumber}</h2></div></div>{findings.length ? <div className="simple-record-list">{findings.map((finding, index) => <div key={`${finding.kind}-${finding.value}-${index}`}><SeverityBadge value={finding.severity} /><strong>{finding.kind === "url" ? "Link review" : "Attachment review"}</strong><span>{finding.value} · {finding.detail}</span></div>)}</div> : <EmptyData icon={ShieldCheck} title="No local risk signal found" copy="This case may still contain indicators. No URL or attachment pattern matched the local rule set." compact />}</section><section className="panel"><div className="panel-header"><div><span>SIMILAR SAVED CASES</span><h2>Shared evidence patterns</h2></div></div>{similar.data?.length ? <div className="simple-record-list">{similar.data.map((item) => <div key={item.id}><SeverityBadge value={item.severity} /><strong>{item.caseNumber} · {item.matches.length} shared signal{item.matches.length === 1 ? "" : "s"}</strong><span>{item.matches.map((match) => `${match.type}: ${match.value}`).join("; ")}</span></div>)}</div> : <EmptyData icon={Network} title="No similar saved case" copy="A match appears only when another case in your account shares an extracted URL, domain, IP, or email indicator." compact />}</section><ReputationEvidencePanel provider="AbuseIPDB" result={abuse} sourceIp={sourceIp} busy={enrichAbuse.isPending} approve={() => enrichAbuse.mutate({ investigationId: detail.data.investigation.id })} /><ReputationEvidencePanel provider="VirusTotal" result={virusTotal} sourceIp={sourceIp} busy={enrichVirusTotal.isPending} approve={() => enrichVirusTotal.mutate({ investigationId: detail.data.investigation.id })} /></div>}</> : <section className="panel empty-panel"><EmptyData icon={Radar} title="No indicators yet" copy="Upload and check an .eml file to extract your first URLs, domains, IPs, email addresses, and evidence hash." /></section>}</div>;
}

function PhishTankEvidencePanel({ entries, urls, busy, approve }: { entries: Array<{ id: number; url: string; inDatabase: number; phishId: number | null; online: number; target: string | null; feedUpdatedAt: Date | string | null }>; urls: string[]; busy: boolean; approve: (url: string) => void }) {
  return <section className="panel"><div className="panel-header"><div><span>PHISHTANK PUBLIC FEED</span><h2>Approved URL checks</h2></div></div>{entries.length ? <div className="simple-record-list">{entries.map((entry) => <div key={entry.id}><SeverityBadge value={entry.inDatabase ? "high" : "safe"} /><strong>{entry.url}</strong><span>{entry.inDatabase ? `Verified ${entry.online ? "online " : ""}phish${entry.phishId ? ` · ID ${entry.phishId}` : ""}${entry.target ? ` · target ${entry.target}` : ""}` : "No verified online match in the cached PhishTank feed."} · feed checked {new Date(entry.feedUpdatedAt || Date.now()).toLocaleString()}</span></div>)}</div> : urls.length ? <div className="analysis-pending"><strong>Select an extracted URL to check the permitted public feed.</strong><p>Only the selected URL is matched against a four-hour server cache of PhishTank's verified-online HTTPS feed. The email body, attachment, and account details are not sent.</p><div className="simple-record-list">{urls.map((url) => <button key={url} className="outline-cta" disabled={busy} onClick={() => approve(url)}><Radar size={15} /> {busy ? "Checking PhishTank…" : "Approve PhishTank check"}<span>{url}</span></button>)}</div></div> : <EmptyData icon={Radar} title="No URL available for PhishTank" copy="This case has no extracted URL indicators to match against the verified-online public feed." compact />}</section>;
}

function IntelligenceView() {
  const iocs = trpc.analysis.indicators.useQuery();
  const cases = trpc.analysis.list.useQuery();
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const activeId = selectedId || cases.data?.[0]?.id;
  const detail = trpc.analysis.detail.useQuery({ investigationId: activeId || 0 }, { enabled: Boolean(activeId) });
  const similar = trpc.analysis.similar.useQuery({ investigationId: activeId || 0 }, { enabled: Boolean(activeId) });
  const utils = trpc.useUtils();
  const enrichAbuse = trpc.analysis.enrichReputation.useMutation({ onSuccess: () => { utils.analysis.reputations.invalidate(); utils.analysis.detail.invalidate(); toast.success("AbuseIPDB evidence was saved with this private case."); }, onError: (error) => toast.error(error.message) });
  const enrichVirusTotal = trpc.analysis.enrichVirusTotal.useMutation({ onSuccess: () => { utils.analysis.reputations.invalidate(); utils.analysis.detail.invalidate(); toast.success("VirusTotal evidence was saved with this private case."); }, onError: (error) => toast.error(error.message) });
  const enrichPhishTank = trpc.analysis.enrichPhishTank.useMutation({ onSuccess: () => { utils.analysis.detail.invalidate(); toast.success("PhishTank feed result was saved with this private case."); }, onError: (error) => toast.error(error.message) });
  const findings = useMemo(() => { try { const parsed = JSON.parse(detail.data?.artifact?.findingsJson || "[]"); return Array.isArray(parsed) ? parsed as Array<{ kind: string; severity: string; value: string; detail: string }> : []; } catch { return []; } }, [detail.data?.artifact?.findingsJson]);
  const sourceIp = detail.data?.artifact?.originatingIp;
  const urls = detail.data?.iocs.filter((indicator) => indicator.type === "url").map((indicator) => indicator.value) || [];
  const abuse = detail.data?.reputations?.find((item) => item.provider === "AbuseIPDB");
  const virusTotal = detail.data?.reputations?.find((item) => item.provider === "VirusTotal");
  return <div className="page-content intelligence-view"><div className="page-title-row"><div><SectionLabel>Extracted indicators</SectionLabel><h1>Links, IPs, and <span>email traces.</span></h1><p>Every external check needs analyst approval. IPs can use AbuseIPDB or VirusTotal; extracted URLs can be matched against PhishTank's permitted public feed.</p></div><span className="time-chip"><Database size={15} /> {iocs.isLoading ? "Loading" : `${iocs.data?.length || 0} saved`}</span></div>{iocs.data?.length ? <><section className="panel"><div className="panel-header"><div><span>ALL SAVED INDICATORS</span><h2>Private extracted data</h2></div></div><div className="simple-record-list">{iocs.data.map((ioc) => <div key={ioc.id}><SeverityBadge value={ioc.type} /><strong>{ioc.value}</strong><span>{ioc.source} · {new Date(ioc.createdAt).toLocaleString()}</span></div>)}</div></section><section className="panel" style={{ marginTop: 14 }}><div className="panel-header"><div><span>SELECT CASE</span><h2>Local risk and comparison</h2></div></div><div className="simple-record-list">{cases.data?.map((item) => <button key={item.id} onClick={() => setSelectedId(item.id)}><SeverityBadge value={item.severity} /><strong>{item.caseNumber}</strong><span>{item.title}</span></button>)}</div></section>{detail.data && <div className="dashboard-main-grid" style={{ marginTop: 14 }}><section className="panel"><div className="panel-header"><div><span>LOCAL RISK SIGNALS</span><h2>{detail.data.investigation.caseNumber}</h2></div></div>{findings.length ? <div className="simple-record-list">{findings.map((finding, index) => <div key={`${finding.kind}-${finding.value}-${index}`}><SeverityBadge value={finding.severity} /><strong>{finding.kind === "url" ? "Link review" : "Attachment review"}</strong><span>{finding.value} · {finding.detail}</span></div>)}</div> : <EmptyData icon={ShieldCheck} title="No local risk signal found" copy="This case may still contain indicators. No URL or attachment pattern matched the local rule set." compact />}</section><section className="panel"><div className="panel-header"><div><span>SIMILAR SAVED CASES</span><h2>Shared evidence patterns</h2></div></div>{similar.data?.length ? <div className="simple-record-list">{similar.data.map((item) => <div key={item.id}><SeverityBadge value={item.severity} /><strong>{item.caseNumber} · {item.matches.length} shared signal{item.matches.length === 1 ? "" : "s"}</strong><span>{item.matches.map((match) => `${match.type}: ${match.value}`).join("; ")}</span></div>)}</div> : <EmptyData icon={Network} title="No similar saved case" copy="A match appears only when another case in your account shares an extracted URL, domain, IP, or email indicator." compact />}</section><ReputationEvidencePanel provider="AbuseIPDB" result={abuse} sourceIp={sourceIp} busy={enrichAbuse.isPending} approve={() => enrichAbuse.mutate({ investigationId: detail.data.investigation.id })} /><ReputationEvidencePanel provider="VirusTotal" result={virusTotal} sourceIp={sourceIp} busy={enrichVirusTotal.isPending} approve={() => enrichVirusTotal.mutate({ investigationId: detail.data.investigation.id })} /><PhishTankEvidencePanel entries={detail.data.urlReputations || []} urls={urls} busy={enrichPhishTank.isPending} approve={(url) => enrichPhishTank.mutate({ investigationId: detail.data.investigation.id, url })} /></div>}</> : <section className="panel empty-panel"><EmptyData icon={Radar} title="No indicators yet" copy="Upload and check an .eml file to extract your first URLs, domains, IPs, email addresses, and evidence hash." /></section>}</div>;
}

function GeolocationViewLegacy() {
  const locations = trpc.analysis.locations.useQuery();
  const cases = trpc.analysis.list.useQuery();
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const activeId = selectedId || cases.data?.[0]?.id;
  const detail = trpc.analysis.detail.useQuery({ investigationId: activeId || 0 }, { enabled: Boolean(activeId) });
  const utils = trpc.useUtils();
  const enrich = trpc.analysis.enrichLocation.useMutation({ onSuccess: () => { utils.analysis.locations.invalidate(); utils.analysis.detail.invalidate(); toast.success("Approximate source-IP location was saved for this private case."); }, onError: (error) => toast.error(error.message) });
  const savedLocations = locations.data || [];
  const mapKey = savedLocations.map((location) => location.id).join("-") || "empty";
  const onMapReady = useCallback((map: google.maps.Map) => {
    const maps = window.google?.maps;
    if (!maps || !savedLocations.length) return;
    const bounds = new maps.LatLngBounds();
    const points: google.maps.LatLng[] = [];
    savedLocations.forEach((location) => {
      if (location.latitude === null || location.longitude === null) return;
      const point = new maps.LatLng(location.latitude, location.longitude);
      points.push(point); bounds.extend(point);
      new maps.marker.AdvancedMarkerElement({ map, position: point, title: `${location.ip} · ${[location.city, location.region, location.country].filter(Boolean).join(", ") || "Approximate location"}` });
    });
    if (points.length > 1) map.fitBounds(bounds, 52); else if (points[0]) map.setCenter(points[0]);
    const visualization = (maps as typeof maps & { visualization?: { HeatmapLayer: new (options: { data: google.maps.LatLng[]; radius?: number }) => { setMap: (target: google.maps.Map) => void } } }).visualization;
    if (points.length > 1 && visualization?.HeatmapLayer) new visualization.HeatmapLayer({ data: points, radius: 30 }).setMap(map);
  }, [savedLocations]);
  const sourceIp = detail.data?.artifact?.originatingIp;
  return <div className="page-content geolocation-view"><div className="page-title-row"><div><SectionLabel>Location map</SectionLabel><h1>Where alerts <span>may come from.</span></h1><p>Location is approximate and is added only after you approve a lookup for a stored public source IP. This is not device tracking.</p></div><span className="time-chip"><MapPin size={15} /> {savedLocations.length ? `${savedLocations.length} saved` : "No locations"}</span></div>{cases.data?.length ? <section className="panel"><div className="panel-header"><div><span>APPROVE A LOOKUP</span><h2>Choose a private case</h2></div></div><div className="simple-record-list">{cases.data.map((item) => <button key={item.id} onClick={() => setSelectedId(item.id)}><SeverityBadge value={item.severity} /><strong>{item.caseNumber}</strong><span>{item.title}</span></button>)}</div>{detail.data && <div className="analysis-pending"><strong>{sourceIp ? `Extracted source IP: ${sourceIp}` : "No source IP was extracted from this case."}</strong><p>When you approve, only this public IP is sent to ipwho.is for an approximate country, region, city, and map coordinate. The result stays in this private workspace.</p><Button className="outline-cta" disabled={!sourceIp || enrich.isPending} onClick={() => enrich.mutate({ investigationId: detail.data.investigation.id })}><MapPin size={15} /> {enrich.isPending ? "Looking up…" : "Approve location lookup"}</Button></div>}</section> : <section className="panel empty-panel"><EmptyData icon={MapPin} title="No case with an IP yet" copy="Check an .eml email first. A location lookup becomes available only when a source IP is extracted." /></section>}{savedLocations.length ? <section className="panel" style={{ marginTop: 14 }}><div className="panel-header"><div><span>PRIVATE THREAT MAP</span><h2>Saved approximate source locations</h2></div></div><MapView key={mapKey} className="w-full h-[390px]" initialCenter={{ lat: savedLocations[0].latitude || 0, lng: savedLocations[0].longitude || 0 }} initialZoom={savedLocations.length > 1 ? 2 : 5} onMapReady={onMapReady} /><div className="simple-record-list">{savedLocations.map((location) => <div key={location.id}><MapPin size={15} /><strong>{location.ip}</strong><span>{[location.city, location.region, location.country].filter(Boolean).join(", ") || "Approximate location not named"} · {new Date(location.enrichedAt).toLocaleString()}</span></div>)}</div></section> : null}</div>;
}

function GeolocationCaseFlow() {
  const cases = trpc.analysis.list.useQuery();
  const locations = trpc.analysis.locations.useQuery();
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const activeId = selectedId || cases.data?.[0]?.id;
  const detail = trpc.analysis.detail.useQuery({ investigationId: activeId || 0 }, { enabled: Boolean(activeId) });
  const utils = trpc.useUtils();
  const enrich = trpc.analysis.enrichLocation.useMutation({ onSuccess: () => { utils.analysis.locations.invalidate(); utils.analysis.detail.invalidate(); toast.success("Approximate source location saved to this private case."); }, onError: (error) => toast.error(error.message) });
  const saved = locations.data || [];
  const extractedSourceIp = detail.data?.artifact?.originatingIp;
  const sourceIp = isExternallyEnrichableIpv4(extractedSourceIp) ? extractedSourceIp : null;
  const onMapReady = useCallback((map: google.maps.Map) => {
    const maps = window.google?.maps;
    if (!maps || !saved.length) return;
    const bounds = new maps.LatLngBounds();
    const points: google.maps.LatLng[] = [];
    saved.forEach((item) => { if (item.latitude === null || item.longitude === null) return; const point = new maps.LatLng(item.latitude, item.longitude); points.push(point); bounds.extend(point); new maps.marker.AdvancedMarkerElement({ map, position: point, title: `${item.ip} · ${[item.city, item.region, item.country].filter(Boolean).join(", ") || "Approximate location"}` }); });
    if (points.length > 1) map.fitBounds(bounds, 52); else if (points[0]) map.setCenter(points[0]);
    const visualization = (maps as typeof maps & { visualization?: { HeatmapLayer: new (options: { data: google.maps.LatLng[]; radius?: number }) => { setMap: (target: google.maps.Map) => void } } }).visualization;
    if (points.length > 1 && visualization?.HeatmapLayer) new visualization.HeatmapLayer({ data: points, radius: 30 }).setMap(map);
  }, [saved]);
  return <div className="page-content geolocation-view"><div className="page-title-row"><div><SectionLabel>Location map</SectionLabel><h1>Where alerts <span>may come from.</span></h1><p>Use a completed case with an extracted public source IP. Location is approximate and is never device tracking.</p></div><span className="time-chip"><MapPin size={15} /> {saved.length ? `${saved.length} saved` : "Step 1: choose a case"}</span></div>{!cases.data?.length ? <section className="panel empty-panel"><EmptyData icon={MapPin} title="Create a case before opening the map" copy="Step 1: check an .eml email. Step 2: return here and choose that private case. Step 3: approve an approximate location lookup only if a public source IP was extracted." /></section> : <><section className="panel"><div className="panel-header"><div><span>STEP 1 — SELECT A CASE</span><h2>Choose private evidence</h2></div></div><div className="simple-record-list">{cases.data.map((item) => <button key={item.id} onClick={() => setSelectedId(item.id)}><SeverityBadge value={item.severity} /><strong>{item.caseNumber}</strong><span>{item.title}</span></button>)}</div>{detail.data && <div className="analysis-pending"><strong>{sourceIp ? `Step 2 — extracted source IP: ${sourceIp}` : "No usable public source IP was extracted from this case."}</strong><p>{sourceIp ? "Step 3 — approve this lookup to send only the public IP to ipwho.is. The approximate country, region, city, and map coordinate stay in your private workspace." : "The map cannot run without a source IP found in the uploaded email headers. Private, loopback, and link-local IPs are blocked before any lookup."}</p><Button className="outline-cta" disabled={!sourceIp || enrich.isPending} onClick={() => enrich.mutate({ investigationId: detail.data.investigation.id })}><MapPin size={15} /> {enrich.isPending ? "Looking up…" : "Approve location lookup"}</Button></div>}</section>{saved.length ? <section className="panel" style={{ marginTop: 14 }}><div className="panel-header"><div><span>PRIVATE THREAT MAP</span><h2>Approved approximate locations</h2></div></div><MapView className="w-full h-[390px]" initialCenter={{ lat: saved[0].latitude || 0, lng: saved[0].longitude || 0 }} initialZoom={saved.length > 1 ? 2 : 5} onMapReady={onMapReady} /><div className="simple-record-list">{saved.map((item) => <div key={item.id}><MapPin size={15} /><strong>{item.ip}</strong><span>{[item.city, item.region, item.country].filter(Boolean).join(", ") || "Approximate location not named"} · {new Date(item.enrichedAt).toLocaleString()}</span></div>)}</div></section> : null}</>}</div>;
}

function ForensicsView({ selectedInvestigationId, selectInvestigation }: { selectedInvestigationId: number | null; selectInvestigation: (id: number) => void }) { const cases = trpc.analysis.list.useQuery(); const activeId = selectedInvestigationId || cases.data?.[0]?.id; const detail = trpc.analysis.detail.useQuery({ investigationId: activeId || 0 }, { enabled: Boolean(activeId) }); const [note, setNote] = useState(""); const utils = trpc.useUtils(); const addNote = trpc.analysis.addNote.useMutation({ onSuccess: () => { setNote(""); utils.analysis.detail.invalidate(); toast.success("Analyst note saved."); }, onError: (error) => toast.error(error.message) }); const updateStatus = trpc.analysis.updateStatus.useMutation({ onSuccess: () => { utils.analysis.detail.invalidate(); utils.analysis.list.invalidate(); utils.analysis.dashboard.invalidate(); toast.success("Case status updated."); }, onError: (error) => toast.error(error.message) }); if (!cases.data?.length && !cases.isLoading) return <div className="page-content forensics-view"><div className="page-title-row"><div><SectionLabel>Case details</SectionLabel><h1>What we <span>found.</span></h1><p>Your private evidence, IOCs, timeline, and notes will appear after your first completed .eml check.</p></div><span className="time-chip"><BriefcaseBusiness size={15} /> No case selected</span></div><section className="panel empty-panel"><EmptyData icon={FileSearch} title="No case data yet" copy="Check an .eml email to create a real private case. No example evidence is shown." /></section></div>; const data = detail.data; return <div className="page-content forensics-view"><div className="page-title-row"><div><SectionLabel>Case details</SectionLabel><h1>What we <span>found.</span></h1><p>Evidence and notes shown here belong to your signed-in account.</p></div><span className="time-chip"><BriefcaseBusiness size={15} /> {data?.investigation.caseNumber || "Loading case"}</span></div><section className="panel"><div className="panel-header"><div><span>YOUR CASES</span><h2>Choose a saved analysis</h2></div></div><div className="simple-record-list">{cases.data?.map((item) => <button key={item.id} onClick={() => selectInvestigation(item.id)}><SeverityBadge value={item.severity} /><strong>{item.caseNumber}</strong><span>{item.title} · score {item.threatScore}/100</span></button>)}</div></section>{data && <><section className="panel"><div className="panel-header"><div><span>CASE SUMMARY</span><h2>{data.investigation.title}</h2></div><SeverityBadge value={data.investigation.severity} /></div><p className="analysis-pending"><strong>Score {data.investigation.threatScore}/100 · {data.investigation.confidence}% confidence</strong><br />{data.investigation.summary}</p><label className="case-status-control">Case status <select value={data.investigation.status} onChange={(event) => updateStatus.mutate({ investigationId: data.investigation.id, status: event.target.value as "open" | "in_progress" | "resolved" | "closed" })} disabled={updateStatus.isPending}><option value="open">Open</option><option value="in_progress">In progress</option><option value="resolved">Resolved</option><option value="closed">Closed</option></select></label></section><div className="dashboard-main-grid"><section className="panel"><div className="panel-header"><div><span>EVIDENCE</span><h2>Saved email</h2></div></div><div className="simple-record-list"><div><strong>{data.artifact?.originalFilename || "Email evidence"}</strong><span>SHA-256: {data.artifact?.sha256 || "Unavailable"}</span><span>From: {data.artifact?.sender || "Unavailable"}</span><span>To: {data.artifact?.recipient || "Unavailable"}</span><span>SPF {data.artifact?.spf} · DKIM {data.artifact?.dkim} · DMARC {data.artifact?.dmarc}</span></div></div></section><section className="panel"><div className="panel-header"><div><span>AI CONTENT REVIEW</span><h2>Bounded assessment</h2></div></div>{data.artifact?.aiCategory ? <div className="simple-record-list"><div><SeverityBadge value={data.artifact.aiCategory} /><strong>{data.artifact.aiCategory.replace(/_/g, " ")} · model {data.artifact.aiModel}</strong><span>{data.artifact.aiSummary}</span><span>Social engineering: {data.artifact.aiSocialEngineering || "No pattern stated."}</span><span>Recommended next steps: {data.artifact.aiRecommendationsJson ? JSON.parse(data.artifact.aiRecommendationsJson).join("; ") : "Review the saved evidence."}</span></div></div> : <EmptyData icon={Bot} title="No AI assessment saved" copy="The email can still be reviewed with structural evidence. The bounded content service may have been unavailable for this case." compact />}</section><section className="panel"><div className="panel-header"><div><span>EXTRACTED IOCs</span><h2>Indicators</h2></div></div>{data.iocs.length ? <div className="simple-record-list">{data.iocs.map((ioc) => <div key={ioc.id}><SeverityBadge value={ioc.type} /><strong>{ioc.value}</strong><span>{ioc.source}</span></div>)}</div> : <EmptyData icon={Radar} title="No indicators found" copy="This email did not contain an extractable IP, link, domain, email address, or hash." compact />}</section><section className="panel"><div className="panel-header"><div><span>CASE TIMELINE</span><h2>Recorded events</h2></div></div><div className="simple-record-list">{data.events.map((event) => <div key={event.id}><Clock3 size={15} /><strong>{event.eventType.replace(/_/g, " ")}</strong><span>{event.detail} · {new Date(event.createdAt).toLocaleString()}</span></div>)}</div></section><section className="panel"><div className="panel-header"><div><span>ANALYST NOTES</span><h2>Private notes</h2></div></div><form className="case-note-form" onSubmit={(event) => { event.preventDefault(); if (note.trim()) addNote.mutate({ investigationId: data.investigation.id, content: note.trim() }); }}><textarea value={note} onChange={(event) => setNote(event.target.value)} placeholder="Add a short private note for this case…" maxLength={5000} /><Button disabled={addNote.isPending || !note.trim()} className="outline-cta">{addNote.isPending ? "Saving…" : "Save note"}</Button></form>{data.notes.length ? <div className="simple-record-list">{data.notes.map((entry) => <div key={entry.id}><MessageSquareText size={15} /><strong>Analyst note</strong><span>{entry.content} · {new Date(entry.createdAt).toLocaleString()}</span></div>)}</div> : <EmptyData icon={MessageSquareText} title="No notes yet" copy="Add a private note to record your review." compact />}</section></div></>}</div>; }

function ForensicsViewWithAiRetry({ selectedInvestigationId, selectInvestigation }: { selectedInvestigationId: number | null; selectInvestigation: (id: number) => void }) {
  const cases = trpc.analysis.list.useQuery();
  const activeId = selectedInvestigationId || cases.data?.[0]?.id;
  const detail = trpc.analysis.detail.useQuery({ investigationId: activeId || 0 }, { enabled: Boolean(activeId) });
  const utils = trpc.useUtils();
  const [note, setNote] = useState("");
  const refreshCase = () => { utils.analysis.detail.invalidate(); utils.analysis.list.invalidate(); utils.analysis.dashboard.invalidate(); };
  const addNote = trpc.analysis.addNote.useMutation({ onSuccess: () => { setNote(""); refreshCase(); toast.success("Analyst note saved."); }, onError: (error) => toast.error(error.message) });
  const updateStatus = trpc.analysis.updateStatus.useMutation({ onSuccess: () => { refreshCase(); toast.success("Case status updated."); }, onError: (error) => toast.error(error.message) });
  const reviewAi = trpc.analysis.reviewAi.useMutation({ onSuccess: () => { refreshCase(); toast.success("Bounded AI assessment saved to this case."); }, onError: (error) => toast.error(error.message) });
  if (!cases.data?.length && !cases.isLoading) return <div className="page-content forensics-view"><div className="page-title-row"><div><SectionLabel>Case details</SectionLabel><h1>What we <span>found.</span></h1><p>Your private evidence, IOCs, timeline, and notes will appear after your first completed .eml check.</p></div><span className="time-chip"><BriefcaseBusiness size={15} /> No case selected</span></div><section className="panel empty-panel"><EmptyData icon={FileSearch} title="No case data yet" copy="Check an .eml email to create a real private case. No example evidence is shown." /></section></div>;
  const data = detail.data;
  return <div className="page-content forensics-view"><div className="page-title-row"><div><SectionLabel>Case details</SectionLabel><h1>What we <span>found.</span></h1><p>Evidence and notes shown here belong to your signed-in account.</p></div><span className="time-chip"><BriefcaseBusiness size={15} /> {data?.investigation.caseNumber || "Loading case"}</span></div><section className="panel"><div className="panel-header"><div><span>YOUR CASES</span><h2>Choose a saved analysis</h2></div></div><div className="simple-record-list">{cases.data?.map((item) => <button key={item.id} onClick={() => selectInvestigation(item.id)}><SeverityBadge value={item.severity} /><strong>{item.caseNumber}</strong><span>{item.title} · score {item.threatScore}/100</span></button>)}</div></section>{data && <><section className="panel"><div className="panel-header"><div><span>CASE SUMMARY</span><h2>{data.investigation.title}</h2></div><SeverityBadge value={data.investigation.severity} /></div><p className="analysis-pending"><strong>Score {data.investigation.threatScore}/100 · {data.investigation.confidence}% confidence</strong><br />{data.investigation.summary}</p><label className="case-status-control">Case status <select value={data.investigation.status} onChange={(event) => updateStatus.mutate({ investigationId: data.investigation.id, status: event.target.value as "open" | "in_progress" | "resolved" | "closed" })} disabled={updateStatus.isPending}><option value="open">Open</option><option value="in_progress">In progress</option><option value="resolved">Resolved</option><option value="closed">Closed</option></select></label></section><div className="dashboard-main-grid"><section className="panel"><div className="panel-header"><div><span>EVIDENCE</span><h2>Saved email</h2></div></div><div className="simple-record-list"><div><strong>{data.artifact?.originalFilename || "Email evidence"}</strong><span>SHA-256: {data.artifact?.sha256 || "Unavailable"}</span><span>From: {data.artifact?.sender || "Unavailable"}</span><span>To: {data.artifact?.recipient || "Unavailable"}</span><span>SPF {data.artifact?.spf} · DKIM {data.artifact?.dkim} · DMARC {data.artifact?.dmarc}</span></div></div></section><section className="panel"><div className="panel-header"><div><span>AI CONTENT REVIEW</span><h2>Bounded assessment</h2></div></div>{data.artifact?.aiCategory ? <div className="simple-record-list"><div><SeverityBadge value={data.artifact.aiCategory} /><strong>{data.artifact.aiCategory.replace(/_/g, " ")} · model {data.artifact.aiModel}</strong><span>{data.artifact.aiSummary}</span><span>Social engineering: {data.artifact.aiSocialEngineering || "No pattern stated."}</span><span>Recommended next steps: {data.artifact.aiRecommendationsJson ? JSON.parse(data.artifact.aiRecommendationsJson).join("; ") : "Review the saved evidence."}</span></div></div> : <div className="simple-record-list"><div><Bot size={15} /><strong>No AI assessment saved</strong><span>The email can still be reviewed with structural evidence. You can retry the bounded review without uploading the evidence again.</span><Button className="outline-cta" onClick={() => reviewAi.mutate({ investigationId: data.investigation.id })} disabled={reviewAi.isPending}>{reviewAi.isPending ? "Reviewing…" : "Run bounded AI review"}</Button></div></div>}</section><section className="panel"><div className="panel-header"><div><span>EXTRACTED IOCs</span><h2>Indicators</h2></div></div>{data.iocs.length ? <div className="simple-record-list">{data.iocs.map((ioc) => <div key={ioc.id}><SeverityBadge value={ioc.type} /><strong>{ioc.value}</strong><span>{ioc.source}</span></div>)}</div> : <EmptyData icon={Radar} title="No indicators found" copy="This email did not contain an extractable IP, link, domain, email address, or hash." compact />}</section><section className="panel"><div className="panel-header"><div><span>CASE TIMELINE</span><h2>Recorded events</h2></div></div><div className="simple-record-list">{data.events.map((event) => <div key={event.id}><Clock3 size={15} /><strong>{event.eventType.replace(/_/g, " ")}</strong><span>{event.detail} · {new Date(event.createdAt).toLocaleString()}</span></div>)}</div></section><section className="panel"><div className="panel-header"><div><span>ANALYST NOTES</span><h2>Private notes</h2></div></div><form className="case-note-form" onSubmit={(event) => { event.preventDefault(); if (note.trim()) addNote.mutate({ investigationId: data.investigation.id, content: note.trim() }); }}><textarea value={note} onChange={(event) => setNote(event.target.value)} placeholder="Add a short private note for this case…" maxLength={5000} /><Button disabled={addNote.isPending || !note.trim()} className="outline-cta">{addNote.isPending ? "Saving…" : "Save note"}</Button></form>{data.notes.length ? <div className="simple-record-list">{data.notes.map((entry) => <div key={entry.id}><MessageSquareText size={15} /><strong>Analyst note</strong><span>{entry.content} · {new Date(entry.createdAt).toLocaleString()}</span></div>)}</div> : <EmptyData icon={MessageSquareText} title="No notes yet" copy="Add a private note to record your review." compact />}</section></div></>}</div>;
}

function AssistantView() { return <div className="page-content assistant-view"><div className="assistant-heading"><div className="assistant-orb"><Bot size={32} /></div><SectionLabel>AI guide</SectionLabel><h1>Get help<br /><span>finding a page.</span></h1><p>Use the AI Guide button in the top bar. It can explain the website and open approved pages, but cannot access files, data, accounts, or settings.</p></div><section className="panel empty-panel"><EmptyData icon={Bot} title="Open the AI Guide from the top bar" copy="The guide is separate from case data. It can only answer website navigation questions and move you to approved screens." /></section></div>; }

function ReportsView() { const cases = trpc.analysis.list.useQuery(); const [selectedId, setSelectedId] = useState<number | null>(null); const activeId = selectedId || cases.data?.[0]?.id; const detail = trpc.analysis.detail.useQuery({ investigationId: activeId || 0 }, { enabled: Boolean(activeId) }); const exportReport = (format: "csv" | "pdf") => { if (!detail.data) return; if (format === "csv") downloadCaseCsv(detail.data); else downloadCasePdf(detail.data); toast.success(`${format.toUpperCase()} report downloaded from saved case evidence.`); }; if (!cases.data?.length && !cases.isLoading) return <div className="page-content reports-view"><div className="page-title-row"><div><SectionLabel>Reports</SectionLabel><h1>Share a <span>clear result.</span></h1><p>Reports use only a completed case and its saved evidence.</p></div><span className="time-chip"><FileText size={15} /> No reports</span></div><section className="panel empty-panel"><EmptyData icon={FileText} title="No reports yet" copy="Check an .eml email first. You can then create a real CSV or PDF report from that private case." /></section></div>; return <div className="page-content reports-view"><div className="page-title-row"><div><SectionLabel>Reports</SectionLabel><h1>Share a <span>clear result.</span></h1><p>Export a real CSV or PDF from one of your saved private cases. No example reports are created.</p></div><span className="time-chip"><FileText size={15} /> {cases.data?.length || 0} cases</span></div><section className="panel"><div className="panel-header"><div><span>SELECT CASE</span><h2>Saved investigation evidence</h2></div></div><div className="simple-record-list">{cases.data?.map((item) => <button onClick={() => setSelectedId(item.id)} key={item.id}><SeverityBadge value={item.severity} /><strong>{item.caseNumber}</strong><span>{item.title} · score {item.threatScore}/100</span></button>)}</div></section>{detail.data && <section className="panel" style={{ marginTop: 14 }}><div className="panel-header"><div><span>EXPORT READY</span><h2>{detail.data.investigation.caseNumber}</h2></div><SeverityBadge value={detail.data.investigation.severity} /></div><div className="simple-record-list"><div><FileText size={17} /><strong>{detail.data.investigation.title}</strong><span>Includes saved score, evidence metadata, AI review when present, IOCs, timeline, and analyst notes.</span><Button onClick={() => exportReport("csv")} className="outline-cta"><Download size={15} /> CSV</Button><Button onClick={() => exportReport("pdf")} className="outline-cta"><Download size={15} /> PDF</Button></div></div></section>}</div>; }

function SettingsViewLegacy() {
  const { user } = useAuth();
  const team = trpc.admin.users.useQuery(undefined, { enabled: user?.role === "admin" });
  const utils = trpc.useUtils();
  const updateRole = trpc.admin.updateUserRole.useMutation({ onSuccess: () => { utils.admin.users.invalidate(); toast.success("User role updated."); }, onError: (error) => toast.error(error.message) });
  return <div className="page-content settings-view"><div className="page-title-row"><div><SectionLabel>Settings</SectionLabel><h1>Website <span>settings.</span></h1><p>Review real signed-in access and the live safety services that still need approved integrations.</p></div><span className="time-chip"><Database size={15} /> {user?.role === "admin" ? "Administrator" : "Analyst access"}</span></div><div className="settings-grid"><section className="panel settings-panel"><div className="panel-header"><div><span>TEAM ACCESS</span><h2>Signed-in users and roles</h2></div><ShieldCheck size={18} /></div>{user?.role === "admin" ? team.data?.length ? <div className="simple-record-list">{team.data.map((member) => <div key={member.id}><BriefcaseBusiness size={15} /><strong>{member.name || member.email || `User ${member.id}`}</strong><span>{member.email || "No email shared"} · last sign-in {new Date(member.lastSignedIn).toLocaleString()}</span><label className="case-status-control">Role <select value={member.role} disabled={updateRole.isPending || member.id === user.id} onChange={(event) => updateRole.mutate({ userId: member.id, role: event.target.value as "user" | "admin" })}><option value="user">User</option><option value="admin">Administrator</option></select></label></div>)}</div> : <EmptyData icon={BriefcaseBusiness} title="No signed-in users yet" copy="A user appears here after completing secure sign-in." compact /> : <EmptyData icon={ShieldCheck} title="Administrator access required" copy="Your account can use the protected workspace. Only administrators can view the team list or change roles." compact />}</section><section className="panel settings-panel"><div className="panel-header"><div><span>DATA SOURCES</span><h2>Reputation, location, and alerts</h2></div><Network size={18} /></div><div className="policy-grid"><p><i>01</i><span><strong>Approximate IP location</strong>Available only after an analyst approves a lookup for a stored public source IP. Private addresses are blocked.</span><b>READY</b></p><p><i>02</i><span><strong>Live threat reputation</strong>AbuseIPDB, VirusTotal, and PhishTank are not connected. They require approved credentials and service terms.</span><b>WAITING</b></p><p><i>03</i><span><strong>High-risk owner alerts</strong>A notification is attempted when a completed check scores 60 or higher. Its delivery result is recorded in that case timeline.</span><b>READY</b></p></div></section><section className="panel settings-panel settings-panel--wide"><div className="panel-header"><div><span>SAFETY RULES</span><h2>Data handling</h2></div><ShieldCheck size={18} /></div><div className="policy-grid"><p><i>01</i><span><strong>Do not show made-up results</strong>Only completed checks from uploaded evidence can appear in the workspace.</span><b>ON</b></p><p><i>02</i><span><strong>Secure evidence upload</strong>An .eml file is uploaded only when a signed-in analyst starts a check, then stored as private evidence.</span><b>ON</b></p><p><i>03</i><span><strong>Keep the AI Guide limited</strong>The Guide can explain pages and open approved screens only. It cannot access or change case data.</span><b>ON</b></p></div></section></div></div>;
}

function SettingsViewWithPhishTankPending() {
  const { user } = useAuth();
  const team = trpc.admin.users.useQuery(undefined, { enabled: user?.role === "admin" });
  const utils = trpc.useUtils();
  const updateRole = trpc.admin.updateUserRole.useMutation({ onSuccess: () => { utils.admin.users.invalidate(); toast.success("User role updated."); }, onError: (error) => toast.error(error.message) });
  return <div className="page-content settings-view"><div className="page-title-row"><div><SectionLabel>Settings</SectionLabel><h1>Website <span>settings.</span></h1><p>Review signed-in access and which analyst-approved safety services are ready.</p></div><span className="time-chip"><Database size={15} /> {user?.role === "admin" ? "Administrator" : "Analyst access"}</span></div><div className="settings-grid"><section className="panel settings-panel"><div className="panel-header"><div><span>TEAM ACCESS</span><h2>Signed-in users and roles</h2></div><ShieldCheck size={18} /></div>{user?.role === "admin" ? team.data?.length ? <div className="simple-record-list">{team.data.map((member) => <div key={member.id}><BriefcaseBusiness size={15} /><strong>{member.name || member.email || `User ${member.id}`}</strong><span>{member.email || "No email shared"} · last sign-in {new Date(member.lastSignedIn).toLocaleString()}</span><label className="case-status-control">Role <select value={member.role} disabled={updateRole.isPending || member.id === user.id} onChange={(event) => updateRole.mutate({ userId: member.id, role: event.target.value as "user" | "admin" })}><option value="user">User</option><option value="admin">Administrator</option></select></label></div>)}</div> : <EmptyData icon={BriefcaseBusiness} title="No signed-in users yet" copy="A user appears here after completing secure sign-in." compact /> : <EmptyData icon={ShieldCheck} title="Administrator access required" copy="Only administrators can view the team list or change roles." compact />}</section><section className="panel settings-panel"><div className="panel-header"><div><span>DATA SOURCES</span><h2>Approved provider checks</h2></div><Network size={18} /></div><div className="policy-grid"><p><i>01</i><span><strong>Approximate IP location</strong>Ready after an analyst approves a stored public source-IP lookup. Private addresses are blocked.</span><b>READY</b></p><p><i>02</i><span><strong>AbuseIPDB and VirusTotal</strong>Ready for separate analyst-approved public-IP reputation checks. Results stay with the private case and its timeline.</span><b>READY</b></p><p><i>03</i><span><strong>PhishTank</strong>Not connected yet because an approved provider credential or data-feed access has not been supplied.</span><b>WAITING</b></p><p><i>04</i><span><strong>High-risk owner alerts</strong>A notification is attempted when a completed check scores 60 or higher. Its delivery result is recorded in the case timeline.</span><b>READY</b></p></div></section><section className="panel settings-panel settings-panel--wide"><div className="panel-header"><div><span>SAFETY RULES</span><h2>Data handling</h2></div><ShieldCheck size={18} /></div><div className="policy-grid"><p><i>01</i><span><strong>Do not show made-up results</strong>Only completed checks from uploaded evidence appear in the workspace.</span><b>ON</b></p><p><i>02</i><span><strong>Secure evidence upload</strong>An .eml file is uploaded only when a signed-in analyst starts a check, then stored as private evidence.</span><b>ON</b></p><p><i>03</i><span><strong>Keep the AI Guide limited</strong>The Guide can explain pages and open approved screens only. It cannot access or change case data.</span><b>ON</b></p></div></section></div></div>;
}

function SettingsView() {
  const { user } = useAuth();
  const team = trpc.admin.users.useQuery(undefined, { enabled: user?.role === "admin" });
  const utils = trpc.useUtils();
  const updateRole = trpc.admin.updateUserRole.useMutation({ onSuccess: () => { utils.admin.users.invalidate(); toast.success("User role updated."); }, onError: (error) => toast.error(error.message) });
  return <div className="page-content settings-view"><div className="page-title-row"><div><SectionLabel>Settings</SectionLabel><h1>Website <span>settings.</span></h1><p>Review signed-in access and analyst-approved data services.</p></div><span className="time-chip"><Database size={15} /> {user?.role === "admin" ? "Administrator" : "Analyst access"}</span></div><div className="settings-grid"><section className="panel settings-panel"><div className="panel-header"><div><span>TEAM ACCESS</span><h2>Signed-in users and roles</h2></div><ShieldCheck size={18} /></div>{user?.role === "admin" ? team.data?.length ? <div className="simple-record-list">{team.data.map((member) => <div key={member.id}><BriefcaseBusiness size={15} /><strong>{member.name || member.email || `User ${member.id}`}</strong><span>{member.email || "No email shared"} · last sign-in {new Date(member.lastSignedIn).toLocaleString()}</span><label className="case-status-control">Role <select value={member.role} disabled={updateRole.isPending || member.id === user.id} onChange={(event) => updateRole.mutate({ userId: member.id, role: event.target.value as "user" | "admin" })}><option value="user">User</option><option value="admin">Administrator</option></select></label></div>)}</div> : <EmptyData icon={BriefcaseBusiness} title="No signed-in users yet" copy="A user appears here after completing secure sign-in." compact /> : <EmptyData icon={ShieldCheck} title="Administrator access required" copy="Only administrators can view the team list or change roles." compact />}</section><section className="panel settings-panel"><div className="panel-header"><div><span>DATA SOURCES</span><h2>Approved provider checks</h2></div><Network size={18} /></div><div className="policy-grid"><p><i>01</i><span><strong>Approximate IP location</strong>Ready after an analyst approves a stored public source-IP lookup. Private addresses are blocked.</span><b>READY</b></p><p><i>02</i><span><strong>AbuseIPDB and VirusTotal</strong>Ready for separate analyst-approved public-IP reputation checks. Results stay with the private case and its timeline.</span><b>READY</b></p><p><i>03</i><span><strong>PhishTank public feed</strong>Ready for analyst-approved checks of extracted URLs against the verified-online HTTPS feed. A four-hour server cache limits downloads without an API key.</span><b>READY</b></p><p><i>04</i><span><strong>High-risk owner alerts</strong>A notification is attempted when a completed check scores 60 or higher. Its delivery result is recorded in the case timeline.</span><b>READY</b></p></div></section><section className="panel settings-panel settings-panel--wide"><div className="panel-header"><div><span>SAFETY RULES</span><h2>Data handling</h2></div><ShieldCheck size={18} /></div><div className="policy-grid"><p><i>01</i><span><strong>Do not show made-up results</strong>Only completed checks from uploaded evidence appear in the workspace.</span><b>ON</b></p><p><i>02</i><span><strong>Secure evidence upload</strong>An .eml file is uploaded only when a signed-in analyst starts a check, then stored as private evidence.</span><b>ON</b></p><p><i>03</i><span><strong>Keep the AI Guide limited</strong>The Guide can explain pages and open approved screens only. It cannot access or change case data.</span><b>ON</b></p></div></section></div></div>;
}

function RequirementsView({ navigate }: { navigate: (view: View) => void }) {
  const [filter, setFilter] = useState<"all" | RequirementStatus>("all");
  const visibleItems = useMemo(() => filter === "all" ? requirementChecklist : requirementChecklist.filter((item) => item.status === filter), [filter]);
  const counts = useMemo(() => requirementChecklist.reduce<Record<RequirementStatus, number>>((total, item) => { total[item.status] += 1; return total; }, { available: 0, waiting: 0, missing: 0 }), []);
  const filterButtons: Array<{ id: "all" | RequirementStatus; label: string; count: number }> = [{ id: "all", label: "All items", count: requirementChecklist.length }, { id: "available", label: "Available", count: counts.available }, { id: "waiting", label: "Needs live data", count: counts.waiting }, { id: "missing", label: "Missing", count: counts.missing }];
  const statusLabels: Record<RequirementStatus, string> = { available: "Available", waiting: "Needs connection", missing: "Not built" };
  return <div className="page-content requirements-view"><div className="page-title-row"><div><SectionLabel>SIH26106 checklist</SectionLabel><h1>Required <span>features.</span></h1><p>This checklist compares the uploaded project requirements with this version of the website. It shows what is ready, what needs real data, and what still needs to be built.</p></div><span className="time-chip"><ListFilter size={15} /> {counts.missing} not built</span></div><section className="requirements-summary"><article><Check size={18} /><span>AVAILABLE</span><strong>{counts.available}</strong><p>Available in this website</p></article><article><Database size={18} /><span>NEEDS CONNECTION</span><strong>{counts.waiting}</strong><p>Waiting for live services</p></article><article><CircleAlert size={18} /><span>NOT BUILT</span><strong>{counts.missing}</strong><p>Still to be developed</p></article></section><div className="requirements-toolbar"><div><span>SHOW</span>{filterButtons.map((button) => <button className={filter === button.id ? "active" : ""} onClick={() => setFilter(button.id)} key={button.id}>{button.label}<b>{button.count}</b></button>)}</div><p>The status is based on the implemented routes and connected services in this version.</p></div><section className="requirements-list">{visibleItems.map((item) => <article className={`requirement-row requirement-row--${item.status}`} key={item.id}><span className="requirement-module">{item.module}</span><span className="requirement-status">{item.status === "available" ? <Check size={15} /> : item.status === "waiting" ? <Database size={15} /> : <CircleAlert size={15} />}{statusLabels[item.status]}</span><div><strong>{item.title}</strong><p>{item.detail}</p></div><button onClick={() => navigate(item.action || "settings")}>{item.status === "missing" ? "See next step" : "Open page"} <ChevronRight size={15} /></button></article>)}</section></div>;
}

function AuthGateway({ returnLanding, loading }: { returnLanding: () => void; loading: boolean }) {
  const signIn = (event: FormEvent) => { event.preventDefault(); startLogin(); };
  return <main className="auth-shell"><div className="auth-grid" /><section className="auth-terminal"><header><div><img className="auth-brand__mark" src="/manus-storage/origin-tracker-logo_395a06a4.png" alt="" /><span>THREAT OS v1.0</span></div><button onClick={returnLanding}>[ BACK ]</button></header><div className="auth-terminal__body"><p className="terminal-status"><i className="live-pulse" /> SECURE ACCOUNT SIGN-IN</p><h1>{loading ? <>CHECKING<br /><span>ACCOUNT.</span></> : <>SIGN IN<br /><span>TO CONTINUE.</span></>}</h1><p className="auth-copy">Use your secure account to open the email safety dashboard. You will be taken to a trusted sign-in page and returned here when you are ready.</p><form onSubmit={signIn}><label>secure@threat-os:~$ <span>account</span></label><div className="auth-account-line"><ShieldCheck size={17} /><span>Secure account sign-in</span></div><Button disabled={loading} className="auth-submit" type="submit">{loading ? "[ CHECKING YOUR SESSION... ]" : "[ CONTINUE TO SIGN IN ]"}</Button></form><div className="auth-scan"><span>CONNECTION</span><i /><b>SAFE CONNECTION</b></div></div><footer><span>VERSION: 0.9.6</span><span>REGION: INDIA</span><span>STATUS: <b>READY</b></span></footer></section></main>;
}

type GuideMessage = { role: "assistant" | "user"; text: string };

function GuideDrawer({ activeView, close, navigate }: { activeView: View; close: () => void; navigate: (view: View) => void }) {
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState<GuideMessage[]>([{ role: "assistant", text: "I am the website guide. I can explain a page or open an approved screen. I cannot read data, upload files, access accounts, or change settings for you." }]);
  const guide = trpc.guide.ask.useMutation({
    onSuccess: ({ reply, navigateTo }) => {
      setMessages((items) => [...items, { role: "assistant", text: reply }]);
      if (navigateTo) { navigate(navigateTo); toast.info(`Opened ${navItems.find((item) => item.id === navigateTo)?.label}.`); }
    },
    onError: () => setMessages((items) => [...items, { role: "assistant", text: "I could not answer right now. I can still help you choose a page from the menu." }]),
  });
  const ask = (event: FormEvent) => { event.preventDefault(); const text = question.trim(); if (!text || guide.isPending) return; setMessages((items) => [...items, { role: "user", text }]); setQuestion(""); guide.mutate({ question: text, currentView: activeView === "requirements" ? "dashboard" : activeView }); };
  const prompts = ["What can I do on this page?", "Open the email check page", "Where do I connect data?", "Show me reports"];
  return <aside className="guide-drawer" aria-label="AI guide"><header><div><Bot size={19} /><span>AI GUIDE</span></div><button onClick={close} aria-label="Close AI guide"><X size={18} /></button></header><div className="guide-drawer__scope"><ShieldCheck size={15} /><span>Navigation only. No data, file, account, or settings changes.</span></div><div className="guide-drawer__messages">{messages.map((message, index) => <p key={index} className={`guide-message guide-message--${message.role}`}>{message.text}</p>)}{guide.isPending && <p className="guide-message guide-message--assistant"><LoaderCircle size={15} className="spin" /> Thinking…</p>}</div><div className="guide-drawer__prompts">{prompts.map((prompt) => <button key={prompt} onClick={() => setQuestion(prompt)}>{prompt}<ChevronRight size={14} /></button>)}</div><form onSubmit={ask}><input value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Ask where to go…" maxLength={500} /><button type="submit" aria-label="Ask AI guide" disabled={guide.isPending || !question.trim()}><Send size={16} /></button></form></aside>;
}

function Workspace({ initialView, userName, signOut }: { initialView: View; userName: string; signOut: () => void }) {
  const [activeView, setActiveView] = useState<View>(initialView);
  const [selectedInvestigationId, setSelectedInvestigationId] = useState<number | null>(null);
  const [compact, setCompact] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(() => import.meta.env.DEV && new URLSearchParams(window.location.search).get("preview") === "mobile-nav");
  const isDevGuidePreview = import.meta.env.DEV && new URLSearchParams(window.location.search).get("preview") === "guide";
  const isDevMobileNavPreview = import.meta.env.DEV && new URLSearchParams(window.location.search).get("preview") === "mobile-nav";
  const [guideOpen, setGuideOpen] = useState(isDevGuidePreview);
  useEffect(() => { if (!isDevMobileNavPreview) setMobileOpen(false); window.scrollTo({ top: 0, behavior: "smooth" }); }, [activeView, isDevMobileNavPreview]);
  const renderView = () => { switch (activeView) { case "dashboard": return <DashboardView setActiveView={setActiveView} selectInvestigation={setSelectedInvestigationId} />; case "analyzer": return <AnalyzerView setActiveView={setActiveView} selectInvestigation={setSelectedInvestigationId} />; case "intelligence": return <IntelligenceView />; case "geolocation": return <GeolocationCaseFlow />; case "forensics": return <ForensicsViewWithAiRetry selectedInvestigationId={selectedInvestigationId} selectInvestigation={setSelectedInvestigationId} />; case "assistant": return <AssistantView />; case "reports": return <ReportsView />; case "settings": return <SettingsView />; case "requirements": return <RequirementsView navigate={setActiveView} />; } };
  return <div className={`workspace-shell ${compact ? "workspace-shell--compact" : ""}`}><WorkspaceSidebar activeView={activeView} setActiveView={setActiveView} compact={compact} setCompact={setCompact} userName={userName} signOut={signOut} /><div className="workspace-main"><Topbar activeView={activeView} setMobileOpen={setMobileOpen} openGuide={() => setGuideOpen(true)} />{renderView()}</div>{guideOpen && <GuideDrawer activeView={activeView} close={() => setGuideOpen(false)} navigate={setActiveView} />}{mobileOpen && <div className="mobile-nav-overlay"><div className="mobile-nav-head"><div className="terminal-brand"><img className="terminal-brand__mark" src="/manus-storage/origin-tracker-logo_395a06a4.png" alt="Origin Tracker" /><div><strong>Origin Tracker</strong><small>Private security workspace</small></div></div><button aria-label="Close navigation" onClick={() => setMobileOpen(false)}><X size={20} /></button></div><nav>{navItems.map(({ id, label, icon: Icon }) => <button onClick={() => setActiveView(id)} className={activeView === id ? "active" : ""} key={id}><Icon size={18} />{label}</button>)}</nav><button onClick={signOut} className="mobile-exit"><LogOut size={18} /> Sign out</button></div>}</div>;
}

export default function Home() {
  const { user, loading, isAuthenticated, logout } = useAuth();
  const previewMode = import.meta.env.DEV ? new URLSearchParams(window.location.search).get("preview") : null;
  const isDevWorkspacePreview = previewMode === "workspace" || previewMode === "guide" || previewMode === "requirements" || previewMode === "mobile-nav" || previewMode === "geolocation" || previewMode === "intelligence";
  const isDevAuthPreview = previewMode === "auth";
  const [mode, setMode] = useState<WorkspaceMode>(() => previewMode === "workspace" || previewMode === "guide" || previewMode === "requirements" || previewMode === "mobile-nav" || previewMode === "geolocation" || previewMode === "intelligence" ? "workspace" : previewMode === "auth" ? "auth" : "landing");
  const [requestedView, setRequestedView] = useState<View>(() => previewMode === "requirements" ? "requirements" : previewMode === "geolocation" ? "geolocation" : previewMode === "intelligence" ? "intelligence" : "dashboard");
  useEffect(() => {
    if (loading || !isAuthenticated) return;
    const savedView = sessionStorage.getItem("threat-os-requested-view") as View | null;
    if (savedView) {
      setRequestedView(savedView);
      sessionStorage.removeItem("threat-os-requested-view");
      setMode("workspace");
    }
  }, [isAuthenticated, loading]);
  const launchWorkspace = (view: View = "dashboard") => {
    setRequestedView(view);
    if (isAuthenticated || isDevWorkspacePreview) { setMode("workspace"); window.scrollTo({ top: 0, behavior: "smooth" }); return; }
    sessionStorage.setItem("threat-os-requested-view", view);
    setMode("auth");
  };
  const returnLanding = () => { setMode("landing"); window.scrollTo({ top: 0, behavior: "smooth" }); };
  const signOut = async () => { await logout(); setMode("landing"); window.scrollTo({ top: 0, behavior: "smooth" }); toast.success("You have signed out."); };
  if (mode === "landing") return <div className="app-screen app-screen--landing"><Landing launchWorkspace={launchWorkspace} /></div>;
  if (isDevAuthPreview || (!isAuthenticated && !isDevWorkspacePreview)) return <div className="app-screen app-screen--auth"><AuthGateway returnLanding={returnLanding} loading={loading} /></div>;
  return <div className="app-screen app-screen--workspace"><Workspace initialView={requestedView} userName={user?.name || user?.email || "Team member"} signOut={signOut} /></div>;
}
