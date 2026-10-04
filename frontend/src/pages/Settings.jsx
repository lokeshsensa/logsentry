import React from 'react';
import { Settings as SettingsIcon, ShieldCheck, Database, Server, Lock, Cpu } from 'lucide-react';

export default function Settings() {
  return (
    <div className="p-8 space-y-8 max-w-5xl mx-auto">
      <div>
        <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
          <SettingsIcon className="w-6 h-6 text-soc-accent" /> SOC System Configuration
        </h1>
        <p className="text-xs text-soc-muted mt-1">
          Defensive boundary controls, database storage parameters, and detection engine settings
        </p>
      </div>

      {/* Defensive Security Posture Overview */}
      <div className="bg-soc-panel border border-soc-border/70 rounded-xl p-6 shadow-lg space-y-4">
        <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
          <ShieldCheck className="w-5 h-5" />
          <span>Defensive Cybersecurity Integrity Policy</span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          LOGSENTRY strictly operates in defensive log analysis mode. Uploaded log payloads are parsed safely using deterministic regular expressions and tokenizers without executing shell commands or remote network probes. Directory traversal protections and filename sanitization prevent unauthorized file tampering.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 text-xs">
          <div className="p-3 bg-soc-surface/40 rounded-lg border border-soc-border/40">
            <span className="text-soc-muted uppercase text-[10px] font-bold block">Execution Guardrail</span>
            <span className="text-emerald-400 font-semibold font-mono">Zero Shell / Zero Subprocess</span>
          </div>
          <div className="p-3 bg-soc-surface/40 rounded-lg border border-soc-border/40">
            <span className="text-soc-muted uppercase text-[10px] font-bold block">Storage Isolation</span>
            <span className="text-cyan-400 font-semibold font-mono">Isolated Data Directory</span>
          </div>
          <div className="p-3 bg-soc-surface/40 rounded-lg border border-soc-border/40">
            <span className="text-soc-muted uppercase text-[10px] font-bold block">Active Operator</span>
            <span className="text-amber-300 font-semibold font-mono">soc_analyst (SOC_LEAD)</span>
          </div>
        </div>
      </div>

      {/* Backend & Database Properties */}
      <div className="bg-soc-panel border border-soc-border/70 rounded-xl p-6 shadow-lg space-y-4">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <Database className="w-4 h-4 text-cyan-400" /> Storage & Engine Parameters
        </h2>
        
        <div className="divide-y divide-soc-border/40 text-xs">
          <div className="py-3 flex justify-between items-center">
            <span className="text-soc-muted">Backend API Server</span>
            <span className="font-mono text-white">FastAPI (Python 3.13)</span>
          </div>
          <div className="py-3 flex justify-between items-center">
            <span className="text-soc-muted">Primary Database</span>
            <span className="font-mono text-white">SQLite3 (Thread-Safe WAL Mode via SQLAlchemy)</span>
          </div>
          <div className="py-3 flex justify-between items-center">
            <span className="text-soc-muted">Maximum File Upload Limit</span>
            <span className="font-mono text-white">50 MB (Stream Chunked Processing)</span>
          </div>
          <div className="py-3 flex justify-between items-center">
            <span className="text-soc-muted">PDF Engine</span>
            <span className="font-mono text-white">ReportLab Document Template Builder</span>
          </div>
          <div className="py-3 flex justify-between items-center">
            <span className="text-soc-muted">Risk Scoring Model</span>
            <span className="font-mono text-cyan-400 font-bold">5-Factor Transparent Normalization (0–100)</span>
          </div>
        </div>
      </div>

      {/* Roadmap Architecture */}
      <div className="bg-soc-panel border border-soc-border/70 rounded-xl p-6 shadow-lg space-y-3">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <Cpu className="w-4 h-4 text-purple-400" /> Modular Architecture & Future Roadmap
        </h2>
        <p className="text-xs text-soc-muted leading-relaxed">
          LOGSENTRY's pluggable parser and detector interfaces are architected to seamlessly accommodate upcoming enterprise capabilities:
        </p>
        <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-slate-300 font-mono pt-1">
          <li className="p-2 bg-soc-surface/30 rounded border border-soc-border/30">• Syslog RFC5424 Daemon Receiver</li>
          <li className="p-2 bg-soc-surface/30 rounded border border-soc-border/30">• Windows EVTX Event Log Ingestion</li>
          <li className="p-2 bg-soc-surface/30 rounded border border-soc-border/30">• MITRE ATT&CK Matrix TTP Tagging</li>
          <li className="p-2 bg-soc-surface/30 rounded border border-soc-border/30">• GeoIP MaxMind ASN Enrichment</li>
          <li className="p-2 bg-soc-surface/30 rounded border border-soc-border/30">• Distributed Elasticsearch / OpenSearch</li>
          <li className="p-2 bg-soc-surface/30 rounded border border-soc-border/30">• SIEM Webhook Alert Integration</li>
        </ul>
      </div>
    </div>
  );
}
