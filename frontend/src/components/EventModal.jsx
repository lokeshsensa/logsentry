import React from 'react';
import { X, Copy, Terminal, ShieldAlert } from 'lucide-react';
import SeverityBadge from './SeverityBadge';

export default function EventModal({ event, onClose }) {
  if (!event) return null;

  const copyToClipboard = (text) => {
    navigator.clipboard?.writeText(text);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="bg-soc-panel border border-soc-border rounded-xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-soc-border bg-soc-surface/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-soc-accent/10 border border-soc-accent/20 text-soc-accent">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-white flex items-center gap-2">
                Event Inspection <span className="text-xs text-soc-muted font-mono">#{event.line_number || event.id?.slice(0, 8)}</span>
              </h3>
              <p className="text-xs text-soc-muted font-mono">{event.timestamp || 'No Timestamp'}</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <SeverityBadge severity={event.severity} />
            <button
              onClick={onClose}
              className="p-1 rounded-lg text-soc-muted hover:text-white hover:bg-soc-surface transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5 text-sm">
          {/* Key Normalized Fields Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-soc-surface/50 p-3 rounded-lg border border-soc-border/50">
              <span className="text-xs text-soc-muted block font-semibold uppercase">Source IP</span>
              <span className="font-mono text-white text-xs font-bold">{event.source_ip || 'None'}</span>
            </div>
            <div className="bg-soc-surface/50 p-3 rounded-lg border border-soc-border/50">
              <span className="text-xs text-soc-muted block font-semibold uppercase">User / Identity</span>
              <span className="font-mono text-cyan-400 text-xs font-bold">{event.username || 'Anonymous'}</span>
            </div>
            <div className="bg-soc-surface/50 p-3 rounded-lg border border-soc-border/50">
              <span className="text-xs text-soc-muted block font-semibold uppercase">Event Type</span>
              <span className="font-mono text-amber-300 text-xs font-bold">{event.event_type || 'SYSTEM'}</span>
            </div>
            <div className="bg-soc-surface/50 p-3 rounded-lg border border-soc-border/50">
              <span className="text-xs text-soc-muted block font-semibold uppercase">Status / Port</span>
              <span className="font-mono text-white text-xs font-bold">
                {event.status_code ? `HTTP ${event.status_code}` : (event.source_port ? `Port ${event.source_port}` : 'N/A')}
              </span>
            </div>
          </div>

          {/* Endpoint / Message */}
          {event.endpoint && (
            <div className="bg-soc-surface/40 p-3 rounded-lg border border-soc-border/50">
              <span className="text-xs text-soc-muted block font-semibold uppercase mb-1">HTTP Method & Resource</span>
              <code className="text-xs text-emerald-400 font-mono">
                {event.method ? `${event.method} ` : ''}{event.endpoint}
              </code>
            </div>
          )}

          {/* Raw Log Line */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-semibold text-soc-muted uppercase tracking-wider">Raw Log Entry</span>
              <button
                onClick={() => copyToClipboard(event.raw_log)}
                className="text-xs text-soc-accent hover:underline flex items-center gap-1 font-mono"
              >
                <Copy className="w-3.5 h-3.5" /> Copy Raw
              </button>
            </div>
            <pre className="p-3 bg-black/60 border border-soc-border rounded-lg text-xs font-mono text-slate-300 whitespace-pre-wrap break-all leading-relaxed">
              {event.raw_log}
            </pre>
          </div>

          {/* Normalized JSON Structure */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-semibold text-soc-muted uppercase tracking-wider">Normalized Data Model</span>
              <button
                onClick={() => copyToClipboard(JSON.stringify(event, null, 2))}
                className="text-xs text-soc-accent hover:underline flex items-center gap-1 font-mono"
              >
                <Copy className="w-3.5 h-3.5" /> Copy JSON
              </button>
            </div>
            <pre className="p-3 bg-black/60 border border-soc-border rounded-lg text-xs font-mono text-cyan-300/90 whitespace-pre-wrap overflow-x-auto max-h-48 leading-relaxed">
              {JSON.stringify(event, null, 2)}
            </pre>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-soc-border bg-soc-surface/30 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg text-xs font-medium bg-soc-surface hover:bg-slate-700 text-white border border-soc-border transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
