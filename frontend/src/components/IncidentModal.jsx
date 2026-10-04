import React, { useState } from 'react';
import { X, ShieldAlert, CheckCircle, Clock, AlertTriangle, FileText, ArrowRight } from 'lucide-react';
import SeverityBadge from './SeverityBadge';
import StatusBadge from './StatusBadge';

export default function IncidentModal({ incidentData, onClose, onStatusUpdate }) {
  if (!incidentData) return null;
  const { incident, detections, sample_events } = incidentData;
  const [selectedStatus, setSelectedStatus] = useState(incident.status);
  const [updating, setUpdating] = useState(false);

  const handleUpdate = async (status) => {
    setUpdating(true);
    setSelectedStatus(status);
    await onStatusUpdate(incident.id, status);
    setUpdating(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="bg-soc-panel border border-soc-border rounded-xl w-full max-w-4xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-soc-border bg-soc-surface/60">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <SeverityBadge severity={incident.severity} />
                <StatusBadge status={selectedStatus} />
                <span className="text-xs text-soc-muted font-mono">Risk: {incident.risk_score}/100</span>
              </div>
              <h2 className="text-base font-bold text-white mt-1">{incident.title}</h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-soc-muted hover:text-white hover:bg-soc-surface transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-6 text-sm">
          {/* Status Workflow Selector */}
          <div className="bg-soc-surface/40 p-4 rounded-xl border border-soc-border/70 flex flex-wrap items-center justify-between gap-4">
            <div>
              <span className="text-xs font-semibold uppercase tracking-wider text-soc-muted block">
                SOC Workflow Status
              </span>
              <p className="text-xs text-slate-300 mt-0.5">Transition investigation lifecycle state</p>
            </div>
            <div className="flex items-center gap-2">
              {['NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map((status) => (
                <button
                  key={status}
                  disabled={updating}
                  onClick={() => handleUpdate(status)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
                    selectedStatus === status
                      ? 'bg-soc-accent text-white border-soc-accent shadow-lg shadow-soc-accent/20'
                      : 'bg-soc-surface text-soc-muted border-soc-border hover:text-white hover:bg-slate-700'
                  }`}
                >
                  {status}
                </button>
              ))}
            </div>
          </div>

          {/* Quick Metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 bg-soc-surface/30 rounded-lg border border-soc-border/50">
              <span className="text-xs text-soc-muted block font-semibold uppercase">Source IP</span>
              <span className="font-mono text-cyan-400 font-bold">{incident.source_ip || 'Internal / Distributed'}</span>
            </div>
            <div className="p-3 bg-soc-surface/30 rounded-lg border border-soc-border/50">
              <span className="text-xs text-soc-muted block font-semibold uppercase">Confidence</span>
              <span className="font-semibold text-white">{incident.confidence}</span>
            </div>
            <div className="p-3 bg-soc-surface/30 rounded-lg border border-soc-border/50">
              <span className="text-xs text-soc-muted block font-semibold uppercase">Security Events</span>
              <span className="font-mono text-amber-300 font-bold">{incident.event_count} events</span>
            </div>
            <div className="p-3 bg-soc-surface/30 rounded-lg border border-soc-border/50">
              <span className="text-xs text-soc-muted block font-semibold uppercase">Time Range</span>
              <span className="font-mono text-xs text-slate-300">
                {incident.first_seen ? new Date(incident.first_seen).toLocaleTimeString() : 'N/A'} - {incident.last_seen ? new Date(incident.last_seen).toLocaleTimeString() : 'N/A'}
              </span>
            </div>
          </div>

          {/* Explainable Narrative */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-soc-muted mb-2 flex items-center gap-1.5">
              <FileText className="w-4 h-4 text-soc-accent" /> Incident Narrative & Attack Rationale
            </h4>
            <div className="p-4 rounded-xl bg-black/40 border border-soc-border text-slate-200 text-xs font-mono whitespace-pre-wrap leading-relaxed">
              {incident.explanation}
            </div>
          </div>

          {/* Recommended Response */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-soc-muted mb-2 flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-amber-400" /> Prescribed Remediation Actions
            </h4>
            <div className="p-4 rounded-xl bg-amber-500/5 border border-amber-500/20 text-amber-200/90 text-xs whitespace-pre-wrap leading-relaxed font-sans">
              {incident.remediation}
            </div>
          </div>

          {/* Triggered Detections */}
          {detections && detections.length > 0 && (
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-soc-muted mb-2">
                Triggered Attack Detections ({detections.length})
              </h4>
              <div className="space-y-2">
                {detections.map((det) => (
                  <div key={det.id} className="p-3 rounded-lg bg-soc-surface/40 border border-soc-border/70 flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-cyan-400">{det.rule_id}</span>
                        <span className="text-xs font-semibold text-white">{det.title}</span>
                      </div>
                      <p className="text-xs text-soc-muted mt-1">{det.explanation?.slice(0, 160)}...</p>
                    </div>
                    <SeverityBadge severity={det.severity} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Sample Related Events */}
          {sample_events && sample_events.length > 0 && (
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-soc-muted mb-2">
                Correlated Event Evidence Log (Sample of {sample_events.length})
              </h4>
              <div className="bg-black/60 rounded-xl border border-soc-border overflow-hidden">
                <div className="max-h-52 overflow-y-auto divide-y divide-soc-border/40 text-xs font-mono">
                  {sample_events.map((ev, i) => (
                    <div key={ev.id || i} className="p-2.5 hover:bg-soc-surface/40 flex items-center justify-between text-slate-300">
                      <div className="truncate pr-4">
                        <span className="text-soc-muted mr-2">[{ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : '#' + (i+1)}]</span>
                        <span className="text-amber-400 mr-2">{ev.event_type}</span>
                        <span className="text-slate-300">{ev.raw_log}</span>
                      </div>
                      <SeverityBadge severity={ev.severity} />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-soc-border bg-soc-surface/40 flex justify-end">
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
