import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ShieldAlert, Info, HelpCircle, RefreshCw, X, ArrowRight } from 'lucide-react';
import { api } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import LoadingSpinner from '../components/LoadingSpinner';

export default function Detections() {
  const [searchParams] = useSearchParams();
  const initialJobId = searchParams.get('job_id') || '';

  const [detections, setDetections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedDet, setSelectedDet] = useState(null);
  const [categoryFilter, setCategoryFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  const fetchDetections = async () => {
    try {
      setLoading(true);
      const params = {
        job_id: initialJobId || undefined,
        category: categoryFilter || undefined,
        severity: severityFilter || undefined,
      };
      const res = await api.getDetections(params);
      setDetections(res.data);
    } catch (err) {
      console.error('Failed to load detections:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDetections();
  }, [initialJobId, categoryFilter, severityFilter]);

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-red-400" /> Attack Detection Findings
          </h1>
          <p className="text-xs text-soc-muted mt-1">
            Atomic rule indicators identified by sliding-window frequency, password spraying, and reconnaissance heuristics
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-soc-surface border border-soc-border text-xs rounded-lg px-3 py-2 text-white focus:outline-none focus:border-soc-accent"
          >
            <option value="">All Categories</option>
            <option value="Authentication">Authentication</option>
            <option value="Web">Web</option>
            <option value="Reconnaissance">Reconnaissance</option>
            <option value="Privilege">Privilege</option>
            <option value="Anomaly">Anomaly</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-soc-surface border border-soc-border text-xs rounded-lg px-3 py-2 text-white focus:outline-none focus:border-soc-accent"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>

          <button
            onClick={fetchDetections}
            className="p-2 rounded-lg bg-soc-surface border border-soc-border text-soc-muted hover:text-white"
            title="Refresh Detections"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {loading ? (
        <LoadingSpinner text="Evaluating detection rules..." />
      ) : detections.length === 0 ? (
        <div className="bg-soc-panel border border-soc-border rounded-xl p-12 text-center text-soc-muted">
          No detections matching criteria.
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Detections List Table */}
          <div className="lg:col-span-2 bg-soc-panel border border-soc-border/70 rounded-xl overflow-hidden shadow-lg">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-soc-surface/60 text-soc-muted border-b border-soc-border uppercase text-[10px] font-bold tracking-wider">
                  <tr>
                    <th className="p-3">Rule</th>
                    <th className="p-3">Attack Type</th>
                    <th className="p-3">Source IP</th>
                    <th className="p-3">Severity</th>
                    <th className="p-3">Confidence</th>
                    <th className="p-3">Events</th>
                    <th className="p-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-soc-border/40 font-mono text-[11px]">
                  {detections.map((d) => (
                    <tr
                      key={d.id}
                      onClick={() => setSelectedDet(d)}
                      className={`hover:bg-soc-surface/40 transition-colors cursor-pointer ${
                        selectedDet?.id === d.id ? 'bg-soc-surface/60 border-l-2 border-soc-accent' : ''
                      }`}
                    >
                      <td className="p-3 text-cyan-400 font-bold">{d.rule_id}</td>
                      <td className="p-3 text-white font-sans font-semibold">{d.attack_type}</td>
                      <td className="p-3 text-slate-300">{d.source_ip || 'Local/Host'}</td>
                      <td className="p-3 font-sans"><SeverityBadge severity={d.severity} /></td>
                      <td className="p-3 font-sans text-soc-muted">{d.confidence}</td>
                      <td className="p-3 text-amber-300 font-bold">{d.event_count}x</td>
                      <td className="p-3 font-sans"><StatusBadge status={d.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Explainability Side Drawer */}
          <div className="bg-soc-panel border border-soc-border/70 rounded-xl p-5 shadow-lg space-y-4">
            {selectedDet ? (
              <div className="space-y-4 animate-fade-in">
                <div className="flex items-start justify-between border-b border-soc-border pb-3">
                  <div>
                    <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-wider">
                      {selectedDet.rule_id} / {selectedDet.category}
                    </span>
                    <h3 className="text-sm font-bold text-white mt-0.5">{selectedDet.title}</h3>
                  </div>
                  <SeverityBadge severity={selectedDet.severity} />
                </div>

                <div className="space-y-3 text-xs">
                  <div>
                    <span className="text-soc-muted uppercase text-[10px] font-bold block">Source & Target</span>
                    <p className="font-mono text-white text-[11px] mt-0.5">
                      {selectedDet.source_ip || 'Internal'} <ArrowRight className="inline w-3 h-3 text-soc-muted" /> {selectedDet.target_endpoint || 'N/A'}
                    </p>
                  </div>

                  <div>
                    <span className="text-soc-muted uppercase text-[10px] font-bold block">Detection Explainability Narrative</span>
                    <div className="p-3 mt-1 bg-black/50 border border-soc-border rounded-lg text-slate-300 font-mono text-[11px] leading-relaxed whitespace-pre-wrap">
                      {selectedDet.explanation}
                    </div>
                  </div>

                  <div>
                    <span className="text-soc-muted uppercase text-[10px] font-bold block">Recommended Mitigation</span>
                    <div className="p-3 mt-1 bg-amber-500/5 border border-amber-500/20 rounded-lg text-amber-200/90 text-[11px] leading-relaxed">
                      {selectedDet.remediation}
                    </div>
                  </div>

                  <div className="pt-2 text-[11px] text-soc-muted border-t border-soc-border flex justify-between">
                    <span>Threshold: {selectedDet.threshold} events</span>
                    <span>Window: {selectedDet.time_window}s</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="h-64 flex flex-col items-center justify-center text-center text-soc-muted space-y-2 p-4">
                <Info className="w-8 h-8 text-soc-muted/50" />
                <p className="text-xs">Click on any detection finding to view its detailed explainable narrative and response guidelines.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
