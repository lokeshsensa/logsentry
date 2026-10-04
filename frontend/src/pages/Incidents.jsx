import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Flame, ShieldAlert, CheckCircle, RefreshCw, Eye, ArrowRight, AlertTriangle } from 'lucide-react';
import { api } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import IncidentModal from '../components/IncidentModal';
import LoadingSpinner from '../components/LoadingSpinner';

export default function Incidents() {
  const [searchParams] = useSearchParams();
  const initialJobId = searchParams.get('job_id') || '';

  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedIncidentData, setSelectedIncidentData] = useState(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      const params = {
        job_id: initialJobId || undefined,
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
      };
      const res = await api.getIncidents(params);
      setIncidents(res.data);
    } catch (err) {
      console.error('Failed to load incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [initialJobId, statusFilter, severityFilter]);

  const handleOpenIncident = async (incidentId) => {
    try {
      const res = await api.getIncident(incidentId);
      setSelectedIncidentData(res.data);
    } catch (err) {
      console.error('Failed to load incident detail:', err);
    }
  };

  const handleStatusUpdate = async (incidentId, newStatus) => {
    try {
      await api.updateIncidentStatus(incidentId, newStatus);
      // Refresh local incidents list
      setIncidents((prev) =>
        prev.map((inc) => (inc.id === incidentId ? { ...inc, status: newStatus } : inc))
      );
      if (selectedIncidentData) {
        setSelectedIncidentData((prev) => ({
          ...prev,
          incident: { ...prev.incident, status: newStatus },
        }));
      }
    } catch (err) {
      alert('Failed to update status: ' + (err.response?.data?.detail || err.message));
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
            <Flame className="w-6 h-6 text-red-500" /> Correlated Incident Workbench
          </h1>
          <p className="text-xs text-soc-muted mt-1">
            Multi-stage attack chains, brute-force progressions, and privilege escalation investigations
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-soc-surface border border-soc-border text-xs rounded-lg px-3 py-2 text-white focus:outline-none focus:border-soc-accent"
          >
            <option value="">All Statuses</option>
            <option value="NEW">NEW</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
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
            onClick={fetchIncidents}
            className="p-2 rounded-lg bg-soc-surface border border-soc-border text-soc-muted hover:text-white"
            title="Refresh Incidents"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {loading ? (
        <LoadingSpinner text="Querying correlated incident queue..." />
      ) : incidents.length === 0 ? (
        <div className="bg-soc-panel border border-soc-border rounded-xl p-12 text-center text-soc-muted">
          No security incidents found matching criteria.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {incidents.map((inc) => (
            <div
              key={inc.id}
              onClick={() => handleOpenIncident(inc.id)}
              className="bg-soc-panel border border-soc-border/70 hover:border-soc-border rounded-xl p-5 shadow-lg space-y-4 cursor-pointer transition-all hover:bg-soc-surface/30 group"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={inc.severity} />
                    <StatusBadge status={inc.status} />
                  </div>
                  <h3 className="text-sm font-bold text-white group-hover:text-cyan-400 transition-colors">
                    {inc.title}
                  </h3>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-soc-muted uppercase block font-semibold">Risk Score</span>
                  <span className="text-sm font-bold font-mono text-amber-300">{inc.risk_score}/100</span>
                </div>
              </div>

              <p className="text-xs text-slate-300 line-clamp-2 leading-relaxed">
                {inc.explanation?.slice(0, 220)}...
              </p>

              <div className="flex items-center justify-between text-xs pt-2 border-t border-soc-border/60 text-soc-muted">
                <div className="flex items-center gap-3 font-mono text-[11px]">
                  <span>Source: <strong className="text-cyan-400">{inc.source_ip || 'Internal'}</strong></span>
                  <span>•</span>
                  <span>{inc.event_count} events</span>
                </div>
                <span className="text-xs text-soc-accent font-semibold flex items-center gap-1">
                  Investigate <ArrowRight className="w-3.5 h-3.5" />
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Incident Investigation Modal */}
      {selectedIncidentData && (
        <IncidentModal
          incidentData={selectedIncidentData}
          onClose={() => setSelectedIncidentData(null)}
          onStatusUpdate={handleStatusUpdate}
        />
      )}
    </div>
  );
}
