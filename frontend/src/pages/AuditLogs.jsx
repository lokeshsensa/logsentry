import React, { useState, useEffect } from 'react';
import { ClipboardList, RefreshCw, ShieldCheck } from 'lucide-react';
import { api } from '../services/api';
import LoadingSpinner from '../components/LoadingSpinner';

export default function AuditLogs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchAuditLogs = async () => {
    try {
      setLoading(true);
      const res = await api.getAuditLogs({ limit: 100 });
      setLogs(res.data);
    } catch (err) {
      console.error('Failed to load audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAuditLogs();
  }, []);

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
            <ClipboardList className="w-6 h-6 text-soc-accent" /> Administrative Audit Trail
          </h1>
          <p className="text-xs text-soc-muted mt-1">
            Immutable log of SOC operator actions, rule changes, file ingestions, and status transitions
          </p>
        </div>
        <button
          onClick={fetchAuditLogs}
          className="p-2 rounded-lg bg-soc-surface border border-soc-border text-soc-muted hover:text-white"
          title="Refresh Audit Logs"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {loading ? (
        <LoadingSpinner text="Reading SOC audit ledger..." />
      ) : logs.length === 0 ? (
        <div className="bg-soc-panel border border-soc-border rounded-xl p-12 text-center text-soc-muted">
          No administrative audit records logged yet.
        </div>
      ) : (
        <div className="bg-soc-panel border border-soc-border/70 rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-soc-surface/60 text-soc-muted border-b border-soc-border uppercase text-[10px] font-bold tracking-wider">
                <tr>
                  <th className="p-3.5">Timestamp</th>
                  <th className="p-3.5">Action</th>
                  <th className="p-3.5">Operator</th>
                  <th className="p-3.5">Resource</th>
                  <th className="p-3.5">Result</th>
                  <th className="p-3.5">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border/40 font-mono text-[11px]">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-soc-surface/30 transition-colors">
                    <td className="p-3.5 text-soc-muted">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="p-3.5 text-cyan-400 font-bold font-sans">
                      {log.action}
                    </td>
                    <td className="p-3.5 text-amber-300 font-sans">{log.actor}</td>
                    <td className="p-3.5 text-slate-200">{log.resource}</td>
                    <td className="p-3.5 font-sans">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        log.result === 'SUCCESS'
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : 'bg-red-500/10 text-red-400 border-red-500/30'
                      }`}>
                        {log.result}
                      </span>
                    </td>
                    <td className="p-3.5 text-slate-300 font-sans max-w-md truncate">
                      {log.details || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
