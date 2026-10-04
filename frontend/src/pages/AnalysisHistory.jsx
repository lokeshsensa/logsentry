import React, { useState, useEffect } from 'react';
import { History, FileText, Download, ExternalLink, ShieldAlert, Flame, RefreshCw } from 'lucide-react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import StatusBadge from '../components/StatusBadge';
import LoadingSpinner from '../components/LoadingSpinner';

export default function AnalysisHistory() {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generatingReport, setGeneratingReport] = useState({});

  const fetchJobs = async () => {
    try {
      setLoading(true);
      const res = await api.getAnalysisJobs({ limit: 50 });
      setJobs(res.data);
    } catch (err) {
      console.error('Failed to load analysis jobs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchJobs();
  }, []);

  const handleGenerateReport = async (jobId) => {
    try {
      setGeneratingReport((prev) => ({ ...prev, [jobId]: true }));
      const res = await api.generateReport(jobId);
      window.open(api.getReportDownloadUrl(res.data.id), '_blank');
    } catch (err) {
      alert('Failed to generate report: ' + (err.response?.data?.detail || err.message));
    } finally {
      setGeneratingReport((prev) => ({ ...prev, [jobId]: false }));
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
            <History className="w-6 h-6 text-soc-accent" /> Analysis Jobs & Scan History
          </h1>
          <p className="text-xs text-soc-muted mt-1">
            Historical log parsing records, detection findings, risk postures, and generated audit reports
          </p>
        </div>
        <button
          onClick={fetchJobs}
          className="p-2 rounded-lg bg-soc-surface border border-soc-border text-soc-muted hover:text-white"
          title="Refresh List"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {loading ? (
        <LoadingSpinner text="Fetching job records..." />
      ) : jobs.length === 0 ? (
        <div className="bg-soc-panel border border-soc-border rounded-xl p-12 text-center text-soc-muted space-y-3">
          <History className="w-10 h-10 mx-auto text-soc-muted/40" />
          <p className="text-sm font-semibold text-white">No analysis jobs recorded yet.</p>
          <p className="text-xs max-w-sm mx-auto">Upload a log file to trigger parsing, attack detection, and incident correlation.</p>
          <Link
            to="/upload"
            className="inline-flex px-4 py-2 rounded-lg text-xs font-bold bg-soc-accent text-white"
          >
            Upload First Log
          </Link>
        </div>
      ) : (
        <div className="bg-soc-panel border border-soc-border/70 rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-soc-surface/60 text-soc-muted border-b border-soc-border uppercase text-[10px] font-bold tracking-wider">
                <tr>
                  <th className="p-3.5">Job ID</th>
                  <th className="p-3.5">Format</th>
                  <th className="p-3.5">Status</th>
                  <th className="p-3.5">Profile</th>
                  <th className="p-3.5">Lines Parsed</th>
                  <th className="p-3.5">Duration</th>
                  <th className="p-3.5">Risk Score</th>
                  <th className="p-3.5">Incidents</th>
                  <th className="p-3.5">Analyzed At</th>
                  <th className="p-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border/40 font-mono">
                {jobs.map((job) => (
                  <tr key={job.id} className="hover:bg-soc-surface/30 transition-colors">
                    <td className="p-3.5 text-cyan-400 font-bold">#{job.id.slice(0, 8)}</td>
                    <td className="p-3.5 text-slate-300 font-sans">{job.detected_format || 'AUTO'}</td>
                    <td className="p-3.5 font-sans"><StatusBadge status={job.status} /></td>
                    <td className="p-3.5 text-soc-muted font-sans">{job.profile}</td>
                    <td className="p-3.5 text-slate-200">{job.parsed_lines?.toLocaleString()} / {job.total_lines?.toLocaleString()}</td>
                    <td className="p-3.5 text-soc-muted">{job.duration_seconds}s</td>
                    <td className="p-3.5 font-bold text-amber-300">{job.risk_score} ({job.risk_level})</td>
                    <td className="p-3.5 text-red-400 font-bold">{job.incidents_count}</td>
                    <td className="p-3.5 text-soc-muted">{new Date(job.created_at).toLocaleString()}</td>
                    <td className="p-3.5 text-right font-sans">
                      <div className="flex items-center justify-end gap-2">
                        <Link
                          to={`/events?job_id=${job.id}`}
                          className="px-2 py-1 rounded bg-soc-surface border border-soc-border hover:bg-slate-700 text-slate-300 text-[11px]"
                          title="View Events"
                        >
                          Events
                        </Link>
                        <button
                          onClick={() => handleGenerateReport(job.id)}
                          disabled={generatingReport[job.id]}
                          className="px-2 py-1 rounded bg-soc-accent/15 border border-soc-accent/30 hover:bg-soc-accent/30 text-soc-accent text-[11px] font-semibold flex items-center gap-1"
                          title="Generate PDF Report"
                        >
                          <FileText className="w-3 h-3" />
                          {generatingReport[job.id] ? 'Generating...' : 'PDF Report'}
                        </button>
                      </div>
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
