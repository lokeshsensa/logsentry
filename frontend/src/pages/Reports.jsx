import React, { useState, useEffect } from 'react';
import { FileBarChart, Download, Plus, FileText, CheckCircle, RefreshCw } from 'lucide-react';
import { api } from '../services/api';
import LoadingSpinner from '../components/LoadingSpinner';

export default function Reports() {
  const [reports, setReports] = useState([]);
  const [jobs, setJobs] = useState([]);
  const [selectedJobId, setSelectedJobId] = useState('');
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

  const fetchReportsAndJobs = async () => {
    try {
      setLoading(true);
      const [repsRes, jobsRes] = await Promise.all([
        api.getReports(),
        api.getAnalysisJobs({ limit: 30 })
      ]);
      setReports(repsRes.data);
      const completedJobs = jobsRes.data.filter((j) => j.status === 'COMPLETED');
      setJobs(completedJobs);
      if (completedJobs.length > 0 && !selectedJobId) {
        setSelectedJobId(completedJobs[0].id);
      }
    } catch (err) {
      console.error('Failed to load reports:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReportsAndJobs();
  }, []);

  const handleGenerate = async () => {
    if (!selectedJobId) return;
    setGenerating(true);
    try {
      const res = await api.generateReport(selectedJobId);
      setReports((prev) => [res.data, ...prev]);
      window.open(api.getReportDownloadUrl(res.data.id), '_blank');
    } catch (err) {
      alert('Failed to generate PDF: ' + (err.response?.data?.detail || err.message));
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
            <FileBarChart className="w-6 h-6 text-soc-accent" /> Defensive Security Reports
          </h1>
          <p className="text-xs text-soc-muted mt-1">
            Automated PDF security audit deliverables conforming to SOC reporting standards
          </p>
        </div>

        <button
          onClick={fetchReportsAndJobs}
          className="p-2 rounded-lg bg-soc-surface border border-soc-border text-soc-muted hover:text-white"
          title="Refresh Reports"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Generate Report Box */}
      <div className="bg-soc-panel border border-soc-border/70 rounded-xl p-5 shadow-lg flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-white">Generate Executive SOC Deliverable</h2>
          <p className="text-xs text-soc-muted mt-0.5">
            Produces a multi-page PDF containing executive summary, top IPs, incident timelines, findings, and technical remediation
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={selectedJobId}
            onChange={(e) => setSelectedJobId(e.target.value)}
            className="bg-soc-surface border border-soc-border text-xs rounded-lg px-3 py-2 text-white font-mono focus:outline-none focus:border-soc-accent"
          >
            {jobs.map((j) => (
              <option key={j.id} value={j.id}>
                Job #{j.id.slice(0, 8)} ({j.total_lines} lines - Risk: {j.risk_score})
              </option>
            ))}
          </select>

          <button
            onClick={handleGenerate}
            disabled={generating || !selectedJobId}
            className="px-4 py-2 rounded-lg text-xs font-bold bg-soc-accent hover:bg-sky-400 text-white flex items-center gap-2 disabled:opacity-50 transition-all shadow-lg shadow-sky-500/20"
          >
            <Plus className="w-4 h-4" />
            {generating ? 'Compiling PDF...' : 'Generate PDF'}
          </button>
        </div>
      </div>

      {/* Reports Table */}
      {loading ? (
        <LoadingSpinner text="Loading generated reports..." />
      ) : reports.length === 0 ? (
        <div className="bg-soc-panel border border-soc-border rounded-xl p-12 text-center text-soc-muted">
          No PDF reports generated yet. Select a completed analysis job above to create your first report.
        </div>
      ) : (
        <div className="bg-soc-panel border border-soc-border/70 rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-soc-surface/60 text-soc-muted border-b border-soc-border uppercase text-[10px] font-bold tracking-wider">
                <tr>
                  <th className="p-3.5">Report Title</th>
                  <th className="p-3.5">Job ID</th>
                  <th className="p-3.5">Format</th>
                  <th className="p-3.5">File Size</th>
                  <th className="p-3.5">Generated At</th>
                  <th className="p-3.5 text-right">Download</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border/40 font-mono">
                {reports.map((rep) => (
                  <tr key={rep.id} className="hover:bg-soc-surface/30 transition-colors">
                    <td className="p-3.5 font-sans font-semibold text-white flex items-center gap-2">
                      <FileText className="w-4 h-4 text-red-400 shrink-0" />
                      <span>{rep.title}</span>
                    </td>
                    <td className="p-3.5 text-cyan-400">#{rep.analysis_job_id?.slice(0, 8)}</td>
                    <td className="p-3.5 font-sans text-soc-muted">PDF Document</td>
                    <td className="p-3.5 text-slate-300 font-sans">
                      {Math.round(rep.file_size_bytes / 1024)} KB
                    </td>
                    <td className="p-3.5 text-soc-muted">
                      {new Date(rep.created_at).toLocaleString()}
                    </td>
                    <td className="p-3.5 text-right font-sans">
                      <a
                        href={api.getReportDownloadUrl(rep.id)}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-soc-accent hover:bg-sky-400 text-white font-bold text-[11px] shadow-sm transition-all"
                      >
                        <Download className="w-3.5 h-3.5" /> Download
                      </a>
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
