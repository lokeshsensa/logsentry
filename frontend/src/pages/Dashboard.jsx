import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Flame,
  Activity,
  Layers,
  Users,
  KeyRound,
  AlertOctagon,
  TrendingUp,
  RefreshCw,
  ExternalLink
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import StatCard from '../components/StatCard';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import LoadingSpinner from '../components/LoadingSpinner';

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#3b82f6',
  INFORMATIONAL: '#64748b'
};

const PIE_COLORS = ['#ef4444', '#f97316', '#f59e0b', '#0ea5e9', '#10b981', '#8b5cf6'];

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [jobs, setJobs] = useState([]);
  const [selectedJobId, setSelectedJobId] = useState('');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchDashboardData = async (jobId = '') => {
    try {
      setRefreshing(true);
      const [statsRes, jobsRes] = await Promise.all([
        api.getDashboardStats(jobId || undefined),
        api.getAnalysisJobs({ limit: 15 }),
      ]);
      setStats(statsRes.data);
      setJobs(jobsRes.data);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDashboardData(selectedJobId);
  }, [selectedJobId]);

  if (loading) {
    return <LoadingSpinner text="Connecting to LOGSENTRY telemetry engine..." />;
  }

  const riskLevelColor = {
    LOW: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
    GUARDED: 'text-blue-400 border-blue-500/30 bg-blue-500/10',
    MEDIUM: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
    HIGH: 'text-orange-400 border-orange-500/30 bg-orange-500/10',
    CRITICAL: 'text-red-400 border-red-500/30 bg-red-500/10',
  }[stats?.overall_risk_level] || 'text-cyan-400 border-cyan-500/30 bg-cyan-500/10';

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header bar with Job Filter and Refresh */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-soc-border/60 pb-6">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2.5">
            Security Operations Console
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          </h1>
          <p className="text-xs text-soc-muted mt-1">
            Real-time defensive attack detection, sliding-window telemetry, and incident response
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Job Filter Dropdown */}
          <select
            value={selectedJobId}
            onChange={(e) => setSelectedJobId(e.target.value)}
            className="bg-soc-surface border border-soc-border text-xs rounded-lg px-3 py-2 text-white font-mono focus:outline-none focus:border-soc-accent"
          >
            <option value="">Aggregate (All Analysis Jobs)</option>
            {jobs.map((j) => (
              <option key={j.id} value={j.id}>
                Job #{j.id.slice(0, 8)} ({j.total_lines} lines - {j.status})
              </option>
            ))}
          </select>

          <button
            onClick={() => fetchDashboardData(selectedJobId)}
            disabled={refreshing}
            className="p-2 rounded-lg bg-soc-surface border border-soc-border text-soc-muted hover:text-white hover:bg-slate-700 transition-colors"
            title="Refresh Dashboard"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-soc-accent' : ''}`} />
          </button>
        </div>
      </div>

      {/* Posture Banner */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-soc-panel to-soc-surface border border-soc-border/80 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xl">
        <div className="flex items-center gap-4">
          <div className={`px-4 py-3 rounded-xl border font-mono font-bold text-lg flex items-center gap-2 ${riskLevelColor}`}>
            <AlertOctagon className="w-6 h-6 shrink-0" />
            <div>
              <span className="text-[10px] uppercase tracking-wider block font-sans text-soc-muted">Risk Score</span>
              <span>{stats?.overall_risk_score} / 100</span>
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-soc-muted">Threat Posture</span>
              <span className={`text-xs font-bold px-2 py-0.5 rounded border ${riskLevelColor}`}>
                {stats?.overall_risk_level}
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1 max-w-xl">
              Transparent multi-factor scoring based on base severity, event frequency, detection confidence, and kill-chain correlation.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Link
            to="/incidents"
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30 flex items-center gap-1.5 transition-all"
          >
            <Flame className="w-4 h-4" /> View Active Incidents ({stats?.active_incidents || 0})
          </Link>
          <Link
            to="/upload"
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-soc-accent text-white hover:bg-sky-400 shadow-lg shadow-sky-500/20 flex items-center gap-1.5 transition-all"
          >
            Ingest New Logs
          </Link>
        </div>
      </div>

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
        <StatCard
          title="Total Events"
          value={stats?.total_events?.toLocaleString() || 0}
          icon={Layers}
          color="cyan"
          subtitle="Normalized entries"
        />
        <StatCard
          title="Detections"
          value={stats?.total_detections || 0}
          icon={ShieldAlert}
          color="amber"
          subtitle="Atomic rules matched"
        />
        <StatCard
          title="Incidents"
          value={stats?.active_incidents || 0}
          icon={Flame}
          color="red"
          badge="High Priority"
        />
        <StatCard
          title="Critical/High"
          value={stats?.critical_high_findings || 0}
          icon={AlertOctagon}
          color="red"
          subtitle="Severe indicators"
        />
        <StatCard
          title="Unique IPs"
          value={stats?.unique_source_ips || 0}
          icon={Users}
          color="indigo"
          subtitle="Observed actors"
        />
        <StatCard
          title="Auth Failures"
          value={stats?.auth_failures || 0}
          icon={KeyRound}
          color="amber"
          subtitle="Failed logins"
        />
        <StatCard
          title="HTTP Errors"
          value={stats?.http_errors || 0}
          icon={Activity}
          color="purple"
          subtitle="4xx/5xx responses"
        />
      </div>

      {/* Charts Row 1: Events Timeline & Detection Categories */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Events Timeline */}
        <div className="lg:col-span-2 bg-soc-panel border border-soc-border/70 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-soc-accent" /> Log Event Telemetry Over Time
              </h3>
              <p className="text-xs text-soc-muted">Volume of observed events and high-severity bursts</p>
            </div>
          </div>
          <div className="h-64">
            {stats?.events_over_time?.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={stats.events_over_time}>
                  <defs>
                    <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 11 }} />
                  <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '12px' }} />
                  <Area type="monotone" dataKey="count" name="All Events" stroke="#0ea5e9" fillOpacity={1} fill="url(#colorTotal)" />
                  <Area type="monotone" dataKey="high_sev" name="High/Critical" stroke="#ef4444" fillOpacity={1} fill="url(#colorHigh)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-soc-muted">
                No temporal event data available. Upload a log to visualize timeline.
              </div>
            )}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-soc-panel border border-soc-border/70 rounded-xl p-5 shadow-lg">
          <h3 className="text-sm font-bold text-white mb-1">Severity Distribution</h3>
          <p className="text-xs text-soc-muted mb-4">Breakdown of detected security findings</p>
          <div className="h-64">
            {stats?.severity_distribution?.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={stats.severity_distribution}
                    dataKey="count"
                    nameKey="severity"
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={4}
                  >
                    {stats.severity_distribution.map((entry) => (
                      <Cell
                        key={entry.severity}
                        fill={SEVERITY_COLORS[entry.severity] || '#64748b'}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-soc-muted">
                No detection severity metrics available.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Charts Row 2: Top Sources, Target Endpoints & Attack Categories */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Top Source IPs */}
        <div className="bg-soc-panel border border-soc-border/70 rounded-xl p-5 shadow-lg">
          <h3 className="text-sm font-bold text-white mb-1">Top Source IPs</h3>
          <p className="text-xs text-soc-muted mb-4">Sources generating the highest log volume</p>
          <div className="h-56">
            {stats?.top_source_ips?.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.top_source_ips} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis type="number" stroke="#64748b" tick={{ fontSize: 10 }} />
                  <YAxis dataKey="ip" type="category" stroke="#64748b" tick={{ fontSize: 10 }} width={90} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }} />
                  <Bar dataKey="count" fill="#0ea5e9" radius={[0, 4, 4, 0]} name="Events" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-soc-muted">No IP data recorded.</div>
            )}
          </div>
        </div>

        {/* Top Targeted Endpoints */}
        <div className="bg-soc-panel border border-soc-border/70 rounded-xl p-5 shadow-lg">
          <h3 className="text-sm font-bold text-white mb-1">Top Targeted Endpoints</h3>
          <p className="text-xs text-soc-muted mb-4">Most frequently requested resources</p>
          <div className="h-56">
            {stats?.top_targeted_endpoints?.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.top_targeted_endpoints} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis type="number" stroke="#64748b" tick={{ fontSize: 10 }} />
                  <YAxis dataKey="endpoint" type="category" stroke="#64748b" tick={{ fontSize: 10 }} width={95} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }} />
                  <Bar dataKey="count" fill="#f59e0b" radius={[0, 4, 4, 0]} name="Hits" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-soc-muted">No endpoints recorded.</div>
            )}
          </div>
        </div>

        {/* Attack Categories */}
        <div className="bg-soc-panel border border-soc-border/70 rounded-xl p-5 shadow-lg">
          <h3 className="text-sm font-bold text-white mb-1">Attack Classification</h3>
          <p className="text-xs text-soc-muted mb-4">Categories of detected suspicious activity</p>
          <div className="h-56">
            {stats?.detection_categories?.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.detection_categories}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="category" stroke="#64748b" tick={{ fontSize: 10 }} />
                  <YAxis stroke="#64748b" tick={{ fontSize: 10 }} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }} />
                  <Bar dataKey="count" fill="#8b5cf6" radius={[4, 4, 0, 0]} name="Detections" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-soc-muted">No detections categorized.</div>
            )}
          </div>
        </div>
      </div>

      {/* Incident Timeline / Recent Incidents Table */}
      <div className="bg-soc-panel border border-soc-border/70 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Flame className="w-4 h-4 text-red-400" /> Correlated Security Incident Activity
            </h3>
            <p className="text-xs text-soc-muted">High-priority attack sequences undergoing SOC investigation</p>
          </div>
          <Link
            to="/incidents"
            className="text-xs text-soc-accent hover:underline flex items-center gap-1 font-semibold"
          >
            Manage All Incidents <ExternalLink className="w-3.5 h-3.5" />
          </Link>
        </div>

        {stats?.incident_timeline?.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-soc-surface/60 text-soc-muted border-b border-soc-border uppercase text-[10px] font-bold tracking-wider">
                <tr>
                  <th className="p-3">Time</th>
                  <th className="p-3">Incident Title</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Source IP</th>
                  <th className="p-3">Risk Score</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border/40 font-mono">
                {stats.incident_timeline.map((inc) => (
                  <tr key={inc.id} className="hover:bg-soc-surface/30 transition-colors">
                    <td className="p-3 text-soc-muted">{inc.time}</td>
                    <td className="p-3 font-sans font-semibold text-white">{inc.title}</td>
                    <td className="p-3 font-sans"><SeverityBadge severity={inc.severity} /></td>
                    <td className="p-3 text-cyan-400">{inc.source_ip}</td>
                    <td className="p-3 text-amber-300 font-bold">{inc.risk_score}/100</td>
                    <td className="p-3 text-right font-sans">
                      <Link
                        to="/incidents"
                        className="text-xs text-soc-accent hover:underline font-semibold"
                      >
                        Investigate
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-8 text-center text-xs text-soc-muted">
            No incidents detected yet. Upload synthetic logs or monitor server telemetry.
          </div>
        )}
      </div>
    </div>
  );
}
