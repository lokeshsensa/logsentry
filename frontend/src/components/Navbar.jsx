import React, { useState, useEffect } from 'react';
import { Shield, Bell, Upload, RefreshCw, Activity } from 'lucide-react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';

export default function Navbar() {
  const [health, setHealth] = useState('ONLINE');
  const [activeIncidents, setActiveIncidents] = useState(0);

  useEffect(() => {
    const checkStatus = async () => {
      try {
        const res = await api.getHealth();
        if (res.data.status === 'HEALTHY') setHealth('ONLINE');
      } catch (err) {
        setHealth('DEGRADED');
      }

      try {
        const stats = await api.getDashboardStats();
        setActiveIncidents(stats.data.active_incidents || 0);
      } catch (e) {}
    };

    checkStatus();
    const interval = setInterval(checkStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-16 border-b border-soc-border/70 bg-soc-panel/90 backdrop-blur-md sticky top-0 z-40 px-6 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-600 to-sky-400 p-0.5 shadow-lg shadow-cyan-500/20">
          <div className="w-full h-full bg-soc-panel rounded-[7px] flex items-center justify-center text-cyan-400">
            <Shield className="w-5 h-5" />
          </div>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-extrabold text-base tracking-wider text-white font-mono">LOGSENTRY</span>
            <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              v1.0 SOC
            </span>
          </div>
          <p className="text-[11px] text-soc-muted -mt-0.5">Defensive Log Analyzer & Attack Detection System</p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* System Health Status */}
        <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full bg-soc-surface/60 border border-soc-border/80 text-xs">
          <span className={`w-2 h-2 rounded-full ${health === 'ONLINE' ? 'bg-emerald-400 animate-ping' : 'bg-amber-400'}`} />
          <span className="font-mono text-[11px] text-soc-muted">SOC ENGINE:</span>
          <span className={`font-mono font-semibold text-[11px] ${health === 'ONLINE' ? 'text-emerald-400' : 'text-amber-400'}`}>
            {health}
          </span>
        </div>

        {/* Quick Upload CTA */}
        <Link
          to="/upload"
          className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-soc-accent hover:bg-sky-400 text-white shadow-lg shadow-sky-500/20 transition-all"
        >
          <Upload className="w-3.5 h-3.5" />
          <span>Upload Log</span>
        </Link>

        {/* Active Incidents Alert */}
        <Link
          to="/incidents"
          className="relative p-2 rounded-lg bg-soc-surface border border-soc-border hover:bg-slate-700 text-slate-300 transition-colors"
          title="Active Security Incidents"
        >
          <Bell className="w-4 h-4" />
          {activeIncidents > 0 && (
            <span className="absolute -top-1 -right-1 px-1.5 py-0.2 rounded-full bg-red-500 text-white font-mono text-[10px] font-bold">
              {activeIncidents}
            </span>
          )}
        </Link>
      </div>
    </header>
  );
}
