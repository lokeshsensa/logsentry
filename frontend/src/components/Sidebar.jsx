import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  UploadCloud,
  History,
  ListFilter,
  ShieldAlert,
  Flame,
  Sliders,
  FileBarChart,
  ClipboardList,
  Settings as SettingsIcon
} from 'lucide-react';

const NAV_ITEMS = [
  { path: '/', label: 'SOC Dashboard', icon: LayoutDashboard },
  { path: '/upload', label: 'Upload Log', icon: UploadCloud },
  { path: '/history', label: 'Analysis Jobs', icon: History },
  { path: '/events', label: 'Log Events', icon: ListFilter },
  { path: '/detections', label: 'Detections', icon: ShieldAlert },
  { path: '/incidents', label: 'Incidents', icon: Flame },
  { path: '/rules', label: 'Detection Rules', icon: Sliders },
  { path: '/reports', label: 'Security Reports', icon: FileBarChart },
  { path: '/audit', label: 'Audit Trail', icon: ClipboardList },
  { path: '/settings', label: 'SOC Settings', icon: SettingsIcon },
];

export default function Sidebar() {
  return (
    <aside className="w-64 border-r border-soc-border/70 bg-soc-panel flex flex-col justify-between shrink-0 min-h-[calc(100vh-4rem)]">
      <div className="p-4 space-y-1">
        <div className="px-3 py-2 text-[11px] font-bold uppercase tracking-wider text-soc-muted">
          SOC Operations
        </div>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-soc-accent/15 text-soc-accent border border-soc-accent/30 font-semibold'
                    : 'text-slate-400 hover:text-white hover:bg-soc-surface/60'
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </div>

      {/* Defensive Footer Banner */}
      <div className="p-4 border-t border-soc-border/60">
        <div className="p-3 rounded-lg bg-soc-surface/40 border border-soc-border/60">
          <span className="text-[10px] font-bold tracking-wider uppercase text-emerald-400 block flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            Defensive Mode
          </span>
          <p className="text-[11px] text-soc-muted mt-1 leading-snug">
            Authorized local inspection only. Offensive automation disabled.
          </p>
        </div>
      </div>
    </aside>
  );
}
