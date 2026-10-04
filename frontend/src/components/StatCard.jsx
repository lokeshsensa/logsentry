import React from 'react';

export default function StatCard({ title, value, subtitle, icon: Icon, color = 'cyan', badge }) {
  const colorMap = {
    cyan: 'text-cyan-400 border-cyan-500/20 bg-cyan-500/5',
    red: 'text-red-400 border-red-500/20 bg-red-500/5',
    amber: 'text-amber-400 border-amber-500/20 bg-amber-500/5',
    emerald: 'text-emerald-400 border-emerald-500/20 bg-emerald-500/5',
    indigo: 'text-indigo-400 border-indigo-500/20 bg-indigo-500/5',
    purple: 'text-purple-400 border-purple-500/20 bg-purple-500/5',
  };

  const selectedColor = colorMap[color] || colorMap.cyan;

  return (
    <div className="bg-soc-panel border border-soc-border/70 rounded-xl p-5 shadow-lg backdrop-blur-sm relative overflow-hidden transition-all duration-200 hover:border-soc-border">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-soc-muted">{title}</span>
        {Icon && (
          <div className={`p-2 rounded-lg border ${selectedColor}`}>
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>
      
      <div className="mt-3 flex items-baseline gap-2">
        <span className="text-2xl font-bold tracking-tight text-white font-mono">{value}</span>
        {badge && (
          <span className="text-xs font-medium px-2 py-0.5 rounded bg-soc-surface border border-soc-border text-soc-muted">
            {badge}
          </span>
        )}
      </div>

      {subtitle && (
        <p className="mt-1 text-xs text-soc-muted truncate">{subtitle}</p>
      )}
    </div>
  );
}
