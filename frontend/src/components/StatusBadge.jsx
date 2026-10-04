import React from 'react';

const STATUS_CONFIG = {
  NEW: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
  INVESTIGATING: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  RESOLVED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  FALSE_POSITIVE: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
  PENDING: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
  PROCESSING: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
  COMPLETED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  FAILED: 'bg-red-500/10 text-red-400 border-red-500/30',
  ACTIVE: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
};

export default function StatusBadge({ status }) {
  const norm = (status || 'NEW').toUpperCase();
  const style = STATUS_CONFIG[norm] || 'bg-slate-700/50 text-slate-300 border-slate-600';

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${style}`}>
      {norm}
    </span>
  );
}
