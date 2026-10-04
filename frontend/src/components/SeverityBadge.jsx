import React from 'react';

const SEVERITY_CONFIG = {
  CRITICAL: {
    bg: 'bg-red-500/10 text-red-400 border-red-500/30',
    dot: 'bg-red-500',
  },
  HIGH: {
    bg: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
    dot: 'bg-orange-500',
  },
  MEDIUM: {
    bg: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    dot: 'bg-amber-500',
  },
  LOW: {
    bg: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    dot: 'bg-blue-400',
  },
  INFORMATIONAL: {
    bg: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
    dot: 'bg-slate-400',
  },
};

export default function SeverityBadge({ severity }) {
  const norm = (severity || 'INFORMATIONAL').toUpperCase();
  const conf = SEVERITY_CONFIG[norm] || SEVERITY_CONFIG.INFORMATIONAL;

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${conf.bg}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${conf.dot} animate-pulse`} />
      {norm}
    </span>
  );
}
