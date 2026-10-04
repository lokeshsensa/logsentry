import React from 'react';

export default function LoadingSpinner({ size = 'md', text = 'Loading data...' }) {
  const sizes = {
    sm: 'w-4 h-4',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
  };

  return (
    <div className="flex flex-col items-center justify-center p-8 gap-3">
      <div className={`${sizes[size]} border-2 border-soc-accent/20 border-t-soc-accent rounded-full animate-spin`} />
      {text && <span className="text-xs font-mono text-soc-muted tracking-wide animate-pulse">{text}</span>}
    </div>
  );
}
