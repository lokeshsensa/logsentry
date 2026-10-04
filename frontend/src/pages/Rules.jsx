import React, { useState, useEffect } from 'react';
import { Sliders, CheckCircle, Edit2, Shield, RefreshCw, X, Save } from 'lucide-react';
import { api } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import LoadingSpinner from '../components/LoadingSpinner';

export default function Rules() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editingRule, setEditingRule] = useState(null);
  const [thresholdVal, setThresholdVal] = useState(0);
  const [timeWindowVal, setTimeWindowVal] = useState(0);
  const [severityVal, setSeverityVal] = useState('HIGH');
  const [saving, setSaving] = useState(false);

  const fetchRules = async () => {
    try {
      setLoading(true);
      const res = await api.getRules();
      setRules(res.data);
    } catch (err) {
      console.error('Failed to load rules:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleToggle = async (rule) => {
    try {
      const res = await api.updateRule(rule.id, { enabled: !rule.enabled });
      setRules((prev) => prev.map((r) => (r.id === rule.id ? res.data : r)));
    } catch (err) {
      alert('Failed to toggle rule: ' + (err.response?.data?.detail || err.message));
    }
  };

  const openEditModal = (rule) => {
    setEditingRule(rule);
    setThresholdVal(rule.threshold);
    setTimeWindowVal(rule.time_window);
    setSeverityVal(rule.severity);
  };

  const handleSaveRule = async (e) => {
    e.preventDefault();
    if (!editingRule) return;
    setSaving(true);
    try {
      const res = await api.updateRule(editingRule.id, {
        threshold: parseFloat(thresholdVal),
        time_window: parseInt(timeWindowVal, 10),
        severity: severityVal,
      });
      setRules((prev) => prev.map((r) => (r.id === editingRule.id ? res.data : r)));
      setEditingRule(null);
    } catch (err) {
      alert('Failed to update rule parameters: ' + (err.response?.data?.detail || err.message));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
            <Sliders className="w-6 h-6 text-soc-accent" /> Detection Rule Policies
          </h1>
          <p className="text-xs text-soc-muted mt-1">
            Configure sliding-window event thresholds, temporal windows, and sensitivity parameters
          </p>
        </div>
        <button
          onClick={fetchRules}
          className="p-2 rounded-lg bg-soc-surface border border-soc-border text-soc-muted hover:text-white"
          title="Refresh Rules"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {loading ? (
        <LoadingSpinner text="Loading detection rule policies..." />
      ) : (
        <div className="bg-soc-panel border border-soc-border/70 rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-soc-surface/60 text-soc-muted border-b border-soc-border uppercase text-[10px] font-bold tracking-wider">
                <tr>
                  <th className="p-3.5">Rule ID</th>
                  <th className="p-3.5">Rule Name</th>
                  <th className="p-3.5">Category</th>
                  <th className="p-3.5">Severity</th>
                  <th className="p-3.5">Threshold</th>
                  <th className="p-3.5">Window</th>
                  <th className="p-3.5">Status</th>
                  <th className="p-3.5 text-right">Configure</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border/40 font-mono">
                {rules.map((rule) => (
                  <tr key={rule.id} className="hover:bg-soc-surface/30 transition-colors">
                    <td className="p-3.5 text-cyan-400 font-bold">{rule.rule_id}</td>
                    <td className="p-3.5 font-sans font-semibold text-white">
                      <div>{rule.name}</div>
                      <div className="text-[11px] text-soc-muted font-normal mt-0.5 line-clamp-1">
                        {rule.description}
                      </div>
                    </td>
                    <td className="p-3.5 font-sans text-soc-muted">{rule.category}</td>
                    <td className="p-3.5 font-sans"><SeverityBadge severity={rule.severity} /></td>
                    <td className="p-3.5 text-amber-300 font-bold">{rule.threshold} events</td>
                    <td className="p-3.5 text-slate-300">{rule.time_window}s ({Math.round(rule.time_window / 60)}m)</td>
                    <td className="p-3.5 font-sans">
                      <button
                        onClick={() => handleToggle(rule)}
                        className={`px-2.5 py-1 rounded text-[11px] font-bold border transition-colors ${
                          rule.enabled
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            : 'bg-slate-700/40 text-slate-400 border-slate-600'
                        }`}
                      >
                        {rule.enabled ? 'ENABLED' : 'DISABLED'}
                      </button>
                    </td>
                    <td className="p-3.5 text-right font-sans">
                      <button
                        onClick={() => openEditModal(rule)}
                        className="px-2.5 py-1 rounded bg-soc-surface border border-soc-border hover:bg-slate-700 text-soc-muted hover:text-white inline-flex items-center gap-1 text-[11px]"
                      >
                        <Edit2 className="w-3 h-3" /> Tune
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Edit Rule Threshold Modal */}
      {editingRule && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="bg-soc-panel border border-soc-border rounded-xl w-full max-w-lg p-6 shadow-2xl space-y-5">
            <div className="flex items-center justify-between border-b border-soc-border pb-3">
              <div>
                <span className="text-xs font-mono text-cyan-400">{editingRule.rule_id}</span>
                <h3 className="text-base font-bold text-white">{editingRule.name}</h3>
              </div>
              <button
                onClick={() => setEditingRule(null)}
                className="p-1 rounded text-soc-muted hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSaveRule} className="space-y-4 text-xs">
              <div>
                <label className="block text-soc-muted uppercase font-semibold mb-1">
                  Threshold (Event Count Trigger)
                </label>
                <input
                  type="number"
                  step="0.5"
                  value={thresholdVal}
                  onChange={(e) => setThresholdVal(e.target.value)}
                  className="w-full px-3 py-2 bg-soc-surface border border-soc-border rounded-lg text-white font-mono focus:outline-none focus:border-soc-accent"
                  required
                />
              </div>

              <div>
                <label className="block text-soc-muted uppercase font-semibold mb-1">
                  Sliding Time Window (Seconds)
                </label>
                <input
                  type="number"
                  value={timeWindowVal}
                  onChange={(e) => setTimeWindowVal(e.target.value)}
                  className="w-full px-3 py-2 bg-soc-surface border border-soc-border rounded-lg text-white font-mono focus:outline-none focus:border-soc-accent"
                  required
                />
              </div>

              <div>
                <label className="block text-soc-muted uppercase font-semibold mb-1">
                  Severity Level
                </label>
                <select
                  value={severityVal}
                  onChange={(e) => setSeverityVal(e.target.value)}
                  className="w-full px-3 py-2 bg-soc-surface border border-soc-border rounded-lg text-white focus:outline-none focus:border-soc-accent"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-soc-border">
                <button
                  type="button"
                  onClick={() => setEditingRule(null)}
                  className="px-4 py-2 rounded-lg bg-soc-surface text-soc-muted hover:text-white border border-soc-border"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="px-4 py-2 rounded-lg bg-soc-accent hover:bg-sky-400 text-white font-bold flex items-center gap-1.5"
                >
                  <Save className="w-3.5 h-3.5" />
                  {saving ? 'Saving...' : 'Save Parameters'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
