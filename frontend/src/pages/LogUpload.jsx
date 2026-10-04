import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  UploadCloud,
  FileCode,
  CheckCircle,
  AlertCircle,
  Play,
  Layers,
  Sparkles,
  ArrowRight,
  ShieldAlert
} from 'lucide-react';
import { api } from '../services/api';

const SAMPLE_LOGS = [
  { name: 'combined_apt_scenario.log', label: 'Multi-Stage APT Scenario (Brute Force + Escalation)', format: 'LINUX_AUTH' },
  { name: 'brute_force.log', label: 'SSH Brute Force Attack (13 Failed Attempts)', format: 'LINUX_AUTH' },
  { name: 'password_spraying.log', label: 'Password Spraying (Multiple Accounts Probed)', format: 'LINUX_AUTH' },
  { name: 'http_error_spike.log', label: 'Web Server HTTP Error Spike (4xx/5xx Burst)', format: 'APACHE_NGINX' },
  { name: 'resource_enumeration.log', label: 'Sensitive Directory Busting (/.env, /admin)', format: 'APACHE_NGINX' },
  { name: 'privilege_abuse.log', label: 'Sudo/Su Privilege Abuse & Escalation Failures', format: 'LINUX_AUTH' },
  { name: 'normal_auth.log', label: 'Benign Baseline Linux Auth (Clean Activity)', format: 'LINUX_AUTH' },
];

const STAGES = [
  'Uploading File',
  'Parsing Raw Entries',
  'Normalizing Common Data Model',
  'Running Attack Detectors (Sliding Window)',
  'Correlating Events & Incidents',
  'Calculating Multi-Factor Risk Score',
  'Completed Analysis'
];

export default function LogUpload() {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [formatType, setFormatType] = useState('AUTO');
  const [profile, setProfile] = useState('STANDARD');
  const [timezone, setTimezone] = useState('UTC');
  const [detectedFormat, setDetectedFormat] = useState(null);
  const [sampleLines, setSampleLines] = useState([]);

  // Progress workflow
  const [isProcessing, setIsProcessing] = useState(false);
  const [currentStage, setCurrentStage] = useState(0);
  const [errorMsg, setErrorMsg] = useState('');
  const [completedJob, setCompletedJob] = useState(null);

  const handleFileChange = async (selectedFile) => {
    if (!selectedFile) return;
    setFile(selectedFile);
    setErrorMsg('');
    setCompletedJob(null);

    // Auto-detect preview
    try {
      const formData = new FormData();
      formData.append('file', selectedFile);
      const res = await api.previewDetectLog(formData);
      setDetectedFormat(res.data.detected_format);
      setSampleLines(res.data.sample_lines || []);
    } catch (err) {
      console.error('Preview detection error:', err);
    }
  };

  const handleSampleSelect = async (sample) => {
    // Fetch synthetic log from server sample directory
    try {
      const res = await fetch(`/sample_logs/${sample.name}`);
      const text = await res.text();
      const blob = new Blob([text], { type: 'text/plain' });
      const sampleFile = new File([blob], sample.name, { type: 'text/plain' });
      setFormatType(sample.format);
      handleFileChange(sampleFile);
    } catch (err) {
      // Fallback: create mock blob
      setErrorMsg(`Could not load local static file directly. Use file upload.`);
    }
  };

  const runAnalysisPipeline = async () => {
    if (!file) {
      setErrorMsg('Please select or drop a log file first.');
      return;
    }

    setIsProcessing(true);
    setErrorMsg('');
    setCurrentStage(0);

    try {
      // Step 1: Upload
      setCurrentStage(0);
      const formData = new FormData();
      formData.append('file', file);
      formData.append('format_type', formatType);

      const uploadRes = await api.uploadLog(formData);
      const logSourceId = uploadRes.data.id;

      // Simulate sequential visual steps for SOC operator clarity
      setCurrentStage(1);
      await new Promise((r) => setTimeout(r, 400));
      setCurrentStage(2);
      await new Promise((r) => setTimeout(r, 400));
      setCurrentStage(3);
      await new Promise((r) => setTimeout(r, 500));
      setCurrentStage(4);

      // Step 2: Trigger Analysis Job
      const jobRes = await api.startAnalysis({
        log_source_id: logSourceId,
        profile: profile,
        timezone_name: timezone,
      }, true);

      setCurrentStage(5);
      await new Promise((r) => setTimeout(r, 400));
      setCurrentStage(6);

      setCompletedJob(jobRes.data);
    } catch (err) {
      console.error('Analysis error:', err);
      setErrorMsg(err.response?.data?.detail || 'Failed to complete analysis pipeline.');
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="p-8 space-y-8 max-w-5xl mx-auto">
      <div>
        <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
          Log Ingestion & Analysis Engine
        </h1>
        <p className="text-xs text-soc-muted mt-1">
          Upload system, authentication, web server, or custom logs for automated parsing and defensive attack correlation.
        </p>
      </div>

      {/* Quick Load Synthetic Attack Datasets */}
      <div className="bg-soc-panel border border-soc-border/70 rounded-xl p-5 shadow-lg">
        <div className="flex items-center gap-2 mb-3">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <h2 className="text-xs font-bold uppercase tracking-wider text-soc-muted">
            Quick Load Synthetic Datasets (One-Click SOC Testing)
          </h2>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
          {SAMPLE_LOGS.map((sample) => (
            <button
              key={sample.name}
              type="button"
              onClick={() => handleSampleSelect(sample)}
              className="text-left p-2.5 rounded-lg bg-soc-surface/40 hover:bg-soc-surface border border-soc-border/60 hover:border-soc-accent/50 transition-all text-xs group"
            >
              <div className="font-semibold text-white group-hover:text-cyan-400 transition-colors">
                {sample.name}
              </div>
              <div className="text-[11px] text-soc-muted truncate mt-0.5">{sample.label}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Drag & Drop Upload Zone */}
      <div className="bg-soc-panel border border-soc-border/70 rounded-xl p-6 shadow-lg space-y-6">
        <label
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            if (e.dataTransfer.files?.[0]) handleFileChange(e.dataTransfer.files[0]);
          }}
          className={`border-2 border-dashed rounded-xl p-8 flex flex-col items-center justify-center cursor-pointer transition-all ${
            file
              ? 'border-soc-accent/60 bg-soc-accent/5'
              : 'border-soc-border hover:border-slate-500 bg-soc-surface/20'
          }`}
        >
          <input
            type="file"
            className="hidden"
            accept=".log,.txt,.syslog"
            onChange={(e) => handleFileChange(e.target.files?.[0])}
          />
          <UploadCloud className={`w-12 h-12 mb-3 ${file ? 'text-soc-accent' : 'text-soc-muted'}`} />
          <div className="text-sm font-semibold text-white">
            {file ? file.name : 'Click to select or drag and drop log file'}
          </div>
          <p className="text-xs text-soc-muted mt-1">
            Supports Linux Auth (/var/log/auth.log), Apache/Nginx combined/common, and Generic application logs. Max 50MB.
          </p>
        </label>

        {/* Detected Format Preview */}
        {detectedFormat && (
          <div className="p-4 rounded-lg bg-cyan-950/20 border border-cyan-800/40 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
                <CheckCircle className="w-4 h-4 text-cyan-400" /> Auto-Detected Format: {detectedFormat}
              </span>
              <span className="text-xs font-mono text-soc-muted">Format confirmed before analysis</span>
            </div>
            {sampleLines.length > 0 && (
              <pre className="p-3 bg-black/60 rounded text-[11px] font-mono text-slate-300 max-h-28 overflow-y-auto leading-relaxed">
                {sampleLines.slice(0, 3).join('\n')}
              </pre>
            )}
          </div>
        )}

        {/* Configuration Selectors */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          {/* Format Selector */}
          <div>
            <label className="text-xs font-semibold uppercase tracking-wider text-soc-muted block mb-1.5">
              Log Format Selector
            </label>
            <select
              value={formatType}
              onChange={(e) => setFormatType(e.target.value)}
              className="w-full bg-soc-surface border border-soc-border rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-soc-accent font-mono"
            >
              <option value="AUTO">AUTO (Auto-Detect Format)</option>
              <option value="LINUX_AUTH">Linux Auth (/var/log/auth.log, secure)</option>
              <option value="APACHE_NGINX">Apache / Nginx Web Access Logs</option>
              <option value="GENERIC">Generic Application Logs</option>
            </select>
          </div>

          {/* Analysis Profile */}
          <div>
            <label className="text-xs font-semibold uppercase tracking-wider text-soc-muted block mb-1.5">
              Analysis Profile
            </label>
            <select
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              className="w-full bg-soc-surface border border-soc-border rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-soc-accent font-mono"
            >
              <option value="STANDARD">STANDARD (All 11 Detection Rules)</option>
              <option value="QUICK">QUICK (High-Severity Attacks Only)</option>
              <option value="DETAILED">DETAILED (Deep Anomaly & Windowing)</option>
            </select>
          </div>

          {/* Time Zone */}
          <div>
            <label className="text-xs font-semibold uppercase tracking-wider text-soc-muted block mb-1.5">
              Log Time Zone
            </label>
            <select
              value={timezone}
              onChange={(e) => setTimezone(e.target.value)}
              className="w-full bg-soc-surface border border-soc-border rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-soc-accent font-mono"
            >
              <option value="UTC">UTC (Universal Coordinated Time)</option>
              <option value="America/New_York">EST / EDT (US Eastern)</option>
              <option value="America/Los_Angeles">PST / PDT (US Pacific)</option>
              <option value="Europe/London">GMT / BST (London)</option>
              <option value="Asia/Kolkata">IST (India Standard Time)</option>
            </select>
          </div>
        </div>

        {errorMsg && (
          <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Progress Stages Monitor */}
        {isProcessing && (
          <div className="p-5 rounded-xl bg-soc-surface/50 border border-soc-border/70 space-y-4 animate-fade-in">
            <div className="flex items-center justify-between text-xs">
              <span className="font-bold text-white flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                Pipeline Execution: {STAGES[currentStage]}
              </span>
              <span className="font-mono text-soc-accent">
                {Math.round(((currentStage + 1) / STAGES.length) * 100)}%
              </span>
            </div>

            {/* Progress Bar */}
            <div className="w-full bg-soc-panel rounded-full h-2 overflow-hidden border border-soc-border/40">
              <div
                className="bg-gradient-to-r from-cyan-500 to-sky-400 h-2 transition-all duration-300"
                style={{ width: `${((currentStage + 1) / STAGES.length) * 100}%` }}
              />
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-[11px]">
              {STAGES.slice(0, 6).map((stage, idx) => (
                <div
                  key={stage}
                  className={`flex items-center gap-1.5 ${
                    idx <= currentStage ? 'text-cyan-400 font-semibold' : 'text-soc-muted'
                  }`}
                >
                  <CheckCircle className={`w-3.5 h-3.5 ${idx <= currentStage ? 'text-cyan-400' : 'text-slate-600'}`} />
                  <span className="truncate">{stage}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Execution Button */}
        {!completedJob && (
          <div className="pt-2">
            <button
              onClick={runAnalysisPipeline}
              disabled={isProcessing || !file}
              className={`w-full py-3 rounded-xl text-xs font-bold flex items-center justify-center gap-2 transition-all shadow-lg ${
                isProcessing || !file
                  ? 'bg-soc-surface text-soc-muted cursor-not-allowed border border-soc-border'
                  : 'bg-soc-accent hover:bg-sky-400 text-white shadow-sky-500/25'
              }`}
            >
              <Play className="w-4 h-4 fill-current" />
              <span>{isProcessing ? 'Analyzing Logs...' : 'Start Defensive Log Analysis'}</span>
            </button>
          </div>
        )}

        {/* Analysis Completed Card */}
        {completedJob && (
          <div className="p-6 rounded-xl bg-gradient-to-r from-emerald-950/30 to-soc-panel border border-emerald-500/40 space-y-4 animate-fade-in">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                <CheckCircle className="w-5 h-5" />
                Analysis Pipeline Successfully Completed
              </div>
              <span className="text-xs font-mono text-soc-muted">
                Completed in {completedJob.duration_seconds}s
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-3 bg-soc-surface/40 rounded-lg border border-soc-border/40">
                <span className="text-soc-muted block">Parsed Lines</span>
                <span className="font-mono text-white font-bold">{completedJob.parsed_lines?.toLocaleString()}</span>
              </div>
              <div className="p-3 bg-soc-surface/40 rounded-lg border border-soc-border/40">
                <span className="text-soc-muted block">Detections</span>
                <span className="font-mono text-amber-300 font-bold">{completedJob.detections_count}</span>
              </div>
              <div className="p-3 bg-soc-surface/40 rounded-lg border border-soc-border/40">
                <span className="text-soc-muted block">Incidents</span>
                <span className="font-mono text-red-400 font-bold">{completedJob.incidents_count}</span>
              </div>
              <div className="p-3 bg-soc-surface/40 rounded-lg border border-soc-border/40">
                <span className="text-soc-muted block">Risk Score</span>
                <span className="font-mono text-cyan-400 font-bold">{completedJob.risk_score} ({completedJob.risk_level})</span>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => {
                  setCompletedJob(null);
                  setFile(null);
                }}
                className="px-4 py-2 rounded-lg text-xs font-medium bg-soc-surface hover:bg-slate-700 text-white border border-soc-border"
              >
                Upload Another Log
              </button>
              <button
                onClick={() => navigate('/')}
                className="px-4 py-2 rounded-lg text-xs font-bold bg-soc-accent hover:bg-sky-400 text-white flex items-center gap-1.5 shadow-lg shadow-sky-500/20"
              >
                View in Dashboard <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
