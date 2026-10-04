import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Search, Filter, RefreshCw, Terminal, Eye, ChevronLeft, ChevronRight } from 'lucide-react';
import { api } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import EventModal from '../components/EventModal';
import LoadingSpinner from '../components/LoadingSpinner';

export default function Events() {
  const [searchParams] = useSearchParams();
  const initialJobId = searchParams.get('job_id') || '';

  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState(null);

  // Filters state
  const [jobs, setJobs] = useState([]);
  const [jobId, setJobId] = useState(initialJobId);
  const [search, setSearch] = useState('');
  const [sourceIp, setSourceIp] = useState('');
  const [username, setUsername] = useState('');
  const [eventType, setEventType] = useState('');
  const [severity, setSeverity] = useState('');
  const [statusCode, setStatusCode] = useState('');

  // Pagination
  const [page, setPage] = useState(0);
  const limit = 50;

  useEffect(() => {
    // Load job list
    api.getAnalysisJobs({ limit: 30 }).then((res) => {
      setJobs(res.data);
      if (!jobId && res.data.length > 0) {
        setJobId(res.data[0].id);
      }
    });
  }, []);

  const fetchEvents = async () => {
    if (!jobId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const params = {
        limit,
        offset: page * limit,
        search: search || undefined,
        source_ip: sourceIp || undefined,
        username: username || undefined,
        event_type: eventType || undefined,
        severity: severity || undefined,
        status_code: statusCode ? parseInt(statusCode, 10) : undefined,
      };

      const res = await api.getAnalysisEvents(jobId, params);
      setEvents(res.data.events || []);
      setTotal(res.data.total || 0);
    } catch (err) {
      console.error('Failed to load events:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [jobId, page, severity, eventType]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(0);
    fetchEvents();
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
            <Terminal className="w-6 h-6 text-soc-accent" /> Normalized Log Events Explorer
          </h1>
          <p className="text-xs text-soc-muted mt-1">
            Search, filter, and inspect normalized 16-field security log structures and raw payloads
          </p>
        </div>

        {/* Job Selector */}
        <div className="flex items-center gap-3">
          <select
            value={jobId}
            onChange={(e) => {
              setJobId(e.target.value);
              setPage(0);
            }}
            className="bg-soc-surface border border-soc-border text-xs rounded-lg px-3 py-2 text-white font-mono focus:outline-none focus:border-soc-accent"
          >
            {jobs.map((j) => (
              <option key={j.id} value={j.id}>
                Job #{j.id.slice(0, 8)} ({j.total_lines} lines - {j.status})
              </option>
            ))}
          </select>
          <button
            onClick={fetchEvents}
            className="p-2 rounded-lg bg-soc-surface border border-soc-border text-soc-muted hover:text-white"
            title="Refresh Events"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <form onSubmit={handleSearchSubmit} className="bg-soc-panel border border-soc-border/70 rounded-xl p-4 shadow-lg space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2.5">
          {/* Free Text Search */}
          <div className="lg:col-span-2 relative">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-soc-muted" />
            <input
              type="text"
              placeholder="Search raw log, message, path..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-2 bg-soc-surface border border-soc-border rounded-lg text-xs text-white placeholder-soc-muted focus:outline-none focus:border-soc-accent"
            />
          </div>

          {/* Source IP */}
          <input
            type="text"
            placeholder="Source IP..."
            value={sourceIp}
            onChange={(e) => setSourceIp(e.target.value)}
            className="px-3 py-2 bg-soc-surface border border-soc-border rounded-lg text-xs text-white placeholder-soc-muted focus:outline-none focus:border-soc-accent font-mono"
          />

          {/* Username */}
          <input
            type="text"
            placeholder="Username..."
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="px-3 py-2 bg-soc-surface border border-soc-border rounded-lg text-xs text-white placeholder-soc-muted focus:outline-none focus:border-soc-accent"
          />

          {/* Event Type */}
          <select
            value={eventType}
            onChange={(e) => {
              setEventType(e.target.value);
              setPage(0);
            }}
            className="px-3 py-2 bg-soc-surface border border-soc-border rounded-lg text-xs text-white focus:outline-none focus:border-soc-accent"
          >
            <option value="">All Event Types</option>
            <option value="AUTH_FAILURE">AUTH_FAILURE</option>
            <option value="AUTH_SUCCESS">AUTH_SUCCESS</option>
            <option value="HTTP_REQUEST">HTTP_REQUEST</option>
            <option value="HTTP_ERROR">HTTP_ERROR</option>
            <option value="ACCESS_DENIED">ACCESS_DENIED</option>
            <option value="PRIVILEGE_EVENT">PRIVILEGE_EVENT</option>
            <option value="SYSTEM_EVENT">SYSTEM_EVENT</option>
          </select>

          {/* Severity */}
          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value);
              setPage(0);
            }}
            className="px-3 py-2 bg-soc-surface border border-soc-border rounded-lg text-xs text-white focus:outline-none focus:border-soc-accent"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="INFORMATIONAL">INFORMATIONAL</option>
          </select>
        </div>

        <div className="flex items-center justify-between pt-1">
          <span className="text-xs text-soc-muted font-mono">
            Showing {events.length} of {total.toLocaleString()} matching records
          </span>
          <button
            type="submit"
            className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-soc-accent hover:bg-sky-400 text-white transition-colors"
          >
            Apply Filters
          </button>
        </div>
      </form>

      {/* Events Table */}
      {loading ? (
        <LoadingSpinner text="Streaming normalized events from storage..." />
      ) : events.length === 0 ? (
        <div className="bg-soc-panel border border-soc-border rounded-xl p-12 text-center text-soc-muted">
          No log events matched your search filters.
        </div>
      ) : (
        <div className="bg-soc-panel border border-soc-border/70 rounded-xl overflow-hidden shadow-lg space-y-3">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-soc-surface/60 text-soc-muted border-b border-soc-border uppercase text-[10px] font-bold tracking-wider">
                <tr>
                  <th className="p-3 w-16">Line</th>
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">Source IP</th>
                  <th className="p-3">User</th>
                  <th className="p-3">Event Type</th>
                  <th className="p-3">Resource / Endpoint</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border/40 font-mono text-[11px]">
                {events.map((ev) => (
                  <tr
                    key={ev.id}
                    onClick={() => setSelectedEvent(ev)}
                    className="hover:bg-soc-surface/40 transition-colors cursor-pointer"
                  >
                    <td className="p-3 text-soc-muted">#{ev.line_number}</td>
                    <td className="p-3 text-slate-300">
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'N/A'}
                    </td>
                    <td className="p-3 text-cyan-400 font-semibold">{ev.source_ip || '-'}</td>
                    <td className="p-3 text-amber-300">{ev.username || '-'}</td>
                    <td className="p-3 text-slate-200 font-sans">{ev.event_type}</td>
                    <td className="p-3 text-emerald-400 max-w-xs truncate">
                      {ev.method ? `${ev.method} ` : ''}{ev.endpoint || ev.message?.slice(0, 45)}
                    </td>
                    <td className="p-3 text-white">
                      {ev.status_code || (ev.source_port ? `p:${ev.source_port}` : '-')}
                    </td>
                    <td className="p-3 font-sans"><SeverityBadge severity={ev.severity} /></td>
                    <td className="p-3 text-right font-sans">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(ev);
                        }}
                        className="p-1 rounded text-soc-muted hover:text-soc-accent hover:bg-soc-surface"
                        title="View Raw and Normalized Event"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          <div className="flex items-center justify-between p-4 border-t border-soc-border/60 text-xs">
            <span className="text-soc-muted">
              Page {page + 1} of {Math.max(1, Math.ceil(total / limit))}
            </span>
            <div className="flex items-center gap-2">
              <button
                disabled={page === 0}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                className="px-3 py-1.5 rounded bg-soc-surface border border-soc-border text-white disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-700 flex items-center gap-1"
              >
                <ChevronLeft className="w-3.5 h-3.5" /> Prev
              </button>
              <button
                disabled={(page + 1) * limit >= total}
                onClick={() => setPage((p) => p + 1)}
                className="px-3 py-1.5 rounded bg-soc-surface border border-soc-border text-white disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-700 flex items-center gap-1"
              >
                Next <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Event Details Inspection Modal */}
      {selectedEvent && (
        <EventModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </div>
  );
}
