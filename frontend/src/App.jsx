import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';

import Dashboard from './pages/Dashboard';
import LogUpload from './pages/LogUpload';
import AnalysisHistory from './pages/AnalysisHistory';
import Events from './pages/Events';
import Detections from './pages/Detections';
import Incidents from './pages/Incidents';
import Rules from './pages/Rules';
import Reports from './pages/Reports';
import AuditLogs from './pages/AuditLogs';
import Settings from './pages/Settings';

export default function App() {
  return (
    <Router>
      <div className="min-h-screen bg-soc-bg text-soc-text flex flex-col font-sans">
        <Navbar />
        <div className="flex flex-1 overflow-hidden">
          <Sidebar />
          <main className="flex-1 overflow-y-auto">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/upload" element={<LogUpload />} />
              <Route path="/history" element={<AnalysisHistory />} />
              <Route path="/events" element={<Events />} />
              <Route path="/detections" element={<Detections />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/rules" element={<Rules />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/audit" element={<AuditLogs />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </div>
    </Router>
  );
}
