import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

export const api = {
  // Health
  getHealth: () => apiClient.get('/health'),

  // Logs
  uploadLog: (formData) => apiClient.post('/logs/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  }),
  previewDetectLog: (formData) => apiClient.post('/logs/preview-detect', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  }),
  getLogSources: () => apiClient.get('/logs/sources'),

  // Analysis
  startAnalysis: (payload, sync = true) => apiClient.post(`/analysis/start?run_sync=${sync}`, payload),
  getAnalysisJobs: (params) => apiClient.get('/analysis', { params }),
  getAnalysisJob: (id) => apiClient.get(`/analysis/${id}`),
  getAnalysisEvents: (id, params) => apiClient.get(`/analysis/${id}/events`, { params }),

  // Detections
  getDetections: (params) => apiClient.get('/detections', { params }),
  getDetection: (id) => apiClient.get(`/detections/${id}`),

  // Incidents
  getIncidents: (params) => apiClient.get('/incidents', { params }),
  getIncident: (id) => apiClient.get(`/incidents/${id}`),
  updateIncidentStatus: (id, status) => apiClient.patch(`/incidents/${id}`, { status }),

  // Dashboard Stats
  getDashboardStats: (jobId) => apiClient.get('/dashboard/stats', { params: jobId ? { job_id: jobId } : {} }),

  // Rules
  getRules: () => apiClient.get('/rules'),
  updateRule: (id, payload) => apiClient.patch(`/rules/${id}`, payload),

  // Reports
  generateReport: (analysisJobId) => apiClient.post('/reports/generate', { analysis_job_id: analysisJobId }),
  getReports: () => apiClient.get('/reports'),
  getReportDownloadUrl: (id) => `${API_BASE_URL}/reports/${id}/download`,

  // Audit
  getAuditLogs: (params) => apiClient.get('/audit', { params }),
};
