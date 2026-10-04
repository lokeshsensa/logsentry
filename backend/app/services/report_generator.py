import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from sqlalchemy.orm import Session

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

from app.models.analysis_job import AnalysisJob
from app.models.detection import Detection
from app.models.incident import Incident
from app.models.log_event import LogEvent
from app.models.report import Report
from app.core.config import settings
from app.core.logging import logger

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        # Header
        self.drawString(54, 750, "LOGSENTRY — Log Analyzer & Attack Detection System | Confidential SOC Report")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 744, 558, 744)
        
        # Footer
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 40, page_text)
        self.drawString(54, 40, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Defensive Operations")
        self.line(54, 50, 558, 50)
        self.restoreState()


class ReportGenerator:
    @staticmethod
    def generate_pdf_report(job_id: str, db: Session) -> Report:
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Analysis job {job_id} not found")

        incidents = db.query(Incident).filter(Incident.analysis_job_id == job_id).all()
        detections = db.query(Detection).filter(Detection.analysis_job_id == job_id).all()
        top_events = (
            db.query(LogEvent.source_ip, LogEvent.severity)
            .filter(LogEvent.analysis_job_id == job_id, LogEvent.source_ip != None)
            .all()
        )

        # Count top IPs
        ip_counts = {}
        for ev in top_events:
            ip_counts[ev.source_ip] = ip_counts.get(ev.source_ip, 0) + 1
        sorted_top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        # File setup
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_filename = f"LOGSENTRY_Report_{job.id[:8]}_{timestamp_str}.pdf"
        report_path = settings.REPORTS_DIR / report_filename

        doc = SimpleDocTemplate(
            str(report_path),
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=60,
            bottomMargin=60
        )

        styles = getSampleStyleSheet()
        primary_color = colors.HexColor("#0f172a")
        accent_blue = colors.HexColor("#0284c7")
        danger_red = colors.HexColor("#b91c1c")
        warning_amber = colors.HexColor("#d97706")
        success_green = colors.HexColor("#16a34a")
        slate_gray = colors.HexColor("#475569")
        light_bg = colors.HexColor("#f8fafc")

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=primary_color,
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            textColor=slate_gray,
            spaceAfter=15
        )
        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=accent_blue,
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            "BodyDark",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor("#1e293b")
        )
        body_bold = ParagraphStyle(
            "BodyDarkBold",
            parent=body_style,
            fontName="Helvetica-Bold"
        )
        code_style = ParagraphStyle(
            "CodeStyle",
            parent=body_style,
            fontName="Courier",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#0f172a")
        )

        story = []

        # Document Header
        story.append(Paragraph("LOGSENTRY — Log Analyzer & Attack Detection System", title_style))
        story.append(Paragraph("SOC INCIDENT ANALYSIS & DEFENSIVE THREAT REPORT", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=accent_blue, spaceAfter=15))

        # 1. Executive Summary
        story.append(Paragraph("1. Executive Summary", h2_style))
        summary_text = (
            f"This security report was generated by the <b>LOGSENTRY</b> automated log analysis platform. "
            f"An analysis was performed on file <b>{job.log_source.original_filename if job.log_source else 'uploaded_log'}</b> "
            f"using the <b>{job.profile}</b> evaluation profile. "
            f"During processing, a total of <b>{job.total_lines:,}</b> raw log entries were ingested, from which <b>{job.parsed_lines:,}</b> "
            f"entries were normalized. The analysis engine uncovered <b>{job.detections_count}</b> atomic attack detection indicators "
            f"and correlated them into <b>{job.incidents_count}</b> actionable security incidents. "
            f"The overall computed security risk score is <b>{job.risk_score}/100</b>, placing the environment at <b>{job.risk_level}</b> risk."
        )
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 10))

        # 2. Analysis Information & 3. Log Statistics Table
        story.append(Paragraph("2. Analysis Information & Log Statistics", h2_style))
        meta_data = [
            [Paragraph("<b>Job ID:</b>", body_style), Paragraph(str(job.id), code_style), Paragraph("<b>Log Format:</b>", body_style), Paragraph(str(job.detected_format or "N/A"), body_style)],
            [Paragraph("<b>Analysis Date:</b>", body_style), Paragraph(job.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"), body_style), Paragraph("<b>Duration:</b>", body_style), Paragraph(f"{job.duration_seconds:.2f} seconds", body_style)],
            [Paragraph("<b>Total Lines:</b>", body_style), Paragraph(f"{job.total_lines:,}", body_style), Paragraph("<b>Parsed Lines:</b>", body_style), Paragraph(f"{job.parsed_lines:,}", body_style)],
            [Paragraph("<b>Failed Lines:</b>", body_style), Paragraph(f"{job.failed_lines:,}", body_style), Paragraph("<b>Analysis Profile:</b>", body_style), Paragraph(str(job.profile), body_style)],
        ]
        meta_table = Table(meta_data, colWidths=[90, 160, 90, 160])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), light_bg),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 12))

        # 4. Security Posture & Risk Overview
        story.append(Paragraph("3. Security Risk Overview", h2_style))
        sev_color = danger_red if job.risk_level in ("CRITICAL", "HIGH") else (warning_amber if job.risk_level == "MEDIUM" else success_green)
        risk_data = [
            [
                Paragraph("<b>Calculated Posture Score:</b>", body_style),
                Paragraph(f"<font color='{sev_color.hexval()}'><b>{job.risk_score} / 100 ({job.risk_level})</b></font>", body_style),
            ],
            [
                Paragraph("<b>Total Detections:</b>", body_style),
                Paragraph(f"{job.detections_count} suspicious indicators", body_style),
            ],
            [
                Paragraph("<b>Correlated Incidents:</b>", body_style),
                Paragraph(f"{job.incidents_count} active incidents", body_style),
            ],
            [
                Paragraph("<b>Scoring Formula:</b>", body_style),
                Paragraph(job.risk_explanation or "Transparent weighted multi-factor risk assessment.", body_style),
            ]
        ]
        risk_table = Table(risk_data, colWidths=[160, 340])
        risk_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), light_bg),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 14))

        # 5. Detected Incidents
        story.append(Paragraph("4. Correlated Security Incidents", h2_style))
        if not incidents:
            story.append(Paragraph("No security incidents were identified during analysis.", body_style))
        else:
            inc_headers = [
                Paragraph("<b>Incident Title</b>", body_bold),
                Paragraph("<b>Severity</b>", body_bold),
                Paragraph("<b>Source IP</b>", body_bold),
                Paragraph("<b>Events</b>", body_bold),
                Paragraph("<b>Risk Score</b>", body_bold),
                Paragraph("<b>Status</b>", body_bold),
            ]
            inc_rows = [inc_headers]
            for inc in incidents:
                inc_rows.append([
                    Paragraph(inc.title[:35], body_style),
                    Paragraph(f"<b>{inc.severity}</b>", body_style),
                    Paragraph(inc.source_ip or "N/A", code_style),
                    Paragraph(str(inc.event_count), body_style),
                    Paragraph(f"{inc.risk_score} ({inc.risk_level})", body_style),
                    Paragraph(inc.status, body_style),
                ])
            inc_table = Table(inc_rows, colWidths=[160, 65, 85, 45, 80, 65])
            inc_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(inc_table)

        story.append(Spacer(1, 14))

        # 6. Detailed Findings (Top 5 Detections)
        story.append(Paragraph("5. Detailed Attack Detection Findings", h2_style))
        if not detections:
            story.append(Paragraph("No detection rules triggered.", body_style))
        else:
            for i, det in enumerate(detections[:6], 1):
                det_content = [
                    Paragraph(f"<b>Finding #{i}: {det.title}</b> [Rule: {det.rule_id} | Severity: <b>{det.severity}</b> | Confidence: {det.confidence}]", body_bold),
                    Spacer(1, 3),
                    Paragraph(f"<b>Source:</b> {det.source_ip or 'Local'} | <b>Target:</b> {det.target_endpoint or 'N/A'} | <b>Observed Events:</b> {det.event_count}", body_style),
                    Spacer(1, 3),
                    Paragraph(f"<b>Explanation:</b> {det.explanation}", body_style),
                    Spacer(1, 3),
                    Paragraph(f"<b>Recommended Action:</b> {det.remediation or 'Investigate host logs.'}", body_style),
                    HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceBefore=4, spaceAfter=8)
                ]
                story.append(KeepTogether(det_content))

        # 7. Top Source IPs Table
        if sorted_top_ips:
            story.append(Paragraph("6. Top Source IP Activity", h2_style))
            ip_rows = [[Paragraph("<b>Source IP</b>", body_bold), Paragraph("<b>Event Count</b>", body_bold), Paragraph("<b>Classification</b>", body_bold)]]
            for ip, cnt in sorted_top_ips:
                is_attack_src = any(d.source_ip == ip for d in detections)
                classification = "Adversary / Scanning" if is_attack_src else "Standard Traffic"
                ip_rows.append([
                    Paragraph(ip, code_style),
                    Paragraph(f"{cnt:,}", body_style),
                    Paragraph(classification, body_style)
                ])
            ip_table = Table(ip_rows, colWidths=[150, 150, 200])
            ip_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(ip_table)
            story.append(Spacer(1, 14))

        # 8. Recommended Remediation & 9. Technical Methodology
        story.append(Paragraph("7. Comprehensive Remediation Recommendations", h2_style))
        remediation_items = [
            "<b>1. Perimeter Ingress Controls:</b> Deploy automated temporary blacklisting (fail2ban/WAF block rules) for IPs exhibiting brute-force, password spraying, or scanning patterns.",
            "<b>2. Identity & Access Hardening:</b> Enforce Multi-Factor Authentication (MFA) across all remote access services (SSH, VPN, Web Portals). Implement account lockout thresholds after 5 consecutive failures.",
            "<b>3. Web Application Shielding:</b> Disable unnecessary HTTP methods (TRACE, TRACK, CONNECT). Ensure administrative endpoints (/admin, /.env, /config) are unreachable from public untrusted subnets.",
            "<b>4. Host-Level Privilege Governance:</b> Restrict sudo privileges to authorized commands. Log and alert on all sudo invocation failures and su attempts.",
            "<b>5. Continuous Log Auditing:</b> Centralize syslog, web access, and application logs into LOGSENTRY for real-time sliding-window correlation."
        ]
        for item in remediation_items:
            story.append(Paragraph(item, body_style))
            story.append(Spacer(1, 3))

        story.append(Spacer(1, 10))
        story.append(Paragraph("8. Technical Detection Methodology", h2_style))
        methodology_text = (
            "LOGSENTRY analyzes logs using a deterministic, multi-stage detection pipeline: "
            "(1) Ingestion & Format Identification; "
            "(2) Streaming Regex & Token Extraction; "
            "(3) Common Normalization into a unified 16-field security data model; "
            "(4) Rule-based Sliding-Window Detection algorithms evaluating temporal frequency and horizontal entity divergence; "
            "(5) Multi-Stage Attack Correlation across authentication, reconnaissance, web, and privilege stages; "
            "(6) Transparent 5-factor mathematical Risk Scoring (0-100 normalized scale). "
            "All findings are defensibly explainable without black-box heuristics."
        )
        story.append(Paragraph(methodology_text, body_style))

        # Build PDF
        doc.build(story, canvasmaker=NumberedCanvas)
        file_size = os.path.getsize(report_path)

        # Store in Report DB model
        report_record = Report(
            analysis_job_id=job.id,
            title=f"Security Audit Report - {job.log_source.original_filename if job.log_source else job.id[:8]}",
            file_path=str(report_path),
            format="PDF",
            file_size_bytes=file_size,
            summary=f"Analysis of {job.total_lines} lines resulted in {job.incidents_count} incidents. Risk: {job.risk_score} ({job.risk_level})."
        )
        db.add(report_record)
        db.commit()

        logger.info(f"Report generated successfully: {report_path} ({file_size} bytes)")
        return report_record

report_generator = ReportGenerator()
