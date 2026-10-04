import time
from datetime import datetime, timezone
from typing import List, Dict
from sqlalchemy.orm import Session
from app.models.analysis_job import AnalysisJob
from app.models.log_source import LogSource
from app.models.log_event import LogEvent
from app.models.detection import Detection
from app.models.incident import Incident, IncidentEvent
from app.models.rule import DetectionRule
from app.parsers.manager import parser_manager
from app.detectors.engine import detection_engine
from app.correlation.engine import correlation_engine
from app.risk.scorer import risk_scorer
from app.services.audit_service import audit_service
from app.core.logging import logger

BATCH_SIZE = 1000

class AnalysisPipeline:
    @staticmethod
    def run_job(job_id: str, db: Session) -> AnalysisJob:
        start_time = time.time()
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Analysis job {job_id} not found")

        log_source = db.query(LogSource).filter(LogSource.id == job.log_source_id).first()
        if not log_source:
            job.status = "FAILED"
            job.error_message = "Associated log source not found"
            db.commit()
            return job

        try:
            job.status = "PROCESSING"
            db.commit()

            # 1. Parsing & Normalization Stream
            event_gen, stats = parser_manager.parse_file_stream(
                file_path=log_source.file_path,
                format_type=log_source.format_type
            )

            job.detected_format = stats["parser_type"]
            job.parser_type = stats["parser_type"]

            # Stream & batch insert events
            all_events = []
            db_event_models = []
            
            for parsed_ev in event_gen:
                all_events.append(parsed_ev)
                
                # Create DB Model
                log_event_db = LogEvent(
                    analysis_job_id=job.id,
                    line_number=parsed_ev.line_number,
                    timestamp=parsed_ev.timestamp,
                    source_ip=parsed_ev.source_ip,
                    destination_ip=parsed_ev.destination_ip,
                    username=parsed_ev.username,
                    event_type=parsed_ev.event_type,
                    method=parsed_ev.method,
                    endpoint=parsed_ev.endpoint,
                    status_code=parsed_ev.status_code,
                    protocol=parsed_ev.protocol,
                    source_port=parsed_ev.source_port,
                    destination_port=parsed_ev.destination_port,
                    process=parsed_ev.process,
                    message=parsed_ev.message,
                    raw_log=parsed_ev.raw_log,
                    severity=parsed_ev.severity
                )
                db_event_models.append(log_event_db)

                if len(db_event_models) >= BATCH_SIZE:
                    db.bulk_save_objects(db_event_models)
                    db.commit()
                    db_event_models.clear()

            if db_event_models:
                db.bulk_save_objects(db_event_models)
                db.commit()
                db_event_models.clear()

            job.total_lines = stats["total_lines"]
            job.parsed_lines = stats["parsed_lines"]
            job.failed_lines = stats["failed_lines"]
            job.events_count = len(all_events)
            db.commit()

            # Sync detection rules from DB
            db_rules = db.query(DetectionRule).filter(DetectionRule.enabled == True).all()
            detection_engine.sync_rules_from_db(db_rules)
            enabled_rule_ids = {r.rule_id for r in db_rules}

            # Adjust rules based on analysis profile if needed
            if job.profile == "QUICK":
                # Only primary high-severity detectors
                enabled_rule_ids = enabled_rule_ids & {"DET-001", "DET-004", "DET-005", "DET-007", "DET-009"}

            # 2. Run Attack Detection Rules
            detection_findings = detection_engine.run_detections(all_events, enabled_rule_ids=enabled_rule_ids)

            # Store Detections in DB
            db_detections: List[Detection] = []
            for det_res in detection_findings:
                det_db = Detection(
                    analysis_job_id=job.id,
                    rule_id=det_res.rule_id,
                    detector_id=det_res.detector_id,
                    attack_type=det_res.attack_type,
                    title=det_res.title,
                    category=det_res.category,
                    severity=det_res.severity,
                    confidence=det_res.confidence,
                    source_ip=det_res.source_ip,
                    target_endpoint=det_res.target_endpoint,
                    first_seen=det_res.first_seen,
                    last_seen=det_res.last_seen,
                    event_count=det_res.event_count,
                    threshold=det_res.threshold,
                    time_window=det_res.time_window,
                    explanation=det_res.explanation,
                    remediation=det_res.remediation,
                    status="ACTIVE"
                )
                db.add(det_db)
                db_detections.append(det_db)

            db.commit()
            job.detections_count = len(db_detections)

            # 3. Correlate Events and Detections into Incidents
            correlated_incidents = correlation_engine.correlate(detection_findings, all_events)

            # 4. Calculate Risk Scoring
            for inc_data in correlated_incidents:
                risk_info = risk_scorer.calculate_incident_risk(inc_data)
                inc_data.risk_score = risk_info["score"]
                inc_data.risk_level = risk_info["level"]
                inc_data.risk_breakdown = risk_info

            # Overall Job Risk Score
            job_risk = risk_scorer.score_analysis_job(correlated_incidents, total_events=len(all_events))
            job.risk_score = job_risk["score"]
            job.risk_level = job_risk["level"]
            job.risk_explanation = job_risk["explanation"]

            # Map detection DB models by (rule_id, source_ip)
            det_db_map = {(d.rule_id, d.source_ip): d.id for d in db_detections}

            # Map events in memory by line number to DB events
            # For quick link, query events from this job
            sample_job_events = db.query(LogEvent.id, LogEvent.line_number, LogEvent.source_ip).filter(LogEvent.analysis_job_id == job.id).all()
            event_id_by_line = {e.line_number: e.id for e in sample_job_events if e.line_number}

            # Store Incidents & IncidentEvents in DB
            for inc_data in correlated_incidents:
                inc_db = Incident(
                    analysis_job_id=job.id,
                    title=inc_data.title,
                    severity=inc_data.severity,
                    confidence=inc_data.confidence,
                    source_ip=inc_data.source_ip,
                    first_seen=inc_data.first_seen,
                    last_seen=inc_data.last_seen,
                    event_count=inc_data.event_count,
                    risk_score=inc_data.risk_score,
                    risk_level=inc_data.risk_level,
                    explanation=f"{inc_data.explanation}\n\n[RISK SCORING] {inc_data.risk_breakdown.get('breakdown', '')}",
                    remediation=inc_data.remediation,
                    status="NEW"
                )
                db.add(inc_db)
                db.flush()  # populate inc_db.id

                # Link incident events & detections
                for det in inc_data.detections:
                    d_id = det_db_map.get((det.rule_id, det.source_ip))
                    
                    # Link top 10 sample related log events
                    for line_idx in det.related_event_indices[:10]:
                        ev_id = event_id_by_line.get(line_idx)
                        if ev_id:
                            inc_ev = IncidentEvent(
                                incident_id=inc_db.id,
                                log_event_id=ev_id,
                                detection_id=d_id
                            )
                            db.add(inc_ev)
                    
                    if d_id and not det.related_event_indices:
                        inc_ev = IncidentEvent(
                            incident_id=inc_db.id,
                            detection_id=d_id
                        )
                        db.add(inc_ev)

            db.commit()
            job.incidents_count = len(correlated_incidents)

            # 5. Finalize Job
            job.status = "COMPLETED"
            job.duration_seconds = round(time.time() - start_time, 3)
            job.completed_at = datetime.now(timezone.utc)
            db.commit()

            audit_service.log_action(
                db=db,
                action="ANALYSIS_COMPLETED",
                resource=f"AnalysisJob:{job.id}",
                details=f"Processed {job.total_lines} lines ({job.parsed_lines} parsed). Created {job.detections_count} detections, {job.incidents_count} incidents. Risk: {job.risk_score} ({job.risk_level})."
            )

            logger.info(f"Analysis job {job.id} completed successfully in {job.duration_seconds}s.")
            return job

        except Exception as e:
            db.rollback()
            job.status = "FAILED"
            job.error_message = str(e)
            job.completed_at = datetime.now(timezone.utc)
            job.duration_seconds = round(time.time() - start_time, 3)
            db.commit()
            logger.error(f"Analysis job {job.id} failed: {e}", exc_info=True)
            audit_service.log_action(
                db=db,
                action="ANALYSIS_FAILED",
                resource=f"AnalysisJob:{job.id}",
                result="FAILURE",
                details=str(e)
            )
            return job

analysis_pipeline = AnalysisPipeline()
