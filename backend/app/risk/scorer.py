from typing import Dict, Any, List, Optional
from app.correlation.engine import CorrelatedIncidentData

SEVERITY_WEIGHTS = {
    "INFORMATIONAL": 1.0,
    "LOW": 2.0,
    "MEDIUM": 5.0,
    "HIGH": 8.0,
    "CRITICAL": 10.0,
}

CONFIDENCE_WEIGHTS = {
    "LOW": 3.0,
    "MEDIUM": 8.0,
    "HIGH": 15.0,
}

class RiskScorer:
    """
    Transparent, explainable risk scoring system.
    Risk Score (0–100) = Base Severity (0-40) + Frequency (0-20) + Confidence (0-15) + Correlation (0-15) + Asset/Context (0-10)
    """

    @staticmethod
    def calculate_incident_risk(incident: CorrelatedIncidentData) -> Dict[str, Any]:
        sev_upper = incident.severity.upper()
        conf_upper = incident.confidence.upper()

        # 1. Base Severity (Max 40 points)
        sev_val = SEVERITY_WEIGHTS.get(sev_upper, 2.0)
        base_points = sev_val * 4.0  # (1..10) * 4 = 4..40

        # 2. Frequency Factor (Max 20 points)
        count = incident.event_count
        if count <= 1:
            freq_points = 3.0
        elif count <= 5:
            freq_points = 7.0
        elif count <= 20:
            freq_points = 12.0
        elif count <= 50:
            freq_points = 16.0
        else:
            freq_points = 20.0

        # 3. Confidence Factor (Max 15 points)
        conf_points = CONFIDENCE_WEIGHTS.get(conf_upper, 8.0)

        # 4. Correlation Multiplier Factor (Max 15 points)
        stage_count = len(incident.attack_stages)
        det_count = len(incident.detections)
        if stage_count >= 3 or det_count >= 3:
            corr_points = 15.0
        elif stage_count == 2 or det_count == 2:
            corr_points = 8.0
        else:
            corr_points = 2.0

        # 5. Asset / Context Factor (Max 10 points)
        # Higher if targeting root, admin, /etc/shadow, /.env, or privilege escalation
        context_points = 3.0
        expl_lower = incident.explanation.lower()
        title_lower = incident.title.lower()
        if any(kw in expl_lower or kw in title_lower for kw in ("root", "admin", "privilege escalation", "/.env", "/etc/shadow", "takeover")):
            context_points = 10.0
        elif any(kw in expl_lower or kw in title_lower for kw in ("sudo", "database", "credential", "brute force")):
            context_points = 7.0

        raw_score = base_points + freq_points + conf_points + corr_points + context_points
        normalized_score = round(max(0.0, min(100.0, raw_score)), 1)

        # Assign Risk Level
        if normalized_score <= 20.0:
            level = "LOW"
        elif normalized_score <= 40.0:
            level = "GUARDED"
        elif normalized_score <= 60.0:
            level = "MEDIUM"
        elif normalized_score <= 80.0:
            level = "HIGH"
        else:
            level = "CRITICAL"

        formula_breakdown = (
            f"Risk Score = {normalized_score}/100. "
            f"Calculation breakdown: Base Severity ({sev_upper}): {base_points:.1f} pts; "
            f"Frequency ({count} events): {freq_points:.1f} pts; "
            f"Confidence ({conf_upper}): {conf_points:.1f} pts; "
            f"Correlation ({stage_count} stages, {det_count} detectors): {corr_points:.1f} pts; "
            f"Context / Critical Asset: {context_points:.1f} pts. "
            f"Total = {base_points:.1f} + {freq_points:.1f} + {conf_points:.1f} + {corr_points:.1f} + {context_points:.1f} = {normalized_score} ({level})."
        )

        return {
            "score": normalized_score,
            "level": level,
            "base_points": base_points,
            "frequency_points": freq_points,
            "confidence_points": conf_points,
            "correlation_points": corr_points,
            "context_points": context_points,
            "breakdown": formula_breakdown
        }

    @staticmethod
    def score_analysis_job(incidents: List[CorrelatedIncidentData], total_events: int) -> Dict[str, Any]:
        """
        Aggregate overall risk posture score for an entire analysis job.
        """
        if not incidents:
            return {
                "score": 0.0,
                "level": "LOW",
                "explanation": "No security detections or suspicious incidents identified in analyzed logs."
            }

        max_incident_score = max((inc.risk_score for inc in incidents), default=0.0)
        # Weighted combination of peak incident risk + incident volume
        volume_factor = min(20.0, len(incidents) * 4.0)
        job_score = round(min(100.0, (max_incident_score * 0.8) + volume_factor), 1)

        if job_score <= 20.0:
            level = "LOW"
        elif job_score <= 40.0:
            level = "GUARDED"
        elif job_score <= 60.0:
            level = "MEDIUM"
        elif job_score <= 80.0:
            level = "HIGH"
        else:
            level = "CRITICAL"

        explanation = (
            f"Overall Job Risk Score: {job_score}/100 ({level}). "
            f"Evaluated {len(incidents)} security incidents across {total_events} parsed events. "
            f"Peak incident risk score is {max_incident_score:.1f}."
        )

        return {
            "score": job_score,
            "level": level,
            "explanation": explanation
        }

risk_scorer = RiskScorer()
