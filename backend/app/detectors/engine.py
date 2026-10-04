from typing import List, Dict, Optional
from app.parsers.base import ParsedEvent
from app.detectors.base import BaseDetector, DetectionResult
from app.detectors.brute_force import BruteForceDetector
from app.detectors.password_spraying import PasswordSprayingDetector
from app.detectors.account_enumeration import AccountEnumerationDetector
from app.detectors.http_error_spike import HttpErrorSpikeDetector
from app.detectors.request_flooding import RequestFloodingDetector
from app.detectors.scanning import ScanningDetector
from app.detectors.privilege import PrivilegeEventDetector
from app.detectors.suspicious_methods import SuspiciousMethodsDetector
from app.detectors.resource_enumeration import ResourceEnumerationDetector
from app.detectors.access_denied import AccessDeniedDetector
from app.detectors.statistical_anomaly import StatisticalAnomalyDetector
from app.core.logging import logger

class DetectionEngine:
    def __init__(self):
        self.detectors: Dict[str, BaseDetector] = {
            "DET-001": BruteForceDetector(),
            "DET-002": PasswordSprayingDetector(),
            "DET-003": AccountEnumerationDetector(),
            "DET-004": HttpErrorSpikeDetector(),
            "DET-005": RequestFloodingDetector(),
            "DET-006": ScanningDetector(),
            "DET-007": PrivilegeEventDetector(),
            "DET-008": SuspiciousMethodsDetector(),
            "DET-009": ResourceEnumerationDetector(),
            "DET-010": AccessDeniedDetector(),
            "DET-011": StatisticalAnomalyDetector(),
        }

    def sync_rules_from_db(self, db_rules: list):
        """Update detector thresholds and time windows from DB configured rules"""
        for rule in db_rules:
            if rule.rule_id in self.detectors:
                det = self.detectors[rule.rule_id]
                det.update_config(
                    threshold=rule.threshold,
                    time_window=rule.time_window,
                    severity=rule.severity
                )

    def run_detections(
        self,
        events: List[ParsedEvent],
        enabled_rule_ids: Optional[set] = None
    ) -> List[DetectionResult]:
        """
        Execute all active detection rules across normalized events.
        """
        all_results: List[DetectionResult] = []
        
        for rule_id, detector in self.detectors.items():
            if enabled_rule_ids is not None and rule_id not in enabled_rule_ids:
                continue
            try:
                findings = detector.detect(events)
                all_results.extend(findings)
                logger.debug(f"Detector {rule_id} ({detector.name}) produced {len(findings)} findings.")
            except Exception as e:
                logger.error(f"Error running detector {rule_id}: {e}", exc_info=True)

        return all_results

detection_engine = DetectionEngine()
