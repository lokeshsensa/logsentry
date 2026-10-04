# LOGSENTRY — Detection Rules & Threat Matrix

LOGSENTRY incorporates 11 defensive attack detection rules utilizing sliding-window time slicing, horizontal entity divergence, and statistical anomaly detection.

---

## Detection Rules Catalog

| Rule ID | Rule Name | Category | Default Severity | Default Threshold | Default Window | Description |
|---|---|---|---|---|---|---|
| **DET-001** | Brute Force Authentication | Authentication | **HIGH** | 5 failures | 300s (5m) | Identifies rapid, repeated authentication failures originating from a single source IP against one or more accounts. |
| **DET-002** | Password Spraying | Authentication | **HIGH** | 3 distinct users | 600s (10m) | Flags horizontal credential guessing where one IP attempts passwords against multiple distinct user identities. |
| **DET-003** | Account Enumeration | Reconnaissance | **MEDIUM** | 4 invalid users | 300s (5m) | Detects probing against non-existent or administrative user accounts (`guest`, `oracle`, `test`, `admin`). |
| **DET-004** | HTTP Error Spike | Web | **MEDIUM** | 12 errors | 120s (2m) | Identifies anomalous client/server error responses (401, 403, 404, 500) from a single source indicating probing or application crashes. |
| **DET-005** | Request Flooding (DoS) | Anomaly | **HIGH** | 40 requests | 30s | Detects an aggressive request volume spike from a single origin exceeding typical human browsing rates. |
| **DET-006** | Port / Endpoint Scanning | Reconnaissance | **MEDIUM** | 7 targets | 60s (1m) | Flags reconnaissance activity probing multiple distinct endpoints or ports in a compact duration. |
| **DET-007** | Privilege Abuse / Escalation | Privilege | **HIGH** | 2 events | 300s (5m) | Contextually flags suspicious sudo failures, unauthorized su invocations, or commands targeting sensitive files (`/etc/shadow`). |
| **DET-008** | Unusual HTTP Methods | Web | **LOW** | 2 requests | 300s (5m) | Monitors unexpected or dangerous HTTP verbs (PUT, DELETE, TRACE, CONNECT, DEBUG). |
| **DET-009** | Sensitive Resource Enumeration | Reconnaissance | **HIGH** | 3 probes | 180s (3m) | Detects requests probing sensitive hidden files and admin paths (`/.env`, `/admin`, `/config`, `/etc/passwd`, `/.git`). Log-only analysis. |
| **DET-010** | Repeated Access Denied | Web | **MEDIUM** | 4 events | 180s (3m) | Flags persistent 403 Forbidden or authorization denial responses indicating unauthorized access attempts. |
| **DET-011** | Statistical Traffic Anomaly | Anomaly | **MEDIUM** | Z-Score >= 2.5 | 60s | Computes rolling mean and standard deviation of request rate; flags intervals deviating by $\ge 2.5$ standard deviations ($Z = \frac{x-\mu}{\sigma}$). |

---

## Sliding-Window Algorithm Architecture

```python
# Two-pointer sliding window implementation
events.sort(key=lambda x: x.timestamp)
left = 0
while left < n:
    right = left
    while right < n and (events[right].timestamp - events[left].timestamp) <= window_delta:
        right += 1
    
    count = right - left
    if count >= threshold:
        matched = events[left:right]
        create_detection(matched)
        left = right  # Advance past cluster
    else:
        left += 1
```

### Deduplication Policy
When adjacent or overlapping sliding windows trigger the same rule for the same source IP, LOGSENTRY merges them into a single consolidated finding with an expanded temporal range (`first_seen` to `last_seen`), aggregated event count, and comprehensive narrative.

---

## Risk Scoring Formula

```
Risk Score = Base Severity Points (0-40)
           + Frequency Factor (0-20)
           + Confidence Weight (0-15)
           + Correlation Multiplier (0-15)
           + Asset / Critical Context (0-10)
Normalized to [0, 100]
```

### Risk Posture Tiers:
- **0–20**: Low
- **21–40**: Guarded
- **41–60**: Medium
- **61–80**: High
- **81–100**: Critical
