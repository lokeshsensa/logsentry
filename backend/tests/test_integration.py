import os
from fastapi.testclient import TestClient
from app.main import app
from app.database.session import SessionLocal
from app.database.init_db import init_db

client = TestClient(app)

def setup_module():
    init_db()

def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"

def test_full_pipeline_upload_and_analysis():
    # 1. Upload brute_force.log
    sample_file_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "sample_logs", "brute_force.log"
    )
    with open(sample_file_path, "rb") as f:
        res = client.post(
            "/api/logs/upload",
            files={"file": ("brute_force.log", f, "text/plain")},
            data={"format_type": "LINUX_AUTH"}
        )
    assert res.status_code == 200
    log_source = res.json()
    assert log_source["id"] is not None

    # 2. Start analysis job synchronously
    res_job = client.post(
        "/api/analysis/start?run_sync=true",
        json={"log_source_id": log_source["id"], "profile": "STANDARD"}
    )
    assert res_job.status_code == 200
    job = res_job.json()
    assert job["status"] == "COMPLETED"
    assert job["total_lines"] > 0
    assert job["detections_count"] >= 1
    assert job["incidents_count"] >= 1
    assert job["risk_score"] > 0

    # 3. Verify Events API
    res_events = client.get(f"/api/analysis/{job['id']}/events")
    assert res_events.status_code == 200
    events_data = res_events.json()
    assert events_data["total"] > 0
    assert len(events_data["events"]) > 0

    # 4. Verify Detections API
    res_dets = client.get(f"/api/detections?job_id={job['id']}")
    assert res_dets.status_code == 200
    dets = res_dets.json()
    assert len(dets) >= 1
    assert any(d["attack_type"] == "Brute Force" for d in dets)

    # 5. Verify Incidents API
    res_incs = client.get(f"/api/incidents?job_id={job['id']}")
    assert res_incs.status_code == 200
    incs = res_incs.json()
    assert len(incs) >= 1
    inc_id = incs[0]["id"]

    # Test Incident status update
    res_update = client.patch(f"/api/incidents/{inc_id}", json={"status": "INVESTIGATING"})
    assert res_update.status_code == 200
    assert res_update.json()["status"] == "INVESTIGATING"

    # 6. Verify Dashboard stats
    res_stats = client.get(f"/api/dashboard/stats?job_id={job['id']}")
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert stats["total_events"] > 0
    assert stats["total_detections"] > 0
    assert stats["active_incidents"] > 0

    # 7. Generate PDF Report
    res_rep = client.post("/api/reports/generate", json={"analysis_job_id": job["id"]})
    assert res_rep.status_code == 200
    report_info = res_rep.json()
    assert report_info["id"] is not None

    # Download report
    res_dl = client.get(f"/api/reports/{report_info['id']}/download")
    assert res_dl.status_code == 200
    assert res_dl.headers["content-type"] == "application/pdf"
    assert len(res_dl.content) > 1000
