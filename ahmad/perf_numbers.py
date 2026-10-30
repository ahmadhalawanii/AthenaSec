#!/usr/bin/env python3
"""AthenaSec performance and reliability numbers. Standard library only.

Works against any running agent (local or lab host). It sends alerts to
POST /api/v1/analyze and reads them back with GET /api/v1/investigations/{alert_id}.

Usage:
  python perf_numbers.py run    [--base-url http://localhost:8000] [--n 10]
  # restart the agent process or container, then:
  python perf_numbers.py verify [--base-url http://localhost:8000]

'run' saves the alert IDs it created to perf_state.json. 'verify' re-reads them
after the restart and also sends one new alert. Results print as a table and are
written to perf_results_<mode>.json. No secrets are involved.
"""
import argparse
import json
import statistics
import sys
import time
import urllib.error
import urllib.request
import uuid

STATE = "perf_state.json"


def call(method, url, body=None, timeout=300):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw, status = exc.read().decode(), exc.code
    except Exception as exc:  # connection refused, timeout
        return None, None, time.perf_counter() - start, type(exc).__name__
    elapsed = time.perf_counter() - start
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = None
    return status, parsed, elapsed, None


def alert(alert_id):
    return {
        "alert_id": alert_id,
        "source": "manual",
        "event_text": "148 failed SSH login attempts against root.",
        "metadata": {
            "source_ip": "203.0.113.50",
            "target_user": "root",
            "failed_attempts": 148,
            "privileged_target": True,
            "asset_criticality": "high",
        },
    }


def send_one(base, alert_id):
    return call("POST", f"{base}/api/v1/analyze", alert(alert_id))


def summarize(times):
    if not times:
        return "n/a"
    s = sorted(times)
    p95 = s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]
    return (f"min {s[0]:.2f}s  median {statistics.median(s):.2f}s  "
            f"p95 {p95:.2f}s  max {s[-1]:.2f}s  (n={len(s)})")


def run(base, n):
    runid = uuid.uuid4().hex[:6]
    results, ids, times, errors = [], [], [], []
    print(f"Sending {n} distinct alerts to {base} (run {runid})...")
    for i in range(n):
        aid = f"ALT-PERF-{runid}-{i:03d}"
        status, body, elapsed, err = send_one(base, aid)
        ok = status == 200 and isinstance(body, dict)
        print(f"  {aid}: status={status} err={err} {elapsed:.2f}s")
        if ok:
            ids.append(aid)
            times.append(elapsed)
            results.append(body)
        else:
            errors.append({"alert_id": aid, "status": status, "error": err})

    # read back
    found, inv_ids, read_status = 0, set(), set()
    for aid in ids:
        status, body, _, _ = call("GET", f"{base}/api/v1/investigations/{aid}")
        read_status.add(status)
        if status == 200 and isinstance(body, dict):
            found += 1
            if body.get("investigation_id"):
                inv_ids.add(body["investigation_id"])

    first = results[0] if results else {}
    out = {
        "mode": "run",
        "base_url": base,
        "alerts_sent": n,
        "alerts_ok": len(ids),
        "errors": errors,
        "analyze_latency": summarize(times),
        "first_alert_seconds": round(times[0], 2) if times else None,
        "read_back_found": found,
        "distinct_investigation_ids": len(inv_ids),
        "read_back_http_statuses": sorted(s for s in read_status if s),
        "first_alert_status_field": first.get("status"),
        "has_policy_or_response_fields": [
            k for k in first
            if any(w in k for w in ("policy", "risk", "response", "approval"))
        ],
    }
    with open(STATE, "w") as fh:
        json.dump({"base_url": base, "alert_ids": ids}, fh)
    report(out, f"perf_results_run.json")
    print(f"\nRestart the agent now, then: python perf_numbers.py verify --base-url {base}")


def verify(base):
    with open(STATE) as fh:
        state = json.load(fh)
    found = 0
    missing = []
    for aid in state["alert_ids"]:
        status, body, _, err = call("GET", f"{base}/api/v1/investigations/{aid}")
        if status == 200:
            found += 1
        else:
            missing.append({"alert_id": aid, "status": status, "error": err})
    new_id = f"ALT-PERF-AFTER-{uuid.uuid4().hex[:6]}"
    status, body, elapsed, err = send_one(base, new_id)
    out = {
        "mode": "verify",
        "base_url": base,
        "alerts_before_restart": len(state["alert_ids"]),
        "still_retrievable": found,
        "missing": missing,
        "new_alert_status": status,
        "new_alert_error": err,
        "new_alert_seconds": round(elapsed, 2),
    }
    report(out, "perf_results_verify.json")


def report(out, path):
    print("\n=== RESULTS ===")
    for k, v in out.items():
        print(f"{k}: {v}")
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["run", "verify"])
    ap.add_argument("--base-url", default="http://localhost:8000")
    ap.add_argument("--n", type=int, default=10)
    a = ap.parse_args()
    base = a.base_url.rstrip("/")
    run(base, a.n) if a.mode == "run" else verify(base)
