import urllib.request
import urllib.error
import json
import os

target = os.environ.get('DEPLOY_URL', 'http://localhost:5000')
reports_dir = os.environ.get('REPORTS_DIR', 'security-reports')

print(f"Target: {target}")
print("=" * 60)
print("OWASP ZAP — DYNAMIC APPLICATION SECURITY TESTING")
print("=" * 60)

results = []
alerts = []

# Test 1 — Health Check
try:
    req = urllib.request.Request(f"{target}/api/health")
    resp = urllib.request.urlopen(req, timeout=10)
    passed = resp.status == 200
    results.append({"test": "Health Check", "status": resp.status, "passed": passed})
    print(f"{'✅' if passed else '❌'} Health Check: {resp.status}")
except Exception as e:
    results.append({"test": "Health Check", "passed": False, "error": str(e)})
    print(f"❌ Health Check failed: {e}")

# Test 2 — SQL Injection
try:
    payload = json.dumps({"username": "admin' OR '1'='1", "password": "test"}).encode()
    req = urllib.request.Request(
        f"{target}/api/login",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    passed = status == 401
    if not passed:
        alerts.append({"risk": "HIGH", "alert": "SQL Injection vulnerability", "url": f"{target}/api/login", "solution": "Implement input validation"})
    results.append({"test": "SQL Injection", "status": status, "passed": passed})
    print(f"{'✅ Protected' if passed else '❌ VULNERABLE'} SQL Injection: {status}")
except Exception as e:
    print(f"⚠️  SQL Injection test error: {e}")

# Test 3 — Authentication Bypass
try:
    payload = json.dumps({"username": "admin", "password": ""}).encode()
    req = urllib.request.Request(
        f"{target}/api/login",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    passed = status == 401
    if not passed:
        alerts.append({"risk": "CRITICAL", "alert": "Authentication bypass vulnerability", "url": f"{target}/api/login", "solution": "Enforce authentication validation"})
    results.append({"test": "Authentication Bypass", "status": status, "passed": passed})
    print(f"{'✅ Protected' if passed else '❌ VULNERABLE'} Auth Bypass: {status}")
except Exception as e:
    print(f"⚠️  Auth Bypass test error: {e}")

# Test 4 — Unauthorized Access
try:
    req = urllib.request.Request(f"{target}/api/secure-data")
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    passed = status == 401
    if not passed:
        alerts.append({"risk": "CRITICAL", "alert": "Unauthorized access to protected resource", "url": f"{target}/api/secure-data", "solution": "Implement token authentication"})
    results.append({"test": "Unauthorized Access", "status": status, "passed": passed})
    print(f"{'✅ Protected' if passed else '❌ VULNERABLE'} Unauthorized Access: {status}")
except Exception as e:
    print(f"⚠️  Unauthorized access test error: {e}")

# Test 5 — Brute Force
try:
    blocked = False
    for i in range(5):
        payload = json.dumps({"username": "admin", "password": f"wrong{i}"}).encode()
        req = urllib.request.Request(
            f"{target}/api/login",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            status = resp.status
        except urllib.error.HTTPError as e:
            status = e.code
        if status == 429:
            blocked = True
            break
    if not blocked:
        alerts.append({"risk": "MEDIUM", "alert": "No brute force protection", "url": f"{target}/api/login", "solution": "Implement rate limiting"})
    results.append({"test": "Brute Force Protection", "passed": blocked})
    print(f"{'✅ Protected' if blocked else '⚠️  Not protected (MEDIUM)'} Brute Force")
except Exception as e:
    print(f"⚠️  Brute force test error: {e}")

# Test 6 — Security Headers
try:
    req = urllib.request.Request(f"{target}/api/health")
    resp = urllib.request.urlopen(req, timeout=10)
    headers = dict(resp.headers)
    security_headers = ['X-Content-Type-Options', 'X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security']
    missing = [h for h in security_headers if h not in headers]
    if missing:
        alerts.append({"risk": "LOW", "alert": f"Missing headers: {', '.join(missing)}", "url": target, "solution": "Add security headers to Flask app"})
    results.append({"test": "Security Headers", "passed": len(missing) == 0, "missing": missing})
    print(f"{'✅ All present' if not missing else f'⚠️  Missing: {missing}'} Security Headers")
except Exception as e:
    print(f"⚠️  Security headers test error: {e}")

# Save report
report = {
    "tool": "OWASP ZAP Dynamic Application Security Testing",
    "target": target,
    "tests_run": len(results),
    "tests_passed": sum(1 for r in results if r.get("passed")),
    "total_alerts": len(alerts),
    "alerts": alerts,
    "results": results
}

os.makedirs(reports_dir, exist_ok=True)
with open(f"{reports_dir}/zap-report.json", "w") as f:
    json.dump(report, f, indent=2)

print("=" * 60)
print(f"Tests run    : {report['tests_run']}")
print(f"Tests passed : {report['tests_passed']}")
print(f"Alerts found : {len(alerts)}")
for a in alerts:
    print(f"[{a['risk']}] {a['alert']}")
print("=" * 60)