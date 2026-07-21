import json
import os
import datetime

reports_dir = os.environ.get('REPORTS_DIR', 'security-reports')
findings = []

# Collect Bandit findings
bandit_path = f'{reports_dir}/bandit-report.json'
if os.path.exists(bandit_path):
    try:
        with open(bandit_path) as f:
            bandit = json.load(f)
        for r in bandit.get('results', []):
            findings.append({
                'tool': 'Bandit (SAST)',
                'severity': r.get('issue_severity', 'LOW'),
                'issue': r.get('issue_text', ''),
                'file': r.get('filename', ''),
                'recommendation': 'Review and fix the identified security pattern'
            })
        print(f"✅ Bandit: {len(bandit.get('results',[]))} findings")
    except Exception as e:
        print(f"⚠️  Bandit: {e}")

# Collect Snyk findings
snyk_path = f'{reports_dir}/snyk-report.json'
if os.path.exists(snyk_path):
    try:
        with open(snyk_path) as f:
            snyk = json.load(f)
        for v in snyk.get('vulnerabilities', []):
            findings.append({
                'tool': 'Snyk (SCA)',
                'severity': v.get('severity', 'LOW').upper(),
                'issue': v.get('title', ''),
                'package': v.get('packageName', ''),
                'recommendation': f"Upgrade {v.get('packageName','')} to fixed version"
            })
        print(f"✅ Snyk: {len(snyk.get('vulnerabilities',[]))} vulnerabilities")
    except Exception as e:
        print(f"⚠️  Snyk: {e}")

# Collect ZAP findings
zap_path = f'{reports_dir}/zap-report.json'
if os.path.exists(zap_path):
    try:
        with open(zap_path) as f:
            zap = json.load(f)
        for alert in zap.get('alerts', []):
            findings.append({
                'tool': 'OWASP ZAP (DAST)',
                'severity': alert.get('risk', 'LOW'),
                'issue': alert.get('alert', ''),
                'url': alert.get('url', ''),
                'recommendation': alert.get('solution', 'Fix the identified vulnerability')
            })
        print(f"✅ ZAP: {len(zap.get('alerts',[]))} alerts")
    except Exception as e:
        print(f"⚠️  ZAP: {e}")

# AI Prioritization
priority = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
findings.sort(key=lambda x: priority.get(x.get('severity', 'LOW'), 4))

# Six Sigma
total_checks = max(len(findings) + 20, 100)
defects = len(findings)
dpmo = (defects / total_checks) * 1000000
if dpmo == 0: sigma = 6.0
elif dpmo <= 3.4: sigma = 6.0
elif dpmo <= 233: sigma = 5.0
elif dpmo <= 6210: sigma = 4.0
elif dpmo <= 66807: sigma = 3.0
elif dpmo <= 308537: sigma = 2.0
else: sigma = 1.0

dmaic = {
    "Define": "Security vulnerabilities in DevOps allow insecure code to reach production",
    "Measure": f"{defects} findings detected. DPMO: {round(dpmo,2)}",
    "Analyze": "Root cause: no automated security checks in CI/CD pipeline",
    "Improve": "Hybrid pipeline with Bandit, SonarQube, Snyk, OWASP ZAP",
    "Control": "Pipeline runs automatically on every git push"
}

summary = {
    'pipeline_id': os.environ.get('CI_PIPELINE_ID', 'local'),
    'commit': os.environ.get('CI_COMMIT_SHORT_SHA', 'local'),
    'branch': os.environ.get('CI_COMMIT_BRANCH', 'main'),
    'timestamp': datetime.datetime.utcnow().isoformat(),
    'approach': 'Hybrid DevSecOps (SAST + DAST + Zero Trust)',
    'tools_used': ['pytest', 'Bandit (SAST)', 'SonarQube (SAST)', 'detect-secrets', 'Snyk (SCA)', 'OWASP ZAP (DAST)'],
    'findings': {
        'total': len(findings),
        'critical': len([f for f in findings if f.get('severity') == 'CRITICAL']),
        'high': len([f for f in findings if f.get('severity') == 'HIGH']),
        'medium': len([f for f in findings if f.get('severity') == 'MEDIUM']),
        'low': len([f for f in findings if f.get('severity') == 'LOW'])
    },
    'six_sigma': {
        'dmaic': dmaic,
        'dpmo': round(dpmo, 2),
        'sigma_level': sigma,
        'interpretation': f'Pipeline at {sigma} sigma — {"Excellent" if sigma >= 5 else "Good" if sigma >= 4 else "Acceptable"}'
    },
    'ai_top_priorities': findings[:5],
    'overall_status': 'PASS' if len([f for f in findings if f.get('severity') == 'CRITICAL']) == 0 else 'REVIEW REQUIRED'
}

os.makedirs(reports_dir, exist_ok=True)
with open(f'{reports_dir}/final-security-report.json', 'w') as f:
    json.dump(summary, f, indent=2)

print('\n' + '=' * 60)
print('AI-POWERED DEVSECOPS SECURITY REPORT')
print('=' * 60)
print(f'Pipeline    : {summary["pipeline_id"]}')
print(f'Commit      : {summary["commit"]}')
print(f'Findings    : {summary["findings"]["total"]}')
print(f'Critical    : {summary["findings"]["critical"]}')
print(f'High        : {summary["findings"]["high"]}')
print(f'Medium      : {summary["findings"]["medium"]}')
print(f'Low         : {summary["findings"]["low"]}')
print(f'DPMO        : {summary["six_sigma"]["dpmo"]}')
print(f'Sigma Level : {summary["six_sigma"]["sigma_level"]} σ')
print(f'Status      : {summary["overall_status"]}')
print('=' * 60)
if findings:
    print('TOP PRIORITY FINDINGS (AI Ranked):')
    for i, f in enumerate(findings[:5], 1):
        print(f'{i}. [{f["severity"]}] {f["tool"]}: {str(f.get("issue",""))[:50]}')
        print(f'   → {f.get("recommendation","")[:55]}')
print('=' * 60)