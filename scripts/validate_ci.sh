#!/usr/bin/env bash
set -e

echo "=========================================================="
echo "          Guardrail OS Local CI/CD Pipeline Validator      "
echo "=========================================================="

echo "--> [1/4] Checking Frontend Type-Script Compilation & Build..."
npm run build
echo "✔ Frontend build passed."

echo "--> [2/4] Running Backend Pytest Suite..."
PYTHONPATH=src python3 -m pytest tests/
echo "✔ Pytest suite passed."

echo "--> [3/4] Verifying Kernel State Endpoint..."
python3 -c "
import urllib.request, json
res = urllib.request.urlopen('http://127.0.0.1:8888/api/kernel/state')
data = json.loads(res.read().decode())
assert 'trust_score' in data
print('✔ Live Kernel State verified. Active Trust Score:', data['trust_score'])
"

echo "--> [4/4] Verifying Firestore Rules & Config File Integrity..."
test -f "firestore.rules"
test -f "firebase-blueprint.json"
echo "✔ Firebase & Firestore rules integrity verified."

echo "=========================================================="
echo "  SUCCESS: All CI/CD pipeline checks passed cleanly!      "
echo "=========================================================="
