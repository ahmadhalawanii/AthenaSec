#!/usr/bin/python3
"""Print bounded, credential-free MISP probe results from this release."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "service-panel"))
from services import SERVICES, _request, _http_result, _misp_login_result, Result

misp = next(service for service in SERVICES if service.key == "misp")
for path, limit in ((misp.path, 16384), ("/users/login", 131072)):
    response = _request(misp, path, limit)
    if isinstance(response, Result):
        result = response
    elif path == misp.path:
        result = _http_result(misp, *response)
    else:
        result = _misp_login_result(response)
    print(f"{path}: {result.state} — {result.detail}")
