"""TLS checking for the backend's outgoing HTTPS calls (MISP, Cortex).

On the AthenaSec server, MISP and Cortex sit on the same machine behind self-signed
certificates, so by default every HTTPS call to them would be refused. Per service
(prefix MISP or CORTEX):

- <PREFIX>_CA_BUNDLE=/path/to/cert.pem   trust that certificate or CA (preferred)
- <PREFIX>_VERIFY_SSL=false              skip checking; only for services on localhost
- neither                                normal checking against the system CAs
"""

import os
import ssl

_FALSE = {"false", "0", "no", "off"}


def tls_verify(prefix: str) -> ssl.SSLContext | bool:
    bundle = (os.getenv(f"{prefix}_CA_BUNDLE") or "").strip()

    if bundle:
        return ssl.create_default_context(cafile=bundle)

    flag = (os.getenv(f"{prefix}_VERIFY_SSL") or "true").strip().lower()

    return flag not in _FALSE
