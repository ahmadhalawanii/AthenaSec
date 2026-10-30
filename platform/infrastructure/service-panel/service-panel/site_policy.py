"""Fixed service destinations. No editable URL or external application launch."""
from urllib.parse import urlsplit

SITES = {
    "wazuh": ("Wazuh", "https://192.168.1.164"),
    "cortex": ("Cortex", "https://192.168.1.164:9444"),
    "misp": ("MISP", "https://192.168.1.164:9445"),
}


def allowed_uri(key, uri):
    if key not in SITES or not isinstance(uri, str):
        return False
    # Reject parser-normalized whitespace and backslashes before parsing.
    if any(ord(char) < 33 or ord(char) == 127 for char in uri) or "\\" in uri:
        return False
    try:
        expected = urlsplit(SITES[key][1])
        actual = urlsplit(uri)
        return (
            actual.scheme == "https"
            and actual.username is None and actual.password is None
            and actual.hostname == expected.hostname
            and (443 if actual.port is None else actual.port) == (443 if expected.port is None else expected.port)
        )
    except ValueError:
        return False
