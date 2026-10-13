from datetime import datetime, timedelta, timezone
import base64
import json
import ssl
from urllib.request import Request, urlopen

from typing import (
    Any,
    Protocol,
)

import requests

from app.schemas import (
    EvidenceObservation,
    EvidenceRequest,
    SecurityAlertInput,
)


class WazuhSearchClient(Protocol):
    def search_alerts(
        self,
        query: dict[str, Any],
    ) -> list[dict[str, Any]]:
        ...


class WazuhIndexerClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_ssl: bool | str = True,
        timeout: float = 10.0,
        legacy_ca_compat: bool = False,
    ):
        self.base_url = (
            base_url.rstrip("/")
        )

        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._legacy_tls_context: ssl.SSLContext | None = None
        if legacy_ca_compat:
            if not isinstance(verify_ssl, str) or not verify_ssl.strip():
                raise ValueError('Legacy lab CA compatibility requires an explicit CA bundle')
            # LAB COMPATIBILITY ONLY. CA-chain and hostname checks remain enabled.
            # Remediate the nonconformant Wazuh CA before production.
            context = ssl.create_default_context(cafile=verify_ssl)
            context.verify_flags &= ~ssl.VERIFY_X509_STRICT
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError('TLS certificate and hostname validation are required')
            self._legacy_tls_context = context

    def _legacy_verified_request(self, path: str, query: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._legacy_tls_context is None:
            raise RuntimeError('Legacy transport is not enabled')
        credentials = base64.b64encode(
            f'{self.username}:{self.password}'.encode('utf-8')
        ).decode('ascii')
        req = Request(
            self.base_url + path,
            data=json.dumps(query).encode('utf-8') if query is not None else None,
            headers={
                'Authorization': 'Basic ' + credentials,
                'Content-Type': 'application/json',
            },
            method='POST' if query is not None else 'GET',
        )
        with urlopen(req, context=self._legacy_tls_context, timeout=self.timeout) as response:
            payload = json.load(response)
        if not isinstance(payload, dict):
            raise ValueError('Unexpected Wazuh Indexer response')
        return payload

    def search_alerts(
        self,
        query: dict[str, Any],
    ) -> list[dict[str, Any]]:
        if self._legacy_tls_context is not None:
            payload = self._legacy_verified_request('/wazuh-alerts*/_search', query)
            hits = payload.get('hits', {}).get('hits', [])
            return hits if isinstance(hits, list) else []
        response = requests.post(
            (
                f"{self.base_url}/"
                "wazuh-alerts*/_search"
            ),
            auth=(
                self.username,
                self.password,
            ),
            json=query,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )

        response.raise_for_status()

        payload = response.json()

        return (
            payload
            .get("hits", {})
            .get("hits", [])
        )

    def health(
        self,
    ) -> dict[str, Any]:
        if self._legacy_tls_context is not None:
            return self._legacy_verified_request('/_cluster/health')
        response = requests.get(
            (
                f"{self.base_url}/"
                "_cluster/health"
            ),
            auth=(
                self.username,
                self.password,
            ),
            verify=self.verify_ssl,
            timeout=self.timeout,
        )

        response.raise_for_status()

        return response.json()


def _get_alert_scope(
    alert: SecurityAlertInput,
) -> dict[str, Any]:
    metadata = alert.metadata

    return {
        "source_ip": (
            metadata.get("source_ip")
            or metadata.get("srcip")
        ),
        "target_user": (
            metadata.get("target_user")
            or metadata.get("username")
        ),
        "agent_id": metadata.get(
            "agent_id"
        ),
    }

def _timestamp_filter(
    alert: SecurityAlertInput,
) -> dict[str, Any] | None:
    raw = alert.metadata.get("timestamp")

    if not isinstance(raw, str) or not raw.strip():
        return None

    value = raw.strip()

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        observed_at = datetime.fromisoformat(value)
    except ValueError:
        return None

    if observed_at.tzinfo is None:
        return None

    observed_at = observed_at.astimezone(timezone.utc)

    window = timedelta(minutes=30)

    return {
        "range": {
            "timestamp": {
                "gte": (observed_at - window).isoformat(),
                "lte": (observed_at + window).isoformat(),
            }
        }
    }


def _base_query(
    must: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "size": 20,
        "sort": [
            {
                "timestamp": {
                    "order": "desc",
                    "unmapped_type": "date",
                }
            }
        ],
        "query": {
            "bool": {
                "must": must,
            }
        },
    }


def build_wazuh_query(
    alert: SecurityAlertInput,
    request: EvidenceRequest,
) -> dict[str, Any] | None:
    scope = _get_alert_scope(
        alert
    )

    source_ip = scope["source_ip"]
    target_user = scope["target_user"]
    agent_id = scope["agent_id"]

    time_filter = _timestamp_filter(alert)

    if time_filter is None:
        return None

    scope_filters: list[
        dict[str, Any]
    ] = [time_filter]

    if source_ip:
        scope_filters.append(
            {
                "term": {
                    "data.srcip": source_ip,
                }
            }
        )

    elif agent_id:
        scope_filters.append(
            {
                "term": {
                    "agent.id": agent_id,
                }
            }
        )

    elif target_user:
        scope_filters.append(
            {
                "term": {
                    "data.dstuser": target_user,
                }
            }
        )

    else:
        return None

    if request == "authentication_history":
        return _base_query(
            [
                {
                    "terms": {
                        "rule.groups": [
                            "authentication_failed",
                            "authentication_success",
                        ]
                    }
                },
                *scope_filters,
            ]
        )

    if request == "source_endpoint_context":
        # The triggering Wazuh alert's agent is typically the monitored
        # TARGET, not the attacker's SOURCE endpoint. Only telemetry from
        # an enrolled agent whose own IP matches the incident source can
        # qualify as source endpoint context.
        if not source_ip:
            return None

        return _base_query(
            [
                time_filter,
                {"term": {"agent.ip": source_ip}},
                {"exists": {"field": "agent.name"}},
                {"bool": {"must_not": [
                    {"term": {"agent.id": "000"}},
                    {"terms": {"rule.groups": [
                        "authentication_failed",
                        "authentication_failures",
                        "authentication_success",
                    ]}},
                ]}},
            ]
        )

    if request == "privilege_activity":
        # Privilege activity concerns the monitored agent, not the attacker's
        # network source. A time- and agent-matched generic event is NOT proof.
        actor = alert.metadata.get("source_user") or target_user
        if not agent_id or not isinstance(actor, str) or not actor.strip():
            return None
        actor = actor.strip()
        return _base_query([
            time_filter,
            {"term": {"agent.id": agent_id}},
            {"bool": {"should": [
                {"term": {"data.srcuser": actor}},
                {"term": {"data.dstuser": actor}},
                {"term": {"data.user": actor}},
            ], "minimum_should_match": 1}},
            {"bool": {"should": [
                {"terms": {"rule.groups": [
                    "sudo", "privilege_escalation", "account_changed",
                    "group_changed", "user_management",
                ]}},
                {"terms": {"decoder.name": [
                    "sudo", "gpasswd", "useradd", "usermod", "userdel",
                    "groupadd", "groupmod", "groupdel",
                ]}},
                {"terms": {"decoder.parent": [
                    "sudo", "gpasswd", "useradd", "usermod", "userdel",
                    "groupadd", "groupmod", "groupdel",
                ]}},
            ], "minimum_should_match": 1}},
        ])

    if request == "related_security_events":
        return _base_query(
            [
                *scope_filters,
                {
                    "range": {
                        "rule.level": {
                            "gte": 7,
                        }
                    }
                },
            ]
        )

    return None


def _nested(
    data: dict[str, Any],
    *path: str,
):
    current: Any = data

    for part in path:
        if not isinstance(
            current,
            dict,
        ):
            return None

        current = current.get(
            part
        )

    return current


def format_wazuh_hit(
    hit: dict[str, Any],
) -> str:
    source = hit.get(
        "_source",
        {},
    )

    fields = [
        (
            "wazuh_alert_id",
            hit.get("_id"),
        ),
        (
            "timestamp",
            source.get("timestamp"),
        ),
        (
            "rule_id",
            _nested(
                source,
                "rule",
                "id",
            ),
        ),
        (
            "rule_level",
            _nested(
                source,
                "rule",
                "level",
            ),
        ),
        (
            "rule_description",
            _nested(
                source,
                "rule",
                "description",
            ),
        ),
        (
            "rule_groups",
            _nested(
                source,
                "rule",
                "groups",
            ),
        ),
        (
            "agent_id",
            _nested(
                source,
                "agent",
                "id",
            ),
        ),
        (
            "agent_name",
            _nested(
                source,
                "agent",
                "name",
            ),
        ),
        (
            "agent_ip",
            _nested(
                source,
                "agent",
                "ip",
            ),
        ),
        (
            "source_ip",
            _nested(
                source,
                "data",
                "srcip",
            ),
        ),
        (
            "target_user",
            _nested(
                source,
                "data",
                "dstuser",
            ),
        ),
        (
            "full_log",
            source.get("full_log"),
        ),
    ]

    parts: list[str] = []

    for name, value in fields:
        if value is None:
            continue

        if isinstance(
            value,
            list,
        ):
            value = ",".join(
                str(item)
                for item in value
            )

        parts.append(
            f"{name}={value}"
        )

    return "; ".join(
        parts
    )


def _verified_source_endpoint_hit(
    alert: SecurityAlertInput,
    hit: dict[str, Any],
) -> bool:
    from ipaddress import ip_address

    source_ip = alert.metadata.get("source_ip") or alert.metadata.get("srcip")
    if not isinstance(source_ip, str):
        return False

    document = hit.get("_source")
    if not isinstance(document, dict):
        return False

    agent = document.get("agent")
    if not isinstance(agent, dict):
        return False

    agent_id = str(agent.get("id") or "").strip()
    if not agent_id or not agent_id.lstrip("0"):
        # 000 is the local Wazuh Manager, not an identified source endpoint.
        return False

    if not isinstance(agent.get("name"), str) or not agent["name"].strip():
        return False

    try:
        source_address = ip_address(source_ip.strip())
        agent_address = ip_address(str(agent.get("ip") or "").strip())
    except ValueError:
        return False

    if source_address != agent_address:
        return False

    rule = document.get("rule")
    if not isinstance(rule, dict):
        return False

    groups = rule.get("groups")
    if not isinstance(groups, list):
        return False

    authentication_groups = {
        "authentication_failed",
        "authentication_failures",
        "authentication_success",
    }
    if authentication_groups.intersection(str(group) for group in groups):
        # An authentication event is not independent endpoint telemetry.
        return False

    return True


def _verified_privilege_activity_hit(
    alert: SecurityAlertInput,
    hit: dict[str, Any],
) -> bool:
    document = hit.get("_source")
    if not isinstance(document, dict):
        return False
    agent = document.get("agent")
    expected_agent = alert.metadata.get("agent_id")
    if not isinstance(agent, dict) or not expected_agent:
        return False
    if str(agent.get("id") or "") != str(expected_agent):
        return False
    actor = alert.metadata.get("source_user") or alert.metadata.get("target_user")
    if not isinstance(actor, str) or not actor.strip():
        return False
    data = document.get("data")
    if not isinstance(data, dict):
        return False
    usernames = {str(data[key]).strip().casefold() for key in
                 ("srcuser", "dstuser", "user") if data.get(key)}
    if actor.strip().casefold() not in usernames:
        return False
    rule = document.get("rule")
    decoder = document.get("decoder")
    rule_groups = rule.get("groups", []) if isinstance(rule, dict) else []
    if not isinstance(rule_groups, list):
        rule_groups = []
    relevant_groups = {
        "sudo", "privilege_escalation", "account_changed",
        "group_changed", "user_management",
    }
    relevant_decoders = {
        "sudo", "gpasswd", "useradd", "usermod", "userdel",
        "groupadd", "groupmod", "groupdel",
    }
    names = set()
    if isinstance(decoder, dict):
        names = {str(decoder[key]).strip().casefold() for key in
                 ("name", "parent") if decoder.get(key)}
    groups = {str(group).strip().casefold() for group in rule_groups}
    return bool(groups & relevant_groups or names & relevant_decoders)


class WazuhEvidenceProvider:
    def __init__(
        self,
        client: WazuhSearchClient,
    ):
        self.client = client

    def gather(
        self,
        alert: SecurityAlertInput,
        requests: list[EvidenceRequest],
    ) -> list[EvidenceObservation]:
        observations: list[
            EvidenceObservation
        ] = []

        unique_requests = list(
            dict.fromkeys(
                requests
            )
        )

        for request in unique_requests:
            query = build_wazuh_query(
                alert,
                request,
            )

            if query is None:
                continue

            hits = self.client.search_alerts(
                query
            )

            for hit in hits:
                if (
                    request == "source_endpoint_context"
                    and not _verified_source_endpoint_hit(alert, hit)
                ):
                    continue

                if (
                    request == "privilege_activity"
                    and not _verified_privilege_activity_hit(alert, hit)
                ):
                    continue

                content = format_wazuh_hit(
                    hit
                )

                if not content:
                    continue

                observations.append(
                    EvidenceObservation(
                        source="wazuh",
                        evidence_type=request,
                        content=content,
                    )
                )

        return observations