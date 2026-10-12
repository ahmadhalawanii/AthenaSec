from datetime import datetime, timedelta, timezone

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
        verify_ssl: bool = True,
        timeout: float = 10.0,
    ):
        self.base_url = (
            base_url.rstrip("/")
        )

        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def search_alerts(
        self,
        query: dict[str, Any],
    ) -> list[dict[str, Any]]:
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
        must = [
            *scope_filters,
        ]

        if agent_id:
            must.append(
                {
                    "term": {
                        "agent.id": agent_id,
                    }
                }
            )

        return _base_query(
            must
        )

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