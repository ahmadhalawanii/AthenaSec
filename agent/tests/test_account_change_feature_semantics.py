from app.ml.feature_extractor import (
    extract_ml_features,
)
from app.tools.wazuh_alert_parser import (
    parse_wazuh_alert,
)


def _payload(
    *,
    identifier,
    rule_id,
    rule_level,
    description,
    decoder_name,
    data,
    mitre_ids=None,
):
    return {
        "id": identifier,
        "rule": {
            "id": rule_id,
            "level": rule_level,
            "description": description,
            "groups": [
                "syslog",
                "adduser",
            ],
            "mitre": {
                "id": (
                    mitre_ids
                    or []
                ),
            },
        },
        "agent": {
            "id": "000",
            "name": "wazuh.manager",
        },
        "full_log": description,
        "data": data,
        "decoder": {
            "name": decoder_name,
            "parent": decoder_name,
        },
    }


def test_chfn_is_account_change_event():
    alert = parse_wazuh_alert(
        _payload(
            identifier="chfn-root",
            rule_id="5904",
            rule_level=8,
            description=(
                "Information from the user "
                "was changed."
            ),
            decoder_name="chfn",
            data={
                "dstuser": "root",
            },
            mitre_ids=[
                "T1098",
            ],
        )
    )

    features = extract_ml_features(
        alert
    )

    assert (
        alert.metadata[
            "target_user"
        ]
        == "root"
    )

    assert (
        features[
            "privileged_target"
        ]
        == 1.0
    )

    assert (
        features[
            "is_account_change_event"
        ]
        == 1.0
    )


def test_groupadd_maps_created_group_to_target_group():
    alert = parse_wazuh_alert(
        _payload(
            identifier="groupadd-wheel",
            rule_id="5901",
            rule_level=8,
            description=(
                "New group added "
                "to the system."
            ),
            decoder_name="groupadd",
            data={
                "dstuser": "wheel",
                "gid": "10",
            },
        )
    )

    features = extract_ml_features(
        alert
    )

    assert (
        alert.metadata[
            "target_group"
        ]
        == "wheel"
    )

    assert (
        features[
            "is_account_change_event"
        ]
        == 1.0
    )

    assert (
        features[
            "is_privilege_group_change"
        ]
        == 1.0
    )


def test_normal_groupadd_is_not_privilege_group_change():
    alert = parse_wazuh_alert(
        _payload(
            identifier="groupadd-developers",
            rule_id="5901",
            rule_level=8,
            description=(
                "New group added "
                "to the system."
            ),
            decoder_name="groupadd",
            data={
                "dstuser": "developers",
                "gid": "1500",
            },
        )
    )

    features = extract_ml_features(
        alert
    )

    assert (
        alert.metadata[
            "target_group"
        ]
        == "developers"
    )

    assert (
        features[
            "is_privilege_group_change"
        ]
        == 0.0
    )


def test_groupdel_maps_extra_data_to_target_group():
    alert = parse_wazuh_alert(
        _payload(
            identifier="groupdel-wheel",
            rule_id="51522",
            rule_level=2,
            description="Group deleted.",
            decoder_name="groupdel",
            data={
                "extra_data": "wheel",
            },
        )
    )

    features = extract_ml_features(
        alert
    )

    assert (
        alert.metadata[
            "target_group"
        ]
        == "wheel"
    )

    assert (
        features[
            "is_account_change_event"
        ]
        == 1.0
    )

    assert (
        features[
            "is_privilege_group_change"
        ]
        == 1.0
    )


def test_userdel_maps_deleted_user_to_target_user():
    alert = parse_wazuh_alert(
        _payload(
            identifier="userdel-root",
            rule_id="5903",
            rule_level=3,
            description=(
                "Group (or user) deleted "
                "from the system."
            ),
            decoder_name="open-userdel",
            data={
                "srcuser": "root",
            },
            mitre_ids=[
                "T1531",
            ],
        )
    )

    features = extract_ml_features(
        alert
    )

    assert (
        alert.metadata[
            "target_user"
        ]
        == "root"
    )

    assert (
        features[
            "privileged_target"
        ]
        == 1.0
    )

    assert (
        features[
            "is_account_change_event"
        ]
        == 1.0
    )


def test_normal_userdel_is_not_privileged_target():
    alert = parse_wazuh_alert(
        _payload(
            identifier="userdel-normal",
            rule_id="5903",
            rule_level=3,
            description=(
                "Group (or user) deleted "
                "from the system."
            ),
            decoder_name="open-userdel",
            data={
                "srcuser": "testuser",
            },
            mitre_ids=[
                "T1531",
            ],
        )
    )

    features = extract_ml_features(
        alert
    )

    assert (
        alert.metadata[
            "target_user"
        ]
        == "testuser"
    )

    assert (
        features[
            "privileged_target"
        ]
        == 0.0
    )

    assert (
        features[
            "is_account_change_event"
        ]
        == 1.0
    )
