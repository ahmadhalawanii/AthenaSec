from dataclasses import dataclass


@dataclass(frozen=True)
class WazuhLabScenario:
    name: str
    log_line: str
    expected_rule_id: str
    source_ip: str
    label: str
    source_dataset: str
    source_row_id: str
    repetitions: int


def brute_force_scenarios() -> list[WazuhLabScenario]:
    return [
        WazuhLabScenario(
            name="ssh_invalid_user_bruteforce",
            log_line=(
                "Sep  3 01:00:00 testhost "
                "sshd[12345]: Failed password "
                "for invalid user fakeuser "
                "from 203.0.113.50 "
                "port 54321 ssh2"
            ),
            expected_rule_id="5712",
            source_ip="203.0.113.50",
            label="brute_force",
            source_dataset="wazuh_lab",
            source_row_id="ssh_invalid_user_bruteforce_001",
            repetitions=10,
        ),
        WazuhLabScenario(
            name="ssh_root_password_bruteforce",
            log_line=(
                "Sep  3 01:15:00 testhost "
                "sshd[22345]: Failed password "
                "for root "
                "from 198.51.100.25 "
                "port 55221 ssh2"
            ),
            expected_rule_id="5763",
            source_ip="198.51.100.25",
            label="brute_force",
            source_dataset="wazuh_lab",
            source_row_id="ssh_root_password_bruteforce_002",
            repetitions=10,
        ),
        WazuhLabScenario(
            name="ssh_root_none_bruteforce",
            log_line=(
                "Sep  3 01:30:00 testhost "
                "sshd[32345]: Failed none "
                "for root "
                "from 192.0.2.80 "
                "port 56221 ssh2"
            ),
            expected_rule_id="5720",
            source_ip="192.0.2.80",
            label="brute_force",
            source_dataset="wazuh_lab",
            source_row_id="ssh_root_none_bruteforce_003",
            repetitions=10,
        ),
    ]


def privilege_misuse_scenarios() -> list[WazuhLabScenario]:
    return [
        WazuhLabScenario(
            name="sudo_three_failed_attempts",
            log_line=(
                "Sep  3 02:30:00 testhost "
                "sudo: testuser : "
                "3 incorrect password attempts ; "
                "TTY=pts/4 ; "
                "PWD=/home/testuser ; "
                "USER=root ; "
                "COMMAND=/bin/bash"
            ),
            expected_rule_id="5404",
            source_ip="",
            label="privilege_misuse",
            source_dataset="wazuh_lab",
            source_row_id="sudo_three_failed_attempts_001",
            repetitions=1,
        ),
        WazuhLabScenario(
            name="sudo_unauthorized_user",
            log_line=(
                "Sep  3 01:41:00 testhost "
                "sudo: guest : "
                "user NOT in sudoers ; "
                "TTY=pts/2 ; "
                "PWD=/home/guest ; "
                "USER=root ; "
                "COMMAND=/bin/bash"
            ),
            expected_rule_id="5405",
            source_ip="",
            label="privilege_misuse",
            source_dataset="wazuh_lab",
            source_row_id="sudo_unauthorized_user_002",
            repetitions=1,
        ),
        WazuhLabScenario(
            name="sudo_command_not_allowed",
            log_line=(
                "Sep  3 02:31:00 testhost "
                "sudo: testuser : "
                "command not allowed ; "
                "TTY=pts/4 ; "
                "PWD=/home/testuser ; "
                "USER=root ; "
                "COMMAND=/bin/bash"
            ),
            expected_rule_id="5406",
            source_ip="",
            label="privilege_misuse",
            source_dataset="wazuh_lab",
            source_row_id="sudo_command_not_allowed_003",
            repetitions=1,
        ),
        WazuhLabScenario(
            name="user_added_to_sudo_group",
            log_line=(
                "Sep  3 01:43:00 testhost "
                "gpasswd[3246]: "
                "user backdooruser added by root "
                "to group sudo"
            ),
            expected_rule_id="2961",
            source_ip="",
            label="privilege_misuse",
            source_dataset="wazuh_lab",
            source_row_id="user_added_to_sudo_group_004",
            repetitions=1,
        ),
    ]


def benign_scenarios() -> list[WazuhLabScenario]:
    return [
        WazuhLabScenario(
            name="ssh_authentication_success",
            log_line=(
                "Sep  3 02:20:00 testhost "
                "sshd[42345]: Accepted password "
                "for normaluser "
                "from 203.0.113.90 "
                "port 57221 ssh2"
            ),
            expected_rule_id="5715",
            source_ip="203.0.113.90",
            label="benign",
            source_dataset="wazuh_lab",
            source_row_id="ssh_authentication_success_001",
            repetitions=1,
        ),
        WazuhLabScenario(
            name="sudo_non_privileged_success",
            log_line=(
                "Sep  3 02:21:00 testhost "
                "sudo: normaladmin : "
                "TTY=pts/3 ; "
                "PWD=/home/normaladmin ; "
                "USER=backupuser ; "
                "COMMAND=/usr/bin/id"
            ),
            expected_rule_id="5407",
            source_ip="",
            label="benign",
            source_dataset="wazuh_lab",
            source_row_id="sudo_non_privileged_success_002",
            repetitions=2,
        ),
        WazuhLabScenario(
            name="pam_login_session_opened",
            log_line=(
                "Sep  3 02:23:00 testhost "
                "su[2238]: "
                "pam_unix(su:session): "
                "session opened for user backupuser "
                "by normaladmin(uid=1000)"
            ),
            expected_rule_id="5501",
            source_ip="",
            label="benign",
            source_dataset="wazuh_lab",
            source_row_id="pam_login_session_opened_003",
            repetitions=1,
        ),
    ]


def all_scenarios() -> list[WazuhLabScenario]:
    return (
        brute_force_scenarios()
        + privilege_misuse_scenarios()
        + benign_scenarios()
    )


def get_scenario_by_name(
    name: str,
) -> WazuhLabScenario:
    for scenario in all_scenarios():
        if scenario.name == name:
            return scenario

    raise ValueError(
        f"Unknown Wazuh lab scenario: {name}"
    )


def docker_injection_command(
    scenario: WazuhLabScenario,
    container_name: str,
    log_path: str,
) -> str:
    return (
        f"1..{scenario.repetitions} | "
        "ForEach-Object { "
        f"docker exec {container_name} "
        f"sh -c \"echo '{scenario.log_line}' "
        f">> {log_path}\"; "
        "Start-Sleep -Milliseconds 300 "
        "}"
    )


def prepare_scenario_run(
    name: str,
    container_name: str,
    log_path: str,
) -> dict[str, str]:
    scenario = get_scenario_by_name(name)

    return {
        "scenario_name": scenario.name,
        "expected_rule_id": scenario.expected_rule_id,
        "source_ip": scenario.source_ip,
        "label": scenario.label,
        "source_dataset": scenario.source_dataset,
        "source_row_id": scenario.source_row_id,
        "injection_command": docker_injection_command(
            scenario=scenario,
            container_name=container_name,
            log_path=log_path,
        ),
    }