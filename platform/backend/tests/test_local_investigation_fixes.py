from types import SimpleNamespace
from app.graph.nodes.gather_evidence import _resolve_evidence_requests
from app.llm import SYSTEM_PROMPT
from app.schemas import AlertAnalysis
from app.services.investigations.analysis_verifier import _claims_successful_authentication


def state(text, existing=()):
    return {
        'alert': SimpleNamespace(source='wazuh', event_text=text, metadata={}),
        'analysis': SimpleNamespace(classification='unknown', requested_evidence=[]),
        'evidence_sufficiency': SimpleNamespace(
            sufficient=False, missing_evidence=['related_security_events']
        ),
        'evidence_records': [SimpleNamespace(evidence_type=x) for x in existing],
    }


def test_unknown_privilege_event_fetches_privilege_activity():
    assert _resolve_evidence_requests(state('user added to sudo group')) == [
        'privilege_activity', 'related_security_events'
    ]


def test_existing_privilege_evidence_is_not_refetched():
    assert _resolve_evidence_requests(state('user added to sudo group', ('privilege_activity',))) == [
        'related_security_events'
    ]


def test_unknown_ssh_login_does_not_fetch_privilege_activity():
    assert _resolve_evidence_requests(state('one failed SSH login')) == ['related_security_events']


def analysis(summary):
    return AlertAnalysis(
        classification='unknown', confidence=0.5, severity_assessment='low',
        summary=summary, evidence_refs=['E001'], uncertainties=[],
        recommended_investigation_steps=[], recommended_response_actions=[],
        requested_evidence=[], needs_more_evidence=False,
    )


def test_negative_login_claim_is_not_success_claim():
    assert not _claims_successful_authentication(analysis('No successful authentication was observed.'))


def test_positive_login_claim_is_success_claim():
    assert _claims_successful_authentication(analysis('A successful authentication occurred.'))


def test_prompt_disambiguation_guidance_is_present():
    assert 'CLASSIFICATION GUIDANCE FOR AMBIGUOUS SECURITY ALERTS:' in SYSTEM_PROMPT
    assert 'unauthorized' in SYSTEM_PROMPT
    assert 'use unknown' in SYSTEM_PROMPT
