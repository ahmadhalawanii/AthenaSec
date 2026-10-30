"""Shared test setup.

POST /api/v1/analyze needs a signed-in operator. Apps built in tests without an
operator identity store get one that accepts TEST_OPERATOR_TOKEN, and the
analyze helpers send it (ANALYZE_HEADERS). Tests that pass their own
operator_identity_store are unaffected.
"""

import pytest

from app.services.auth.operator_identity import OperatorIdentity

TEST_OPERATOR_TOKEN = "test-operator-token"
ANALYZE_HEADERS = {"Authorization": f"Bearer {TEST_OPERATOR_TOKEN}"}


class _TestOperatorIdentityStore:
    def resolve(self, token):
        if token == TEST_OPERATOR_TOKEN:
            return OperatorIdentity("analyst-test", True, False)
        return None


@pytest.fixture
def operator_identity_for_tests(monkeypatch):
    monkeypatch.setattr(
        "app.main.build_operator_identity_store_from_env",
        lambda: _TestOperatorIdentityStore(),
    )
