"""Contract test for the Devin API request shape.

The real risk here is not logic — it's a typo in a field name that breaks the first live
run. This test asserts the outgoing JSON body and URL match the Devin API v3 contract we
documented in the project memory (devin-api.md).
"""

from unittest.mock import MagicMock, patch

from app import devin_client


def _fake_response():
    r = MagicMock()
    r.json.return_value = {
        "session_id": "dev-sess-1",
        "url": "https://app.devin.ai/sessions/dev-sess-1",
    }
    r.raise_for_status = MagicMock()
    return r


def test_create_session_posts_correct_url_and_payload():
    with patch.object(devin_client.settings, "mock_devin", False):
        client = devin_client.DevinClient(
            api_key="cog_test",
            org_id="org_test",
            base_url="https://api.devin.ai/v3",
        )
        with patch.object(client._client, "post", return_value=_fake_response()) as mock_post:
            client.create_session(
                prompt="fix yaml",
                canonical_id="YAML-001-abcdef1234",
                canonical_name="YAML-001",
                cwe="CWE-502",
                severity="high",
                title="YAML-001: yaml fix",
            )

    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    url = args[0] if args else kwargs["url"]
    body = kwargs["json"]

    assert url == "https://api.devin.ai/v3/organizations/org_test/sessions"
    assert body["prompt"] == "fix yaml"
    assert body["repos"] == ["sevensyeds/superset"]
    assert body["tags"] == ["YAML-001", "CWE-502", "high"]
    assert body["advanced_mode"] == "improve"
    assert body["max_acu_limit"] == 10
    assert body["title"] == "YAML-001: yaml fix"
    assert "structured_output_schema" in body


def test_create_session_structured_schema_contains_required_fields():
    with patch.object(devin_client.settings, "mock_devin", False):
        client = devin_client.DevinClient(
            api_key="cog_test", org_id="org_test",
        )
        with patch.object(client._client, "post", return_value=_fake_response()) as mock_post:
            client.create_session(
                prompt="x",
                canonical_id="YAML-001-abc",
                canonical_name="YAML-001",
                cwe="CWE-502",
                severity="high",
                title="t",
            )

    schema = mock_post.call_args.kwargs["json"]["structured_output_schema"]
    assert isinstance(schema, dict)
    props = schema.get("properties", {})
    for field in (
        "vulnerability_fixed",
        "root_cause_summary",
        "files_changed",
        "tests_run",
        "test_results_summary",
        "backward_compatibility_risk",
        "needs_human_review",
        "confidence",
        "recommended_follow_up",
    ):
        assert field in props, f"structured_output_schema missing required field: {field}"


def test_prompt_threads_issue_number_as_closes_directive():
    from app.prompts import prompt_for

    for name in ("YAML-001", "MD5-001", "PICKLE-001"):
        rendered = prompt_for(name, issue_number=42)
        assert "Closes #42" in rendered, f"{name} prompt missing Closes #42 directive"


def test_get_session_uses_correct_url():
    with patch.object(devin_client.settings, "mock_devin", False):
        client = devin_client.DevinClient(
            api_key="cog_test",
            org_id="org_test",
            base_url="https://api.devin.ai/v3",
        )
        fake = _fake_response()
        fake.json.return_value = {"status": "running", "status_detail": "working"}
        with patch.object(client._client, "get", return_value=fake) as mock_get:
            client.get_session("dev-sess-1")

    mock_get.assert_called_once()
    args, _ = mock_get.call_args
    assert args[0] == "https://api.devin.ai/v3/organizations/org_test/sessions/dev-sess-1"
