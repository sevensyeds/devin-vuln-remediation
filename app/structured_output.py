from typing import Literal

from pydantic import BaseModel, Field


class DevinRemediationOutput(BaseModel):
    """Schema Devin is forced to return. Values drive canonical status + comment wording."""

    vulnerability_fixed: bool = Field(
        ...,
        description="True if the specific vulnerability named in the prompt was remediated.",
    )
    root_cause_summary: str = Field(
        ...,
        description="One-paragraph summary of the root cause and the fix applied.",
    )
    files_changed: list[str] = Field(
        ...,
        description="Relative paths of files modified in this PR.",
    )
    tests_run: bool = Field(
        ...,
        description="True if you ran the existing test suite (or a targeted subset) after the change.",
    )
    test_results_summary: str = Field(
        ...,
        description="Pass/fail summary of tests run. If tests were not run, explain why.",
    )
    backward_compatibility_risk: Literal["none", "low", "medium", "high"] = Field(
        ...,
        description="Honest assessment of backward-compat risk for existing deployments.",
    )
    needs_human_review: bool = Field(
        ...,
        description="True if you could not fully verify the fix is safe and want a human to look before merge.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Your confidence the fix is correct and complete.",
    )
    recommended_follow_up: str = Field(
        default="",
        description="Optional: related cleanups or follow-ups you did NOT do in this PR.",
    )


def remediation_schema() -> dict:
    """JSON Schema payload for Devin's `structured_output_schema` field."""
    return DevinRemediationOutput.model_json_schema()
