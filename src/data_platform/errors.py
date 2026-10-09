"""Structured, non-secret-bearing pipeline exceptions."""

from __future__ import annotations


class PipelineError(Exception):
    """An actionable pipeline failure with a stable machine-readable code."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "pipeline_error",
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable

    def as_dict(self) -> dict[str, object]:
        return {"code": self.code, "message": str(self), "retryable": self.retryable}
