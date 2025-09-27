from typing import Optional, Union

from pydantic import BaseModel, Field, ConfigDict


class KnockRequest(BaseModel):
    """Schema describing the optional body for the /knock endpoint."""

    model_config = ConfigDict(extra="forbid")

    ip_address: Optional[str] = Field(
        default=None,
        description="IP address or CIDR block to whitelist. If omitted, the caller's source IP is used.",
        examples=["203.0.113.54", "203.0.113.0/24"],
    )
    ttl: Optional[Union[int, str]] = Field(
        default=None,
        description="Requested time-to-live in seconds for the whitelist entry. Must be a positive integer.",
        examples=[300, 3600],
    )


class KnockResponse(BaseModel):
    """Successful response returned by the /knock endpoint."""

    whitelisted_entry: str = Field(description="The IP address or CIDR range that was whitelisted.")
    expires_at: int = Field(description="Unix epoch timestamp indicating when the whitelist entry expires.")
    expires_in_seconds: int = Field(
        description="Number of seconds from now until the whitelist entry expires."
    )


class ErrorResponse(BaseModel):
    """Standard error payload returned by API endpoints when a request fails."""

    error: str = Field(description="Human-readable explanation of the failure.")


class HealthResponse(BaseModel):
    """Response model for the /health endpoint."""

    status: str = Field(description="Overall service health status.")
