"""
Pydantic models for request/response schemas in the Knocker API.
"""
from typing import Optional
from pydantic import BaseModel, Field, field_validator
import ipaddress


class KnockRequest(BaseModel):
    """Request schema for the knock endpoint."""
    ip_address: Optional[str] = Field(
        None,
        description="IP address or CIDR range to whitelist. If not provided, the client's IP is used.",
        json_schema_extra={"example": "192.168.1.100"}
    )
    ttl: Optional[int] = Field(
        None,
        description="Time-to-live in seconds for the whitelist entry. Must be positive integer.",
        json_schema_extra={"example": 3600},
        gt=0
    )

    @field_validator('ip_address')
    @classmethod
    def validate_ip_address(cls, v):
        if v is None:
            return v
        try:
            # Try to parse as IP address first
            ipaddress.ip_address(v)
            return v
        except ValueError:
            try:
                # Try to parse as CIDR network
                ipaddress.ip_network(v, strict=False)
                return v
            except ValueError:
                raise ValueError("Invalid IP address or CIDR notation")


class KnockResponse(BaseModel):
    """Response schema for successful knock requests."""
    whitelisted_entry: str = Field(
        description="The IP address or CIDR range that was added to the whitelist",
        json_schema_extra={"example": "192.168.1.100"}
    )
    expires_at: int = Field(
        description="Unix timestamp when the whitelist entry will expire",
        json_schema_extra={"example": 1640995200}
    )
    expires_in_seconds: int = Field(
        description="Number of seconds until the entry expires (actual TTL applied)",
        json_schema_extra={"example": 3600}
    )


class HealthResponse(BaseModel):
    """Response schema for health check endpoint."""
    status: str = Field(
        description="Service status indicator",
        json_schema_extra={"example": "ok"}
    )


class ErrorResponse(BaseModel):
    """Response schema for error responses."""
    error: str = Field(
        description="Error message describing what went wrong",
        json_schema_extra={"example": "Invalid or missing API key."}
    )