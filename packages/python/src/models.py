"""
Type definitions for L{CORE} Python SDK
"""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class LCoreConfig:
    """Configuration for LCore client."""
    attestor_url: str
    cartesi_url: Optional[str] = None
    dapp_address: Optional[str] = None
    timeout: float = 30.0


@dataclass
class DeviceSubmission:
    """Device data submission request."""
    did: str
    payload: dict[str, Any]
    signature: str
    timestamp: int


@dataclass
class SubmissionResult:
    """Result of a device data submission."""
    success: bool
    tx_hash: Optional[str] = None
    block_number: Optional[int] = None
    error: Optional[str] = None


@dataclass
class CartesiInspectResult:
    """Result of a Cartesi inspect query."""
    status: str
    data: Optional[dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class AttestationRecord:
    """An attestation record from L{CORE}."""
    device_did: str
    data: dict[str, Any]
    timestamp: int
    tx_hash: str
    block_number: int
