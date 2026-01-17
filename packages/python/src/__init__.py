"""
L{CORE} Python SDK

Privacy-preserving IoT attestation layer built on Cartesi Rollups.

Example usage:
    from lcore import LCore, DeviceIdentity

    # Initialize client
    lcore = LCore(
        attestor_url="http://localhost:8001",
        cartesi_url="http://localhost:10000",
        dapp_address="0xAE0863401D5B953b89cad8a5E7c98f5136E9C26d"
    )

    # Generate device identity
    device = DeviceIdentity.generate()
    print(f"Device DID: {device.did}")

    # Submit sensor data
    result = await lcore.submit_device_data(
        device=device,
        payload={"temperature": 23.4, "humidity": 65}
    )
"""

from .client import LCore
from .device import DeviceIdentity
from .did import (
    parse_did_key,
    public_key_to_did_key,
    create_jws,
    verify_jws,
)
from .models import (
    DeviceSubmission,
    SubmissionResult,
    CartesiInspectResult,
    LCoreConfig,
)

__version__ = "0.1.0"
__all__ = [
    "LCore",
    "DeviceIdentity",
    "parse_did_key",
    "public_key_to_did_key",
    "create_jws",
    "verify_jws",
    "DeviceSubmission",
    "SubmissionResult",
    "CartesiInspectResult",
    "LCoreConfig",
]
