"""
L{CORE} Client for Python

Main client class for interacting with L{CORE} attestor and Cartesi node.
"""

import json
from typing import Any, Optional

import httpx

from .models import LCoreConfig, SubmissionResult, CartesiInspectResult
from .device import DeviceIdentity


class LCore:
    """
    Client for interacting with L{CORE} attestor and Cartesi node.

    Example:
        >>> lcore = LCore(
        ...     attestor_url="http://localhost:8001",
        ...     cartesi_url="http://localhost:10000",
        ...     dapp_address="0xAE0863401D5B953b89cad8a5E7c98f5136E9C26d"
        ... )
        >>>
        >>> # Submit device data
        >>> device = DeviceIdentity.generate()
        >>> result = await lcore.submit_device_data(device, {"temperature": 23.4})
        >>> print(result.tx_hash)
    """

    def __init__(
        self,
        attestor_url: str,
        cartesi_url: Optional[str] = None,
        dapp_address: Optional[str] = None,
        timeout: float = 30.0,
    ):
        """
        Initialize L{CORE} client.

        Args:
            attestor_url: URL of the attestor server (e.g., "http://localhost:8001")
            cartesi_url: URL of Cartesi node for inspect queries (optional)
            dapp_address: Cartesi DApp contract address (optional)
            timeout: HTTP request timeout in seconds
        """
        self.config = LCoreConfig(
            attestor_url=attestor_url.rstrip("/"),
            cartesi_url=cartesi_url.rstrip("/") if cartesi_url else None,
            dapp_address=dapp_address,
            timeout=timeout,
        )
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self.config.timeout)
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "LCore":
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()

    async def submit_device_data(
        self,
        device: DeviceIdentity,
        payload: dict[str, Any],
    ) -> SubmissionResult:
        """
        Submit signed device data to L{CORE}.

        The device signs the payload with its private key, and the attestor
        verifies the signature before submitting to Cartesi.

        Args:
            device: DeviceIdentity with signing capabilities
            payload: Sensor data to submit

        Returns:
            SubmissionResult with tx_hash and block_number on success

        Example:
            >>> device = DeviceIdentity.generate()
            >>> result = await lcore.submit_device_data(
            ...     device=device,
            ...     payload={"temperature": 23.4, "humidity": 65}
            ... )
            >>> if result.success:
            ...     print(f"Submitted: {result.tx_hash}")
        """
        # Sign the payload
        submission = device.sign(payload)

        # Submit to attestor
        url = f"{self.config.attestor_url}/api/device/submit"

        try:
            response = await self.client.post(url, json=submission)
            data = response.json()

            if response.status_code == 201:
                return SubmissionResult(
                    success=True,
                    tx_hash=data.get("data", {}).get("txHash"),
                    block_number=data.get("data", {}).get("blockNumber"),
                )
            else:
                return SubmissionResult(
                    success=False,
                    error=data.get("error", f"HTTP {response.status_code}"),
                )

        except httpx.RequestError as e:
            return SubmissionResult(
                success=False,
                error=f"Request failed: {str(e)}",
            )

    async def submit_raw(
        self,
        did: str,
        payload: dict[str, Any],
        signature: str,
        timestamp: int,
    ) -> SubmissionResult:
        """
        Submit pre-signed device data to L{CORE}.

        Use this when you have a signature from an external source
        (e.g., hardware security module, embedded device).

        Args:
            did: Device DID (did:key:z...)
            payload: Sensor data
            signature: JWS compact serialization
            timestamp: Unix timestamp

        Returns:
            SubmissionResult with tx_hash and block_number on success
        """
        url = f"{self.config.attestor_url}/api/device/submit"

        submission = {
            "did": did,
            "payload": payload,
            "signature": signature,
            "timestamp": timestamp,
        }

        try:
            response = await self.client.post(url, json=submission)
            data = response.json()

            if response.status_code == 201:
                return SubmissionResult(
                    success=True,
                    tx_hash=data.get("data", {}).get("txHash"),
                    block_number=data.get("data", {}).get("blockNumber"),
                )
            else:
                return SubmissionResult(
                    success=False,
                    error=data.get("error", f"HTTP {response.status_code}"),
                )

        except httpx.RequestError as e:
            return SubmissionResult(
                success=False,
                error=f"Request failed: {str(e)}",
            )

    async def inspect(self, path: str) -> CartesiInspectResult:
        """
        Query data from Cartesi via inspect endpoint.

        Args:
            path: Inspect path (e.g., "attestations/did:key:z...")

        Returns:
            CartesiInspectResult with decoded data

        Example:
            >>> result = await lcore.inspect("attestations/latest")
            >>> if result.status == "ok":
            ...     print(result.data)
        """
        if not self.config.cartesi_url:
            return CartesiInspectResult(
                status="error",
                error="Cartesi URL not configured",
            )

        url = f"{self.config.cartesi_url}/inspect/{path}"

        try:
            response = await self.client.get(url)
            data = response.json()

            if response.status_code == 200:
                # Decode reports from hex
                reports = data.get("reports", [])
                decoded_data = None

                if reports:
                    payload_hex = reports[0].get("payload", "")
                    if payload_hex.startswith("0x"):
                        payload_hex = payload_hex[2:]
                    try:
                        decoded_data = json.loads(bytes.fromhex(payload_hex).decode())
                    except Exception:
                        decoded_data = {"raw": payload_hex}

                return CartesiInspectResult(
                    status="ok",
                    data=decoded_data,
                )
            else:
                return CartesiInspectResult(
                    status="error",
                    error=data.get("error", f"HTTP {response.status_code}"),
                )

        except httpx.RequestError as e:
            return CartesiInspectResult(
                status="error",
                error=f"Request failed: {str(e)}",
            )

    async def health_check(self) -> bool:
        """
        Check if the attestor server is healthy.

        Returns:
            True if server is responding, False otherwise
        """
        try:
            response = await self.client.get(f"{self.config.attestor_url}/healthcheck")
            return response.status_code == 200
        except Exception:
            return False


# Synchronous wrapper for non-async usage
class LCoreSync:
    """
    Synchronous wrapper for LCore client.

    Use this when you can't use async/await.

    Example:
        >>> lcore = LCoreSync(attestor_url="http://localhost:8001")
        >>> device = DeviceIdentity.generate()
        >>> result = lcore.submit_device_data(device, {"temperature": 23.4})
    """

    def __init__(
        self,
        attestor_url: str,
        cartesi_url: Optional[str] = None,
        dapp_address: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.config = LCoreConfig(
            attestor_url=attestor_url.rstrip("/"),
            cartesi_url=cartesi_url.rstrip("/") if cartesi_url else None,
            dapp_address=dapp_address,
            timeout=timeout,
        )
        self._client = httpx.Client(timeout=timeout)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> "LCoreSync":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def submit_device_data(
        self,
        device: DeviceIdentity,
        payload: dict[str, Any],
    ) -> SubmissionResult:
        """Submit signed device data to L{CORE}."""
        submission = device.sign(payload)
        url = f"{self.config.attestor_url}/api/device/submit"

        try:
            response = self._client.post(url, json=submission)
            data = response.json()

            if response.status_code == 201:
                return SubmissionResult(
                    success=True,
                    tx_hash=data.get("data", {}).get("txHash"),
                    block_number=data.get("data", {}).get("blockNumber"),
                )
            else:
                return SubmissionResult(
                    success=False,
                    error=data.get("error", f"HTTP {response.status_code}"),
                )

        except httpx.RequestError as e:
            return SubmissionResult(
                success=False,
                error=f"Request failed: {str(e)}",
            )

    def health_check(self) -> bool:
        """Check if the attestor server is healthy."""
        try:
            response = self._client.get(f"{self.config.attestor_url}/healthcheck")
            return response.status_code == 200
        except Exception:
            return False
