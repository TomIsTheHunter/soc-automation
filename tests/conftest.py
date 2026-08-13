import asyncio
from typing import Any

import httpx
import pytest
from pytest_socket import disable_socket, enable_socket

from app.main import create_app
from fixtures.alerts import AMBIGUOUS_ALERT, BENIGN_ALERT, HIGH_RISK_ALERT


class OfflineClient:
    def __init__(self) -> None:
        self.application = create_app()

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        disable_socket()
        transport = httpx.ASGITransport(app=self.application)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, url, **kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        enable_socket()
        try:
            return asyncio.run(self._request(method, url, **kwargs))
        finally:
            disable_socket()

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)


@pytest.fixture
def client() -> OfflineClient:
    return OfflineClient()


@pytest.fixture
def high_risk_alert() -> dict[str, object]:
    return HIGH_RISK_ALERT.copy()


@pytest.fixture
def benign_alert() -> dict[str, object]:
    return BENIGN_ALERT.copy()


@pytest.fixture
def ambiguous_alert() -> dict[str, object]:
    return AMBIGUOUS_ALERT.copy()
