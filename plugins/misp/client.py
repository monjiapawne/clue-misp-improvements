from typing import Literal

import requests
from clue.common.exceptions import (
    AuthenticationException,
    ClueException,
    TimeoutException,
)
from consts import MISP_API_KEY, MISP_URL, VERIFY

# Reuse TCP connections across requests, MISP returns 500 if too many connections
_session = requests.Session()
_session.headers.update(
    {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": MISP_API_KEY,
    }
)


def misp_request(method: Literal["get", "post"], path: str, timeout: float, **kwargs) -> dict:
    """"""

    try:
        rsp = _session.request(method, f"{MISP_URL}{path}", verify=VERIFY, timeout=timeout, **kwargs)
    except requests.exceptions.Timeout as e:
        raise TimeoutException("MISP failed to respond in time", cause=e)
    except requests.exceptions.ConnectionError as e:
        raise ClueException(f"Failed to connect to MISP: {e}", cause=e)
    except requests.exceptions.RequestException as e:
        raise ClueException(f"Request failed: {e}", cause=e)

    if rsp.status_code == 403:
        raise AuthenticationException(f"Authentication to MISP server: {MISP_URL} failed")
    elif rsp.status_code != 200:
        raise ClueException(f"Error requesting data [{rsp.status_code}]: {rsp.text[:200]}")

    try:
        return rsp.json()
    except ValueError as e:
        raise ClueException(f"MISP returned non JSON response: {rsp.text[:200]}", cause=e)
