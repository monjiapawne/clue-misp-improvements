from enum import StrEnum

import requests
from clue.models.actions import ExecuteRequest
from consts import API_URL, MAX_TIMEOUT
from pydantic import Field


class SightingType(StrEnum):
    """Possible types a sighting could be."""

    SIGHTING = "0"
    FALSE_POSITIVE = "1"
    EXPIRATION = "1"


class ReportSighting(ExecuteRequest):
    """"""

    sighting_type: SightingType = Field(default=SightingType.SIGHTING, description="Type of sighting to report")


def report_sighting(session: requests.Session, values: list[str], request: ReportSighting):
    """Reports a list of sightings using provided values to MISP"""
    payload = {"values": values, "type": request.sighting_type}
    url = f"{API_URL}/sightings/add"
    rsp = session.post(url, json=payload, timeout=MAX_TIMEOUT)

    return rsp.text
