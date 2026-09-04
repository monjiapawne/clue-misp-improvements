from typing import Literal

from client import misp_request
from clue.models.actions import ExecuteRequest
from consts import MAX_TIMEOUT, SIGHTING_SOURCE
from pydantic import Field

SightingType = Literal["true positive", "false positive", "expiration"]
SIGHTING_TYPE_IDS = {"true positive": "0", "false positive": "1", "expiration": "2"}


class ReportSighting(ExecuteRequest):
    """"""

    sighting_type: SightingType = Field(default="true positive", description="Type of sighting to report")


def report_sighting(values: list[str], request: ReportSighting):
    """Reports a list of sightings using provided values to MISP"""
    payload = {"values": values, "type": SIGHTING_TYPE_IDS[request.sighting_type], "source": SIGHTING_SOURCE}

    misp_request("post", "/sightings/add", MAX_TIMEOUT, json=payload)
