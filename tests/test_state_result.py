"""Real Runner STATE_RESULT shape and compatibility with older senders."""

import pytest

from scrp.envelope import Endpoint, new_message_id
from scrp.validate import ARTIFACT_EXPORT_V1, ProtocolError, validate


def state_result(**extra):
    payload = dict(runtime_state="READY", worker_alive=True, queue_depth=0, action_state=None)
    payload.update(extra)
    return Endpoint("SES-001", "RT-SBX-001", 1, "CONN-001").envelope(
        "STATE_RESULT", payload, correlation_id=new_message_id(), status="OK")


@pytest.mark.parametrize("profile", [None, ARTIFACT_EXPORT_V1])
@pytest.mark.parametrize("title", ["", "Run", "실행", "a" * 256, "가" * 85 + "a"],
                         ids=["empty", "ascii", "korean", "ascii_boundary", "utf8_boundary"])
def test_runner_foreground_title_is_accepted(profile, title):
    # Includes empty captions and the Runner's 256 UTF-8-byte boundary.
    assert len(title.encode("utf-8")) <= 256
    validate(state_result(foreground_window=title), profile)


def test_older_runner_without_foreground_title_is_accepted():
    validate(state_result())


@pytest.mark.parametrize("title", [None, 0, True, [], {}, "a" * 257])
def test_invalid_foreground_title_is_rejected(title):
    with pytest.raises(ProtocolError) as error:
        validate(state_result(foreground_window=title))
    assert error.value.code == "INVALID_ARGUMENT"


def test_unregistered_state_property_still_rejected():
    with pytest.raises(ProtocolError, match="unexpected") as error:
        validate(state_result(foreground_window="실행", unexpected="value"))
    assert error.value.code == "INVALID_ARGUMENT"
