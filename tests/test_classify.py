"""Status groups for the link checker."""

from watson.classify import (
    BROKEN,
    INSECURE,
    OK,
    REDIRECT,
    UNVERIFIED,
    classify_link,
)

HOME = "https://www.example.com/"


def _classify(**kwargs):
    defaults = {
        "status": None,
        "error": None,
        "location": None,
        "requested_url": "https://www.example.com/page",
        "home_url": HOME,
        "raw_href": "/page",
    }
    defaults.update(kwargs)
    return classify_link(**defaults)


def test_broken_statuses_and_transport_errors():
    assert _classify(status=404).category == BROKEN
    assert _classify(status=410).category == BROKEN
    assert _classify(error="dns").category == BROKEN
    assert _classify(error="refused").category == BROKEN
    assert _classify(error="timeout").category == BROKEN
    assert "http://" in _classify(status=404, raw_href="http://www.example.com/old").reason


def test_could_not_verify():
    for status in (401, 403, 429, 500, 503, 999):
        result = _classify(status=status)
        assert result.category == UNVERIFIED, status
    assert _classify(error="connect").category == UNVERIFIED
    assert _classify(error="tls").category == UNVERIFIED


def test_ordinary_redirect_is_not_a_soft_404():
    result = _classify(
        status=301,
        location="https://www.example.com/docs/handbook.pdf",
        requested_url="https://www.example.com/handbook",
    )
    assert result.category == REDIRECT
    assert result.soft_404 is False


def test_working_relative_link_is_ok_and_explicit_http_is_insecure():
    assert _classify(status=200, raw_href="/about").category == OK
    insecure = _classify(status=200, raw_href="http://www.example.com/about")
    assert insecure.category == INSECURE
    assert insecure.soft_404 is False
