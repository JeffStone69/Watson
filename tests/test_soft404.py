"""Soft 404s: redirects home, redirects to a not-found page, or a 200 that says so."""

from watson.classify import REDIRECT, classify_link, detect_soft_404

HOME = "https://example-school.example.edu/"
PAGE = "https://example-school.example.edu/news/old-story"


def test_redirect_to_home_is_a_soft_404():
    assert detect_soft_404(
        requested_url=PAGE,
        status=302,
        location=HOME,
        home_url=HOME,
    )
    result = classify_link(
        status=302,
        error=None,
        location="/",
        requested_url=PAGE,
        home_url=HOME,
        raw_href="/news/old-story",
    )
    assert result.category == REDIRECT
    assert result.soft_404 is True
    assert "home page" in result.reason


def test_redirect_to_a_not_found_path_is_a_soft_404():
    assert detect_soft_404(
        requested_url=PAGE,
        status=302,
        location="https://example-school.example.edu/not-found.html",
        home_url=HOME,
    )


def test_real_404_is_not_soft():
    assert not detect_soft_404(
        requested_url=PAGE,
        status=404,
        location=None,
        home_url=HOME,
    )


def test_the_not_found_page_itself_is_not_reported_again():
    assert not detect_soft_404(
        requested_url="https://example-school.example.edu/not-found.html",
        status=200,
        location=None,
        home_url=HOME,
        title="Page not found",
        heading="Page not found",
    )


def test_ok_page_with_a_not_found_title_is_soft():
    assert detect_soft_404(
        requested_url=PAGE,
        status=200,
        location=None,
        home_url=HOME,
        title="Page not found",
        heading="The page you requested is not available",
    )


def test_home_page_redirecting_to_itself_is_not_soft():
    assert not detect_soft_404(
        requested_url=HOME,
        status=302,
        location=HOME,
        home_url=HOME,
    )
