"""Smoke test: verify project imports and version."""

from firmable import __version__


def test_version_is_set() -> None:
    """Package version must be a non-empty string."""
    assert isinstance(__version__, str)
    assert len(__version__) > 0


def test_version_format() -> None:
    """Package version must follow semver (major.minor.patch)."""
    parts = __version__.split(".")
    assert len(parts) == 3
    for part in parts:
        assert part.isdigit()
