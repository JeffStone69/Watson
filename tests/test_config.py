"""Config file parsing."""

from pathlib import Path

import pytest

from watson.config import UsageError, config_from_mapping, load_toml

ROOT = Path(__file__).resolve().parents[1]


def test_example_config_loads_and_uses_a_placeholder_host():
    data = load_toml(ROOT / "watson.example.toml")
    config = config_from_mapping(data)
    assert config.start_url == "https://www.example.com/"
    assert config.rate == 1
    assert config.max_pages == 100
    assert config.osv_lookup is False


def test_cli_overrides_and_bad_url():
    config = config_from_mapping({}, overrides={"start_url": "https://www.example.com/path", "rate": 2, "max_pages": 5})
    assert config.rate == 2
    assert config.max_pages == 5
    with pytest.raises(UsageError):
        config_from_mapping({}, overrides={"start_url": "ftp://www.example.com/"})
