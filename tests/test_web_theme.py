"""Tests for AUFLA dashboard theme support (Dark and Light themes)."""

from pathlib import Path
from aufla.web.server import STATIC


def test_index_html_has_theme_support():
    assert STATIC.exists(), "index.html must exist in aufla/web"
    content = STATIC.read_text(encoding="utf-8")

    # Light theme CSS selector and color variables
    assert '[data-theme="light"]' in content
    assert "--page:#f6f8fa" in content or "--page: #f6f8fa" in content
    assert "--surface:#ffffff" in content or "--surface: #ffffff" in content

    # Theme toggle control
    assert 'id="themetoggle"' in content
    assert "theme-toggle" in content

    # Persistence in localStorage
    assert 'localStorage.getItem("aufla_theme")' in content
    assert 'localStorage.setItem("aufla_theme"' in content

    # System prefers-color-scheme detection
    assert "prefers-color-scheme: light" in content
