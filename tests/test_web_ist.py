"""Tests for IST timezone conversion, datetime parsing, and report formatting."""

from datetime import datetime, timezone
import pytest
from aufla.web.server import ForensicHandler, _fmt_ist, _fmt_ist_utc


def test_iso_to_ms_naive_interpreted_as_ist():
    # Naive browser datetime-local input
    ms = ForensicHandler._iso_to_ms("2026-09-19T00:00")
    assert ms is not None
    # 2026-09-19 00:00:00 IST is 2026-09-18 18:30:00 UTC
    dt_utc = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    assert dt_utc.strftime("%Y-%m-%d %H:%M:%S") == "2026-09-18 18:30:00"


def test_iso_to_ms_date_only():
    ms_start = ForensicHandler._iso_to_ms("2026-09-19", is_end=False)
    assert ms_start is not None
    dt_start_utc = datetime.fromtimestamp(ms_start / 1000, tz=timezone.utc)
    assert dt_start_utc.strftime("%Y-%m-%d %H:%M:%S") == "2026-09-18 18:30:00"

    ms_end = ForensicHandler._iso_to_ms("2026-09-19", is_end=True)
    assert ms_end is not None
    dt_end_utc = datetime.fromtimestamp(ms_end / 1000, tz=timezone.utc)
    assert dt_end_utc.strftime("%Y-%m-%d %H:%M:%S") == "2026-09-19 18:29:59"


def test_iso_to_ms_utc_explicit():
    # Explicit UTC Z suffix must not be shifted by IST offset
    ms = ForensicHandler._iso_to_ms("2026-09-18T18:30:00Z")
    assert ms is not None
    dt_utc = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    assert dt_utc.strftime("%Y-%m-%d %H:%M:%S") == "2026-09-18 18:30:00"


def test_fmt_ist():
    ms = ForensicHandler._iso_to_ms("2026-09-19T02:25:59")
    formatted = _fmt_ist(ms)
    assert formatted == "2026-09-19 02:25:59 IST"


def test_fmt_ist_utc():
    ms = ForensicHandler._iso_to_ms("2026-09-19T02:25:59")
    formatted = _fmt_ist_utc(ms)
    assert formatted == "2026-09-19 02:25:59 IST (20:55:59Z)"
