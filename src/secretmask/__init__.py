"""Typed, zero-dependency secret masker for strings and nested data."""

from __future__ import annotations

from ._config import MaskConfig
from ._mask import SecretMask, mask, mask_json, mask_text
from ._strategy import Strategy

__version__ = "0.2.0"

__all__ = ["MaskConfig", "SecretMask", "Strategy", "mask", "mask_json", "mask_text"]
