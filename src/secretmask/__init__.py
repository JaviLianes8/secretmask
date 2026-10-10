"""Typed, zero-dependency secret masker for strings and nested data."""

from __future__ import annotations

from ._config import MaskConfig
from ._mask import SecretMask, mask, mask_text

__version__ = "0.1.0"

__all__ = ["MaskConfig", "SecretMask", "mask", "mask_text"]
