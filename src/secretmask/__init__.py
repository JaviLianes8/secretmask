"""Typed, zero-dependency secret masker for strings, logs and nested data.

>>> from secretmask import mask, mask_text
>>> mask_text("Authorization: Bearer abc123def456ghi")
'Authorization: Bearer ***'
>>> mask({"user": "ada", "password": "hunter2"})
{'user': 'ada', 'password': '***'}
"""

from ._config import MaskConfig
from ._mask import SecretMask, mask, mask_json, mask_text
from ._strategy import Strategy

__version__ = "1.0.0"

__all__ = ["MaskConfig", "SecretMask", "Strategy", "mask", "mask_json", "mask_text"]

# Public names report the package as their home, as in help() and tracebacks.
for _name in __all__:
    globals()[_name].__module__ = __name__
del _name
