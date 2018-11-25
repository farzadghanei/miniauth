"""
miniauth.typing
---------------
polyfil module for Python "typing", to avoid
adding dependency to "typing" module in production
where we don't need the type checking.
"""
try:
    from typing import Any, Mapping, Text
except ImportError:
    # typing module is not available, mock imported types
    # with None so they can be imported
    Any, Mapping = None, None  # type: ignore
    Text = str  # type: ignore
