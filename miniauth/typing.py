"""
miniauth.typing
---------------
polyfil module for Python "typing", to avoid
adding dependency to "typing" module in production
where type checking is not needed.
"""
try:
    from typing import Any, Iterable, Mapping, Text
except ImportError:
    # typing module is not available, mock imported types
    # with None so they can be imported
    Iterable, Any, Mapping = None, None, None  # type: ignore
    Text = str  # type: ignore
