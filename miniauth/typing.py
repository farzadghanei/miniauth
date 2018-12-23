"""
miniauth.typing
---------------
polyfil module for Python "typing", to avoid
adding dependency to "typing" module in production
where type checking is not needed.
"""
try:
    from typing import Any, AnyStr, Iterable, List, Mapping, Text, Tuple
except ImportError:
    # typing module is not available, mock imported types
    # with None so they can be imported
    Any, AnyStr, Iterable, List, Mapping, Tuple = None, None, None, None, None, None  # type: ignore
    Text = str  # type: ignore
