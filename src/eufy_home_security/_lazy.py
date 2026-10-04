"""Lazy re-exports for package ``__init__`` modules (PEP 562).

A package that eagerly re-exports its submodules makes ``import package.tiny``
pay for every sibling — aiohttp, cryptography and the push stack cost over a
second on a small host. Each ``__init__`` instead declares which submodule
defines each public name and resolves it on first attribute access::

    __getattr__, __dir__ = lazy_exports(__name__, globals(), {"Thing": "thing"})
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from importlib import import_module
from typing import Any


def lazy_exports(
    package: str, namespace: dict[str, Any], exports: Mapping[str, str]
) -> tuple[Callable[[str], Any], Callable[[], list[str]]]:
    """Module-level ``__getattr__`` / ``__dir__`` resolving ``exports`` on demand.

    ``exports`` maps a public name to the submodule (relative to ``package``)
    that defines it; a name mapping to itself is the submodule object. A
    resolved name is stored in ``namespace`` so the lookup happens once.
    """

    def getattr_(name: str) -> Any:
        module = exports.get(name)
        if module is None:
            raise AttributeError(f"module {package!r} has no attribute {name!r}")
        imported = import_module(f".{module}", package)
        value = imported if module == name else getattr(imported, name)
        namespace[name] = value
        return value

    def dir_() -> list[str]:
        return sorted({*namespace, *exports})

    return getattr_, dir_
