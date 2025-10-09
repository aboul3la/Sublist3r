"""subbrute package initializer.

This exposes the subbrute module at package level so code that does
`from subbrute import subbrute` continues to work when the package is
installed or used from a development checkout.
"""

# Re-export the subbrute module so `from subbrute import subbrute` works
from . import subbrute

__all__ = ["subbrute"]
