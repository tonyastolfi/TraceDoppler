"""A package for calculating and correcting clock skew in Jaeger traces."""

__version__ = "0.3.0"

from .correcter import correct_skew
from .utils import generate_call_tree, discover_services