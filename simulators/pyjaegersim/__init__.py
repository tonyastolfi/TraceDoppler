"""A package for synthetic generation of jaeger trace data."""

from .datastructs import Span, Trace
from .utils import save_traces
from .tracerprovider import TracerProvider
from .microservice import Microservice, Application
