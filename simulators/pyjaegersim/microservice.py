from typing import List, Tuple, Any, Dict, Iterable
from abc import abstractmethod, ABC
from time import time_ns
import json

import numpy as np
from opentelemetry.sdk.resources import Resource
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from pyjaegersim import TracerProvider


def setup_local_tracer(serviceName, endpoint="http://localhost:4317"):
    resource = Resource.create(
        {
            "SERVICE_NAME": serviceName,  # required
            "service.name": serviceName,
        }
    )
    tracer_provider = TracerProvider(resource=resource)
    otlp_exporter = OTLPSpanExporter(endpoint=endpoint)
    exporter = BatchSpanProcessor(otlp_exporter)

    trace.set_tracer_provider(tracer_provider)
    tracer_provider.add_span_processor(exporter)

    return trace.get_tracer(__name__)


# Milliseconds in terms of Nanoseconds (Default trace unit)
MS_FROM_NS = int(1e6)


class _microservice(ABC):

    LEAF_RUNTIME = 10
    CALL_DELAY = 5

    def __init__(self, name: str, clock_skew: float = 0):
        """
        name: str
            The name of the service
        clock_skew: float
            The clock skew of the service
        """
        self.name = name
        self.clock_skew = clock_skew

    @abstractmethod
    def sample_latency(self, latency: float):
        """Sample the latency of a call to another service. Parametrized by a distribution of choice with magnitude `latency`."""
        pass

    @abstractmethod
    def generate_trace(
        self,
        startTime: int,
        edges: List[Tuple[Any, float]],
        serviceName: str = None,
    ):
        """Generates a trace for the service. This method should be implemented by the user."""
        pass


class Microservice(_microservice):

    LEAF_RUNTIME = 10 * MS_FROM_NS
    CALL_DELAY = 5 * MS_FROM_NS

    def __init__(
        self, name: str, clock_skew: float = 0, latency_distribution: str = "poisson"
    ):
        """
        name: str
            The name of the service
        clock_skew: float
            The clock skew of the service, in nanoseconds.
        latency_distribution: str
            The distribution of the latency of the service. Must be one of "poisson" or "normal".
        """
        super().__init__(name=name, clock_skew=clock_skew)

        self._latency_distribution = latency_distribution
        _latency_dist_mapp = {
            "poisson": self._sample_poisson_latency,
            "normal": self._sample_normal_latency,
        }
        if self._latency_distribution not in _latency_dist_mapp.keys():
            raise ValueError(
                "Latency distribution must be one of ", _latency_dist_mapp.keys()
            )
        self.sample_latency = _latency_dist_mapp[self._latency_distribution]

    @staticmethod
    def _sample_poisson_latency(latency: float):
        return max(np.random.poisson(latency, size=1)[0], int(0.1 * MS_FROM_NS))

    @staticmethod
    def _sample_normal_latency(latency: float):
        return max(np.random.normal(latency, latency / 10), int(0.1 * MS_FROM_NS))

    def sample_latency(self, latency: float):
        """Sample the latency of a call to another service."""
        _ = latency
        pass

    def _generate_span(
        self,
        startTime: int,
        edges: Dict[str, List[Tuple[Any, float]]],
        tracer: trace.Tracer,
    ):
        """Generate a span for the service. Calls the services in `edges` and propagates child spans generation for them."""

        calls = edges.get(self.name, [])

        with tracer.start_as_current_span(
            name=self.name,
            start_time=startTime + self.clock_skew,
            duration=self.LEAF_RUNTIME,
            end_on_exit=True,
        ) as span:
            if len(calls) == 0:
                return span

            runtime = 0
            for child, latency in calls:
                forward_latency = self.sample_latency(latency)
                back_latency = self.sample_latency(latency)

                runtime += self.CALL_DELAY
                _span = child._generate_span(
                    startTime=startTime + runtime + forward_latency,
                    edges=edges,
                    tracer=tracer,
                )
                _duration = _span._end_time - _span._start_time
                runtime += _duration + back_latency + self.CALL_DELAY

            span._end_time = span._start_time + max(self.LEAF_RUNTIME, runtime)
            return span

    def generate_trace(
        self,
        startTime: int,
        edges: List[Tuple[Any, float]],
        tracer: trace.Tracer,
    ):
        """Generates a trace for the service.

        startTime: int
            The start time of the trace.
        edges: List[Tuple[Any, float]]
            The edges of the service. A list of the form [(Microservice, latency),].
            These are the downstream services that the service calls.
        tracer: trace.Tracer
            The tracer to use for the trace.
        """
        self._generate_span(startTime, edges, tracer=tracer)


class Application:

    def __init__(
        self,
        name: str,
        frontends: Iterable[Microservice],
        nodes: Dict[str, Microservice],
        edges: Dict[str, List[Tuple[Any, float]]] = None,
        frontend_weights: List[float] = "uniform",
    ):
        """A representation of an application.

        name: str
            The name of the application, and Trace.
        frontends: List[Microservice]
            The frontends of the application, a collection of Microservices.
        nodes: Dict[str, Microservice]
            The nodes of the application. A dictionary of the form {name: Microservice}.
        edges: Dict[str, List[Tuple[Any, float]]]
            The edges of the application. A dictionary of the form {name: [(Microservice, latency),]}.
            Note: Each tuple is a downstream service and the latency of the call, which are called in order sequentially.
        frontend_weights: List[float]
            The weights of the frontends, for entry point selection. Uniform by default.
        """

        self.name = name
        self.tracer = setup_local_tracer(self.name)
        self.frontends = frontends
        self.frontend_weights = frontend_weights
        if frontend_weights == "uniform":
            self.frontend_weights = [1 / len(frontends)] * len(frontends)

        self.nodes = nodes
        self.edges = edges

    @property
    def frontend_weights(self):
        return self._frontend_weights

    @frontend_weights.setter
    def frontend_weights(self, weights):
        """Reparametrize the frontend weights as sampling distribution."""
        self._frontend_weights = np.array(weights)
        self._qc()
        self._frontend_cumsum = np.cumsum(weights)

    def generate_trace(self, startTime=None):
        value = np.random.rand()
        frontend = self.frontends[np.searchsorted(self._frontend_cumsum, value)]
        if startTime is None:
            startTime = int(time_ns())
        return frontend.generate_trace(
            startTime=startTime,
            edges=self.edges,
            tracer=self.tracer,
        )

    def _qc(self):
        if np.sum(self.frontend_weights) != 1:
            raise ValueError(
                "Frontend weights must sum to 1, got {}".format(
                    np.sum(self.frontend_weights)
                )
            )