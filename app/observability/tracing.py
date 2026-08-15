import os

try:
    from opentelemetry import trace
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
except ImportError:  # pragma: no cover - optional during test/runtime bootstrap
    trace = None
    FastAPIInstrumentor = None
    OTLPSpanExporter = None
    Resource = None
    TracerProvider = None
    BatchSpanProcessor = None


def setup_tracing(service_name: str = "ai-guardrail-proxy"):
    if trace is None:
        return None

    resource = Resource.create({"service.name": service_name}) if Resource else None
    provider = TracerProvider(resource=resource) if resource else TracerProvider()
    exporter = None

    endpoint = os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    if endpoint and OTLPSpanExporter is not None:
        exporter = OTLPSpanExporter(endpoint=endpoint)
    elif OTLPSpanExporter is not None:
        exporter = OTLPSpanExporter()

    if exporter is not None:
        provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)
    return trace.get_tracer(service_name)


def instrument_fastapi(app):
    if FastAPIInstrumentor is None:
        return None
    FastAPIInstrumentor.instrument_app(app)
    return app
