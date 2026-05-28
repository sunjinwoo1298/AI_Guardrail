from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, Iterable, Tuple


DEFAULT_HISTOGRAM_BUCKETS = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    float("inf"),
)

_REGISTRY = []
_REGISTRY_LOCK = Lock()


def _normalize_labels(labelnames: Tuple[str, ...], labels: Dict[str, str]) -> Tuple[str, ...]:
    return tuple(str(labels.get(name, "")) for name in labelnames)


def _escape_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n")


@dataclass
class _MetricBase:
    name: str
    documentation: str
    labelnames: Tuple[str, ...] = field(default_factory=tuple)
    metric_type: str = "untyped"

    def __post_init__(self):
        self._samples = {}
        self._lock = Lock()
        with _REGISTRY_LOCK:
            _REGISTRY.append(self)

    def labels(self, **kwargs):
        if len(kwargs) != len(self.labelnames):
            missing = [label for label in self.labelnames if label not in kwargs]
            raise ValueError(f"Missing labels: {missing}")

        label_values = _normalize_labels(self.labelnames, kwargs)
        with self._lock:
            if label_values not in self._samples:
                self._samples[label_values] = self._new_child(label_values)
            return self._samples[label_values]

    def _new_child(self, label_values: Tuple[str, ...]):
        return _BoundMetric(self, label_values)

    def _iter_sample_lines(self):
        raise NotImplementedError


class _BoundMetric:
    def __init__(self, parent: _MetricBase, label_values: Tuple[str, ...]):
        self.parent = parent
        self.label_values = label_values
        self.value = 0.0
        self.sum = 0.0
        self.count = 0.0
        if parent.metric_type == "histogram":
            self.bucket_counts = {bucket: 0.0 for bucket in DEFAULT_HISTOGRAM_BUCKETS}

    def _inc(self, amount: float):
        self.value += amount

    def inc(self, amount: float = 1.0):
        self._inc(amount)

    def dec(self, amount: float = 1.0):
        self._inc(-amount)

    def observe(self, amount: float):
        self.sum += amount
        self.count += 1
        for bucket in DEFAULT_HISTOGRAM_BUCKETS:
            if amount <= bucket:
                self.bucket_counts[bucket] += 1


class Counter(_MetricBase):
    metric_type = "counter"

    def __init__(self, name: str, documentation: str, labelnames: Iterable[str] = ()): 
        self.name = name
        self.documentation = documentation
        self.labelnames = tuple(labelnames)
        self.metric_type = "counter"
        super().__post_init__()

    def inc(self, amount: float = 1.0):
        self.labels() if not self.labelnames else None
        self._default_child().inc(amount)

    def _default_child(self):
        key = tuple()
        with self._lock:
            if key not in self._samples:
                self._samples[key] = _BoundMetric(self, key)
            return self._samples[key]


class Gauge(_MetricBase):
    metric_type = "gauge"

    def __init__(self, name: str, documentation: str, labelnames: Iterable[str] = ()): 
        self.name = name
        self.documentation = documentation
        self.labelnames = tuple(labelnames)
        self.metric_type = "gauge"
        super().__post_init__()

    def inc(self, amount: float = 1.0):
        self._default_child().inc(amount)

    def dec(self, amount: float = 1.0):
        self._default_child().dec(amount)

    def _default_child(self):
        key = tuple()
        with self._lock:
            if key not in self._samples:
                self._samples[key] = _BoundMetric(self, key)
            return self._samples[key]


class Histogram(_MetricBase):
    metric_type = "histogram"

    def __init__(self, name: str, documentation: str, labelnames: Iterable[str] = ()): 
        self.name = name
        self.documentation = documentation
        self.labelnames = tuple(labelnames)
        self.metric_type = "histogram"
        super().__post_init__()

    def observe(self, amount: float):
        self._default_child().observe(amount)

    def _default_child(self):
        key = tuple()
        with self._lock:
            if key not in self._samples:
                self._samples[key] = _BoundMetric(self, key)
            return self._samples[key]


def _format_labels(labelnames: Tuple[str, ...], label_values: Tuple[str, ...]) -> str:
    if not labelnames:
        return ""
    pairs = [f'{name}="{_escape_text(value)}"' for name, value in zip(labelnames, label_values)]
    return "{" + ",".join(pairs) + "}"


def _render_metric(metric: _MetricBase) -> str:
    lines = [f"# HELP {metric.name} {_escape_text(metric.documentation)}", f"# TYPE {metric.name} {metric.metric_type}"]
    for label_values, sample in metric._samples.items():
        labels = _format_labels(metric.labelnames, label_values)
        if metric.metric_type == "counter":
            lines.append(f"{metric.name}_total{labels} {sample.value}")
        elif metric.metric_type == "gauge":
            lines.append(f"{metric.name}{labels} {sample.value}")
        elif metric.metric_type == "histogram":
            cumulative = 0.0
            for bucket in DEFAULT_HISTOGRAM_BUCKETS:
                cumulative += sample.bucket_counts[bucket]
                bucket_label = labels[:-1] + ("," if labels else "{") if labels else "{"
                if labels:
                    bucket_labels = labels[:-1] + f',le="{bucket if bucket != float("inf") else "+Inf"}"' + "}"
                else:
                    bucket_labels = f'{{le="{bucket if bucket != float("inf") else "+Inf"}"}}'
                lines.append(f"{metric.name}_bucket{bucket_labels} {cumulative}")
            lines.append(f"{metric.name}_count{labels} {sample.count}")
            lines.append(f"{metric.name}_sum{labels} {sample.sum}")
    return "\n".join(lines)


def generate_latest() -> bytes:
    with _REGISTRY_LOCK:
        metrics = list(_REGISTRY)
    text = "\n".join(_render_metric(metric) for metric in metrics)
    return (text + "\n").encode("utf-8")


def make_asgi_app():
    async def app(scope, receive, send):
        if scope["type"] != "http":
            return

        body = generate_latest()
        headers = [
            (b"content-type", b"text/plain; version=0.0.4; charset=utf-8"),
            (b"cache-control", b"no-cache"),
        ]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    return app
