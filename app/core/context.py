from contextvars import ContextVar
from typing import Any, Optional

request_id_context: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
# Name of the calling application (from API_KEYS "appname:key", or "<org>/<project>" for
# control-plane tenants); labels metrics and logs.
app_context: ContextVar[str] = ContextVar("app", default="anonymous")
# Model actually serving the request (updated after a fallback); labels model metrics.
model_context: ContextVar[str] = ContextVar("model", default="none")
# The resolved control-plane tenant for this request (app.control.tenancy.TenantContext),
# or None for legacy env-configured keys.
tenant_context: ContextVar[Optional[Any]] = ContextVar("tenant", default=None)
