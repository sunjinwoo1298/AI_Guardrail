from app.core.logger import logger
from app.core.pricing import get_pricing


def is_priced(model_name: str) -> bool:
    return get_pricing(model_name) is not None


def calculate_cost(model_name: str, input_tokens: int, output_tokens: int) -> float:
    """USD cost = input_tokens/1M * input price + output_tokens/1M * output price.

    Returns 0.0 for models with no price entry; callers use `is_priced` to tell
    "free" apart from "unknown" (and the proxy exports a metric for the latter).
    """
    pricing = get_pricing(model_name)
    if pricing is None:
        logger.warning(f"No pricing configured for model '{model_name}'; cost reported as 0.0")
        return 0.0
    cost = (input_tokens / 1_000_000) * pricing["input"] + (output_tokens / 1_000_000) * pricing["output"]
    return round(cost, 8)
