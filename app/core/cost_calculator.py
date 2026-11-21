from app.core.pricing import MODEL_PRICING
from app.core.logger import logger

def calculate_cost(model_name: str, input_tokens: int, output_tokens: int) -> float:
    clean_model = model_name.split("/")[-1] if "/" in model_name else model_name
    if clean_model not in MODEL_PRICING:
        logger.warning(f"Model '{clean_model}' (from '{model_name}') not found in pricing configuration. Cost calculated as 0.0.")
        return 0.0
    
    pricing = MODEL_PRICING[clean_model]
    input_cost = (input_tokens / 1000) * pricing["input_cost_per_1k"]
    output_cost = (output_tokens / 1000) * pricing["output_cost_per_1k"]
    
    total_cost = input_cost + output_cost
    return total_cost