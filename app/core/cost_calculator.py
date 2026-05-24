from app.core.pricing import MODEL_PRICING

def calculate_cost(model_name: str, input_tokens: int, output_tokens: int) -> float:
    if model_name not in MODEL_PRICING:
        raise ValueError(f"Model '{model_name}' not found in pricing configuration.")
    
    pricing = MODEL_PRICING[model_name]
    input_cost = (input_tokens / 1000) * pricing["input_cost_per_1k"]
    output_cost = (output_tokens / 1000) * pricing["output_cost_per_1k"]
    
    total_cost = input_cost + output_cost
    return total_cost