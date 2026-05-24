from groq import Groq
from app.core.config import GROQ_API_KEY
from fastapi import HTTPException
from app.core.logger import logger
from app.core.cost_calculator import calculate_cost
import json
import time
from app.core.request_id import generate_request_id

client = Groq(api_key=GROQ_API_KEY)

async def generate_response(query: str):
    try:
        start_time = time.time()
        request_id = generate_request_id()
        chat_completion = await client.chat.completions.create(
            messages=[{"role": "user", "content": query}],
             model="llama3-8b-8192",)
        usage =  chat_completion.usage
        prompt_tokens = usage.prompt_tokens
        completion_tokens = usage.completion_tokens
        total_tokens = usage.total_tokens
        estimated_cost = calculate_cost("llama3-8b-8192", prompt_tokens, completion_tokens)
        response = chat_completion.choices[0].message.content  
        logger.info(f"Generated Response: {response}") 

        latency = time.time() - start_time
        logger.info(f"Groq API Latency: {latency:.2f} seconds")
        logger.info(f"Token Usage - Prompt: {prompt_tokens}, Completion: {completion_tokens}, Total: {total_tokens}")
        logger.info(f"Estimated Cost for this request: ${estimated_cost:.6f}")
        logger.info(f"Request ID: {request_id}")
        return {
            "status": "success",
            "latency": latency,
            "model": "llama3-8b-8192",
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "estimated_cost": estimated_cost,
            "request_id": request_id,
            "response": response

        } 
             
    except Exception as e:
        logger.error(f"Error generating response: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Groq API Error: {str(e)}"
        )
    
async def stream_response(query: str):

    try:
        start_time = time.time()

        request_id = generate_request_id()

        stream = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": query
                }
            ],
            model="llama3-8b-8192",
            stream=True
        )

        full_response = ""

        for chunk in stream:

            content = chunk.choices[0].delta.content

            if content:

                full_response += content

                yield f"data: {content}\n\n"

        latency = time.time() - start_time

        logger.info(
            f"Groq API Stream Latency: {latency:.2f} seconds"
        )

        # Token estimation fallback
        # Streaming responses often do not return usage metadata

        estimated_prompt_tokens = len(query.split())

        estimated_completion_tokens = len(full_response.split())

        estimated_total_tokens = (
            estimated_prompt_tokens +
            estimated_completion_tokens
        )

        estimated_cost = calculate_cost(
            "llama3-8b-8192",
            estimated_prompt_tokens,
            estimated_completion_tokens
        )

        logger.info(
            f"""
            Request ID: {request_id}
            Prompt Tokens: {estimated_prompt_tokens}
            Completion Tokens: {estimated_completion_tokens}
            Total Tokens: {estimated_total_tokens}
            Estimated Cost: ${estimated_cost}
            """
        )

        metadata = {
            "status": "success",
            "latency": round(latency, 2),
            "model": "llama3-8b-8192",
            "prompt_tokens": estimated_prompt_tokens,
            "completion_tokens": estimated_completion_tokens,
            "total_tokens": estimated_total_tokens,
            "estimated_cost": estimated_cost,
            "request_id": request_id
        }

        yield f"data: {json.dumps({'__meta': metadata})}\n\n"

    except Exception as e:

        logger.error(
            f"Error streaming response: {str(e)}"
        )

        raise HTTPException(
            status_code=500,
            detail=f"Groq API Stream Error: {str(e)}"
        )