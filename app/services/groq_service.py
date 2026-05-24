from groq import Groq
from app.core.config import GROQ_API_KEY
from fastapi import HTTPException
from app.core.logger import logger
import time

client = Groq(api_key=GROQ_API_KEY)

async def generate_response(query: str):
    try:
        start_time = time.time()

        chat_completion = await client.chat.completions.create(
            messages=[{"role": "user", "content": query}],
             model="llama3-8b-8192",)
        
        response = chat_completion.choices[0].message.content  
        logger.info(f"Generated Response: {response}") 

        latency = time.time() - start_time
        logger.info(f"Groq API Latency: {latency:.2f} seconds")

        return {
            "status": "success",
            "latency": latency,
            "model": "llama3-8b-8192",
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

        chat_completion = await client.chat.completions.create(
            messages=[{"role": "user", "content": query}],
             model="llama3-8b-8192",
             stream=True
        )
        
        latency = time.time() - start_time
        logger.info(f"Groq API Stream Latency: {latency:.2f} seconds")

        async for chunk in chat_completion:
            content = chunk.choices[0].delta.get("content", "")
            if content:
                yield f"data: {content}\n\n"

    except Exception as e:
        logger.error(f"Error streaming response: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Groq API Stream Error: {str(e)}"
        )