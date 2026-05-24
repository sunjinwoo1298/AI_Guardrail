from fastapi import APIRouter
from app.models.request_models import PromptRequest
from app.services.groq_service import generate_response, stream_response


router = APIRouter()

@router.post("/generate")
async def generate(request: PromptRequest):
    result = await generate_response(request.prompt)
    return result

@router.post("/stream")
async def stream(request: PromptRequest):
    result = await stream_response(request.prompt)
    return result