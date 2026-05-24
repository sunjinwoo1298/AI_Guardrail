from fastapi import APIRouter
from app.models.request_models import PromptRequest
from app.services.groq_service import generate_response

router = APIRouter()

@router.post("/generate")
async def generate(request: PromptRequest):
    result = await generate_response(request.prompt)
    return result