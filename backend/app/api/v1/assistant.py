from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.schemas.assistant import AssistantQueryRequest, AssistantQueryResponse
from app.services.assistant_service import AssistantService

router = APIRouter()


@router.post("/query", response_model=AssistantQueryResponse)
def ask_assistant(
    payload: AssistantQueryRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AssistantQueryResponse:
    """Ask GNOSIS: thin bridge to the deterministic, authorization-enforcing AssistantService."""
    result = AssistantService.process_query(db, current_user, payload.query)
    return AssistantQueryResponse(
        answer=result.answer,
        sources=result.sources,
        access_denied=result.access_denied,
    )