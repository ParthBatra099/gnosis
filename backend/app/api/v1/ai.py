from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.ai.investigator import run_investigation
from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.schemas.ai import InvestigationRequest, InvestigationResponse

router = APIRouter()


@router.post("/investigate", response_model=InvestigationResponse)
def investigate(
    payload: InvestigationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> InvestigationResponse:
    """Read-only AI investigator endpoint providing structured security evidence."""
    return run_investigation(
        db=db,
        user=current_user,
        question=payload.question,
        resource_id=payload.resource_id,
        incident_id=payload.incident_id,
    )