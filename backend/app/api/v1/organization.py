"""MFA-protected organization APIs. No business data or credential responses."""
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models import Department, DepartmentAdminAssignment, User
from app.schemas.organization import (
    AssignmentCreate, AssignmentPage, AssignmentRead, DepartmentCreate, DepartmentMutation, DepartmentPage,
    DepartmentRead, DepartmentUpdate, EmployeeCreate, EmployeeCreated, EmployeePage, EmployeeRead,
    EmployeeUpdate, IdentityMutation, RoleChange,
)
from app.services import organization_management as service
from app.services.identity_service import IdentityError, StaleIdentityError
from app.services.organization_authority import OrganizationScope
from app.services import session_management
from app.schemas.auth import SessionPage, SessionRevokeRequest
from fastapi import Request, Response


class OrganizationRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        async def safe_handler(request):
            try:
                response = await handler(request)
            except RequestValidationError:
                response = JSONResponse({"detail": {"code": "INVALID_INPUT"}}, status_code=422)
            except StaleIdentityError:
                response = JSONResponse({"detail": {"code": "STALE_REVISION"}}, status_code=409)
            except IdentityError:
                response = JSONResponse({"detail": {"code": "IDENTITY_INVARIANT"}}, status_code=409)
            except IntegrityError:
                response = JSONResponse({"detail": {"code": "IDENTITY_CONFLICT"}}, status_code=409)
            except HTTPException:
                raise
            except Exception:
                response = JSONResponse({"detail": {"code": "SERVICE_UNAVAILABLE"}}, status_code=503)
            response.headers["Cache-Control"] = "no-store"
            return response
        return safe_handler


router = APIRouter(route_class=OrganizationRoute)
Identifier = Annotated[str, Path(min_length=1, max_length=36)]


def page(query, limit, offset, convert):
    total = query.count()  # Scope/search/filters are already SQL predicates.
    return {"items": [convert(row) for row in query.limit(limit).offset(offset).all()],
            "total": total, "limit": limit, "offset": offset}


@router.get("/departments", response_model=DepartmentPage)
def list_departments(q: str | None = Query(default=None, max_length=100), active: bool | None = None,
                     limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0, le=100000),
                     current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = service.departments_query(db, current_user.id)
    if q:
        query = query.filter(func.lower(Department.name).contains(q.lower(), autoescape=True))
    if active is not None:
        query = query.filter(Department.active == active)
    return page(query.order_by(Department.name, Department.id), limit, offset, lambda row: service.department_read(db, row))


@router.get("/departments/{department_id}", response_model=DepartmentRead)
def get_department(department_id: Identifier, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return service.department_read(db, service.department_target(db, current_user.id, department_id))


@router.post("/departments", response_model=DepartmentRead, status_code=201)
def create_department(payload: DepartmentCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    with service.mutation(db, current_user.id, service.A.ORGANIZATION_ADMINISTER) as tx:
        return service.create_department(tx, current_user.id, payload)


@router.patch("/departments/{department_id}", response_model=DepartmentRead)
def update_department(department_id: Identifier, payload: DepartmentUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    with service.mutation(db, current_user.id, service.A.ORGANIZATION_ADMINISTER) as tx:
        return service.update_department(tx, current_user.id, department_id, payload)


@router.post("/departments/{department_id}/deactivate", response_model=DepartmentRead)
def deactivate_department(department_id: Identifier, payload: DepartmentMutation, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    with service.mutation(db, current_user.id, service.A.ORGANIZATION_ADMINISTER) as tx:
        return service.department_status(tx, current_user.id, department_id, payload, False)


@router.post("/departments/{department_id}/reactivate", response_model=DepartmentRead)
def reactivate_department(department_id: Identifier, payload: DepartmentMutation, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    with service.mutation(db, current_user.id, service.A.ORGANIZATION_ADMINISTER) as tx:
        return service.department_status(tx, current_user.id, department_id, payload, True)


@router.get("/employees", response_model=EmployeePage)
def list_employees(q: str | None = Query(default=None, max_length=100), home_department_id: str | None = Query(default=None, max_length=36),
                   active: bool | None = None, limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0, le=100000),
                   current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = service.employees_query(db, current_user.id)
    if q:
        query = query.filter(or_(func.lower(User.name).contains(q.lower(), autoescape=True),
                                 func.lower(User.email).contains(q.lower(), autoescape=True)))
    if home_department_id is not None:
        query = query.filter(User.department_id == home_department_id)
    if active is not None:
        query = query.filter(User.active == active)
    return page(query.order_by(User.name, User.id), limit, offset, lambda row: service.employee_read(db, row))


@router.get("/employees/{user_id}", response_model=EmployeeRead)
def get_employee(user_id: Identifier, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return service.employee_read(db, service.employee_target(db, current_user.id, user_id))


@router.post("/employees", response_model=EmployeeCreated, status_code=201)
def create_employee(payload: EmployeeCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    with service.mutation(db, current_user.id, service.A.IDENTITY_ADMINISTER) as tx:
        result = service.create_employee(tx, current_user.id, payload)
        return {**result.model_dump(), "requires_trusted_onboarding": True}


@router.patch("/employees/{user_id}", response_model=EmployeeRead)
def update_employee(user_id: Identifier, payload: EmployeeUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    with service.mutation(db, current_user.id, service.A.IDENTITY_ADMINISTER) as tx:
        return service.update_employee(tx, current_user.id, user_id, payload)


@router.post("/employees/{user_id}/role", response_model=EmployeeRead)
def change_role(user_id: Identifier, payload: RoleChange, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    with service.mutation(db, current_user.id, service.A.IDENTITY_ADMINISTER) as tx:
        return service.change_role(tx, current_user.id, user_id, payload)


@router.post("/employees/{user_id}/deactivate", response_model=EmployeeRead)
def deactivate_employee(user_id: Identifier, payload: IdentityMutation, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    with service.mutation(db, current_user.id, service.A.IDENTITY_ADMINISTER) as tx:
        return service.employee_status(tx, current_user.id, user_id, payload, False)


@router.post("/employees/{user_id}/reactivate", response_model=EmployeeRead)
def reactivate_employee(user_id: Identifier, payload: IdentityMutation, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    with service.mutation(db, current_user.id, service.A.IDENTITY_ADMINISTER) as tx:
        return service.employee_status(tx, current_user.id, user_id, payload, True)


def assignments_query(db, actor_id, department_id=None, user_id=None):
    global_access, ids = service.read_scope(db, actor_id, service.A.DEPARTMENT_ASSIGNMENTS_ADMINISTER)
    query = db.query(DepartmentAdminAssignment)
    if not global_access:
        query = query.filter(DepartmentAdminAssignment.department_id.in_(ids))
    if department_id is not None:
        if not global_access and department_id not in ids:
            service.error(404, "NOT_FOUND")
        if db.scalar(select(Department.id).where(Department.id == department_id)) is None:
            service.error(404, "NOT_FOUND")
        query = query.filter(DepartmentAdminAssignment.department_id == department_id)
    if user_id is not None:
        service.employee_target(db, actor_id, user_id)
        query = query.filter(DepartmentAdminAssignment.user_id == user_id)
    return query


def assignments_page(db, query, active, limit, offset):
    if active is not None:
        query = query.filter(DepartmentAdminAssignment.revoked_at.is_(None) if active else DepartmentAdminAssignment.revoked_at.is_not(None))
    return page(query.order_by(DepartmentAdminAssignment.assigned_at.desc(), DepartmentAdminAssignment.id), limit, offset,
                lambda row: service.assignment_read(db, row))


@router.get("/assignments", response_model=AssignmentPage)
def list_assignments(department_id: str | None = Query(default=None, max_length=36), user_id: str | None = Query(default=None, max_length=36),
                     active: bool | None = None, limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0, le=100000),
                     current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    service.require(service.authority.evaluate_authority(db, current_user.id, service.A.DEPARTMENT_ASSIGNMENTS_ADMINISTER, OrganizationScope()))
    return assignments_page(db, assignments_query(db, current_user.id, department_id, user_id), active, limit, offset)


@router.get("/departments/{department_id}/assignments", response_model=AssignmentPage)
def department_assignments(department_id: Identifier, active: bool | None = None, limit: int = Query(default=50, ge=1, le=100),
                           offset: int = Query(default=0, ge=0, le=100000), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return assignments_page(db, assignments_query(db, current_user.id, department_id=department_id), active, limit, offset)


@router.get("/employees/{user_id}/assignments", response_model=AssignmentPage)
def employee_assignments(user_id: Identifier, active: bool | None = None, limit: int = Query(default=50, ge=1, le=100),
                         offset: int = Query(default=0, ge=0, le=100000), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return assignments_page(db, assignments_query(db, current_user.id, user_id=user_id), active, limit, offset)


@router.post("/assignments", response_model=AssignmentRead, status_code=201)
def create_assignment(payload: AssignmentCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    with service.mutation(db, current_user.id, service.A.DEPARTMENT_ASSIGNMENTS_ADMINISTER) as tx:
        return service.create_assignment(tx, current_user.id, payload)


@router.post("/assignments/{assignment_id}/revoke", response_model=AssignmentRead)
def revoke_assignment(assignment_id: Identifier, payload: IdentityMutation, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    with service.mutation(db, current_user.id, service.A.DEPARTMENT_ASSIGNMENTS_ADMINISTER) as tx:
        return service.revoke_assignment(tx, current_user.id, assignment_id, payload)


@router.get("/employees/{user_id}/sessions", response_model=SessionPage)
def employee_sessions(user_id: Identifier, request: Request,
                      limit: int = Query(default=20, ge=1, le=100), offset: int = Query(default=0, ge=0, le=100000),
                      current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Even self-targeting through the administrator route requires identity authority.
    service.require(service.authority.evaluate_authority(db, current_user.id, service.A.IDENTITY_ADMINISTER, OrganizationScope()))
    return session_management.inventory(db, current_user.id, user_id,
                                        request.state.principal.authentication_context_id, limit=limit, offset=offset)


@router.post("/employees/{user_id}/sessions/{session_ref}/revoke", status_code=204)
def revoke_employee_session(user_id: Identifier, payload: SessionRevokeRequest, request: Request, session_ref: str = Path(pattern=r"^[0-9a-f]{64}$"),
                            current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Transactional revalidation is also performed by the service for cross-user targets.
    with service.mutation(db, current_user.id, service.A.IDENTITY_ADMINISTER) as tx:
        # Use this same explicit transaction, rather than a separately committing service call.
        session_management.revoke_in_transaction(tx, current_user.id, user_id, session_ref, payload.reason,
                                                 request.state.principal.authentication_context_id)
    return Response(status_code=204)
