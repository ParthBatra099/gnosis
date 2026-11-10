from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.access import router as access_router
from app.api.v1.ai import router as ai_router
from app.api.v1.assistant import router as assistant_router
from app.api.v1.auth import router as auth_router
from app.api.v1.console import router as console_router
from app.api.v1.monitoring import router as monitoring_router
from app.api.v1.resources import router as resources_router
from app.api.v1.organization import router as organization_router
from app.core.config import settings
from app.core.constants import HEALTH_STATUS_OK

def create_app():
    app = FastAPI(
        title=settings.PROJECT_NAME,
        debug=settings.DEBUG,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.AUTH_ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
    )

    # Register routers
    app.include_router(auth_router, prefix="/auth", tags=["Auth"])
    app.include_router(resources_router, prefix="/resources", tags=["Resources"])
    app.include_router(access_router, prefix="/access", tags=["Access"])
    app.include_router(monitoring_router, prefix="/monitoring", tags=["Monitoring"])
    app.include_router(console_router, prefix="/console", tags=["Console"])
    app.include_router(ai_router, prefix="/ai", tags=["AI Investigator"])
    app.include_router(assistant_router, prefix="/assistant", tags=["Assistant"])
    app.include_router(organization_router, prefix="/organization", tags=["Organization"])


    @app.get("/health", status_code=200)
    def health_check() -> dict[str, str]:
        """Public health status check endpoint."""
        return {"status": HEALTH_STATUS_OK}

    return app


app = create_app()
