from enum import Enum


class OrganizationRole(str, Enum):
    SUPER_ADMIN = "SUPER_ADMIN"
    DEPARTMENT_ADMIN = "DEPARTMENT_ADMIN"
    EMPLOYEE = "EMPLOYEE"


HEALTH_STATUS_OK: str = "ok"
