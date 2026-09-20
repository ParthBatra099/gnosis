import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.database import SessionLocal
from app.core.security import hash_password
from app.models import Department, User


def get_or_create_department(db, name: str, description: str) -> Department:
    department = (
        db.query(Department)
        .filter(Department.name == name)
        .first()
    )

    if department:
        print(f"Department '{name}' already exists.")
        return department

    department = Department(
        name=name,
        description=description,
    )
    db.add(department)
    db.commit()
    db.refresh(department)

    print(f"Created Department: {name}")
    return department


def get_or_create_user(
    db,
    name: str,
    email: str,
    legacy_email: str,
    password: str,
    role: str,
    department_id: str,
) -> User:
    # Check if target email already exists
    user = db.query(User).filter(User.email == email).first()
    if user:
        print(f"User '{email}' already exists.")
        return user

    # Check if legacy email exists and update it
    legacy_user = db.query(User).filter(User.email == legacy_email).first()
    if legacy_user:
        legacy_user.email = email
        db.commit()
        db.refresh(legacy_user)
        print(f"Updated user email: {legacy_email} -> {email}")
        return legacy_user

    # Create new user if neither exists
    user = User(
        name=name,
        email=email,
        password_hash=hash_password(password),
        role=role,
        department_id=department_id,
        active=True,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    print(f"Created User: {name} ({email})")
    return user


def seed_demo_users() -> None:
    db = SessionLocal()

    try:
        it_department = get_or_create_department(
            db,
            "IT",
            "Information Technology",
        )

        hr_department = get_or_create_department(
            db,
            "HR",
            "Human Resources",
        )

        get_or_create_user(
            db=db,
            name="GNOSIS Admin",
            email="admin@gnosis.com",
            legacy_email="admin@gnosis.local",
            password="Admin@12345",
            role="ADMIN",
            department_id=it_department.id,
        )

        get_or_create_user(
            db=db,
            name="Demo Employee",
            email="employee@gnosis.com",
            legacy_email="employee@gnosis.local",
            password="Employee@12345",
            role="EMPLOYEE",
            department_id=hr_department.id,
        )

    finally:
        db.close()


if __name__ == "__main__":
    seed_demo_users()