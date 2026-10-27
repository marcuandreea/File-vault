"""User registration and login."""

from __future__ import annotations

from filevault.models import AuditEventType, User
from filevault.models.user import normalize_email, normalize_username
from filevault.repositories.user_repository import UserRepository
from filevault.security.password_hasher import PasswordHasher
from filevault.services.audit_service import AuditService

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


class AuthenticationError(Exception):
    """Base class for authentication failures."""


class UsernameAlreadyTakenError(AuthenticationError):
    """Raised when registering with a username that already exists."""


class EmailAlreadyTakenError(AuthenticationError):
    """Raised when registering with an email that already exists."""


class InvalidCredentialsError(AuthenticationError):
    """Raised when login fails. Deliberately does not say which part was wrong."""


class AuthenticationService:
    """Registers users and checks their credentials."""

    def __init__(
        self,
        users: UserRepository,
        passwords: PasswordHasher,
        audit: AuditService,
    ) -> None:
        self._users = users
        self._passwords = passwords
        self._audit = audit

    def register(self, username: str, email: str, password: str) -> User:
        """Create an account and return the stored user."""
        self._check_password_policy(password)
        user = User.create(username, email, self._passwords.hash(password))

        if self._users.get_by_username(user.username) is not None:
            raise UsernameAlreadyTakenError(f"username '{user.username}' is taken")
        if self._users.get_by_email(user.email) is not None:
            raise EmailAlreadyTakenError(f"email '{user.email}' is taken")

        registered = self._users.add(user)
        self._audit.record(
            AuditEventType.USER_REGISTERED,
            user_id=registered.id,
            message="user registered",
        )
        return registered

    def login(self, username: str, password: str) -> User:
        """Return the user when the password matches, otherwise raise."""
        user = self._users.get_by_username(normalize_username(username))
        if user is None or not self._passwords.verify(password, user.password_hash):
            # Unknown username and wrong password produce the same audit event,
            # so the trail cannot be used to enumerate accounts.
            self._audit.record(
                AuditEventType.LOGIN_FAILED,
                message="invalid credentials",
            )
            raise InvalidCredentialsError("invalid username or password")
        self._audit.record(
            AuditEventType.LOGIN_SUCCEEDED,
            user_id=user.id,
            message="login succeeded",
        )
        return user

    @staticmethod
    def _check_password_policy(password: str) -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(
                f"password must be at least {MIN_PASSWORD_LENGTH} characters"
            )
        if len(password) > MAX_PASSWORD_LENGTH:
            raise ValueError(
                f"password must be at most {MAX_PASSWORD_LENGTH} characters"
            )
