"""In-memory persistence with locking.

A single :class:`DataStore` instance is shared per application (and per
test). All mutating operations are serialized by a re-entrant lock so that
converted refresh-token races are decided atomically: exactly one
concurrent rotation can win.
"""

from __future__ import annotations

import threading
from collections import defaultdict

from app.models import Document, RefreshTokenRecord, Session, User


class DataStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.users_by_id: dict[str, User] = {}
        self.users_by_username: dict[str, str] = {}
        self.sessions: dict[str, Session] = {}
        self.refresh_tokens: dict[str, RefreshTokenRecord] = {}
        # Family-level compromise flag set when a rotated token is replayed.
        self.compromised_families: set[str] = set()
        # Bumped whenever a user's roles/permissions change or the user is
        # disabled/re-enabled; access tokens older than this are stale.
        self.security_version: dict[str, int] = defaultdict(int)
        # Example resource domain used by the demo routes.
        self.documents: dict[str, Document] = {}

    # ------------------------------------------------------------------ users
    def add_user(self, user: User) -> None:
        with self._lock:
            self.users_by_id[user.id] = user
            self.users_by_username[user.username] = user.id
            self.security_version[user.id] = 1

    def get_user(self, user_id: str) -> User | None:
        with self._lock:
            return self.users_by_id.get(user_id)

    def get_user_by_username(self, username: str) -> User | None:
        with self._lock:
            user_id = self.users_by_username.get(username)
            return self.users_by_id.get(user_id) if user_id else None

    def update_user_security(self, user_id: str) -> None:
        """Record that roles/permissions/disabled changed; bump version."""
        with self._lock:
            self.security_version[user_id] += 1

    def get_security_version(self, user_id: str) -> int:
        with self._lock:
            return self.security_version.get(user_id, 0)

    # --------------------------------------------------------------- sessions
    def add_session(self, session: Session) -> None:
        with self._lock:
            self.sessions[session.id] = session

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            return self.sessions.get(session_id)

    def revoke_session(self, session_id: str, reason: str = "logout") -> None:
        with self._lock:
            session = self.sessions.get(session_id)
            if session and not session.revoked:
                session.revoked = True
                session.revoked_reason = reason

    def revoke_all_user_sessions(self, user_id: str, reason: str = "user_security_change") -> None:
        with self._lock:
            for session in self.sessions.values():
                if session.user_id == user_id and not session.revoked:
                    session.revoked = True
                    session.revoked_reason = reason

    # ---------------------------------------------------------- refresh tokens
    def save_refresh_token(self, record: RefreshTokenRecord) -> None:
        with self._lock:
            self.refresh_tokens[record.id] = record

    def get_refresh_token(self, token_id: str) -> RefreshTokenRecord | None:
        with self._lock:
            return self.refresh_tokens.get(token_id)

    def rotate_refresh_token(
        self, old_id: str, new_record: RefreshTokenRecord, now: float
    ) -> RefreshTokenRecord | None:
        """Atomically consume *old_id* and install *new_record*.

        Returns the consumed record for the single winning caller, or
        ``None`` if the token was already used / revoked / missing.
        """
        with self._lock:
            old = self.refresh_tokens.get(old_id)
            if old is None or old.used or old.revoked:
                return None
            old.used = True
            old.replaced_by = new_record.id
            self.refresh_tokens[new_record.id] = new_record
            session = self.sessions.get(old.session_id)
            if session is not None:
                session.last_rotated_at = now
            return old

    def mark_family_compromised(self, family_id: str, reason: str = "replay") -> None:
        """Replay of an already-rotated token: revoke the whole family."""
        with self._lock:
            self.compromised_families.add(family_id)
            for rt in self.refresh_tokens.values():
                if rt.family_id == family_id:
                    rt.revoked = True
            session_ids = {
                rt.session_id
                for rt in self.refresh_tokens.values()
                if rt.family_id == family_id
            }
            for sid in session_ids:
                self.revoke_session(sid, reason=f"compromised:{reason}")

    def is_family_compromised(self, family_id: str) -> bool:
        with self._lock:
            return family_id in self.compromised_families

    def revoke_family(self, family_id: str, reason: str = "logout") -> None:
        with self._lock:
            for rt in self.refresh_tokens.values():
                if rt.family_id == family_id and not (rt.used and rt.replaced_by):
                    rt.revoked = True
            session_ids = {
                rt.session_id
                for rt in self.refresh_tokens.values()
                if rt.family_id == family_id
            }
            for sid in session_ids:
                self.revoke_session(sid, reason=reason)

    # --------------------------------------------------------------- documents
    def add_document(self, document: Document) -> None:
        with self._lock:
            self.documents[document.id] = document

    def get_document(self, document_id: str) -> Document | None:
        with self._lock:
            return self.documents.get(document_id)

    def delete_document(self, document_id: str) -> None:
        with self._lock:
            self.documents.pop(document_id, None)
