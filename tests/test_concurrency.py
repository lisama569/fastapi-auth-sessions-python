"""Concurrent refresh, replay containment and revocation consistency."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from app.models import Session
from app.tokens import issue_token_pair


def _concurrent_refresh(store, settings, raw_token, *, workers=16):
    start = threading.Barrier(workers)

    def worker():
        start.wait()  # maximize contention: all threads enter together
        try:
            from app.tokens import rotate_refresh_token

            return rotate_refresh_token(raw_token, store, settings, source="load-test")
        except Exception as exc:
            return exc

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda _: worker(), range(workers)))


def test_concurrent_refresh_exactly_one_wins(store, settings, audit_records):
    user = store.get_user_by_username("alice")
    session = Session(id="s-conc-1", user_id=user.id, created_at=0, last_rotated_at=0)
    store.add_session(session)
    pair = issue_token_pair(store, user, session, settings)

    outcomes = _concurrent_refresh(store, settings, pair.refresh_token, workers=24)

    successes = [o for o in outcomes if not isinstance(o, Exception)]
    failures = [o for o in outcomes if isinstance(o, Exception)]

    # Exactly one request succeeds and produces a new valid session token.
    assert len(successes) == 1, outcomes
    assert len(failures) == 23

    from app.errors import AuthErrorCode

    # Losers must all be reported as replay, not generic errors.
    assert all(f.code is AuthErrorCode.TOKEN_REPLAYED for f in failures), failures

    # The winning rotated token itself is now unusable: family was revoked
    # the moment a losing caller replayed the consumed token.
    from app.tokens import rotate_refresh_token

    new_rt = successes[0].refresh_token
    try:
        rotate_refresh_token(new_rt, store, settings)
        raise AssertionError("rotated token must not survive a detected replay")
    except Exception as exc:
        assert getattr(exc, "code", None) is AuthErrorCode.TOKEN_REPLAYED

    # No live refresh record and no active session remain: stolen-token
    # reaction must not leave behind any new valid session.
    assert store.is_family_compromised(
        store.get_refresh_token(__import__("app.tokens", fromlist=["hash_refresh_token"]).hash_refresh_token(pair.refresh_token)).family_id
    )
    assert store.get_session(session.id).revoked is True

    texts = [r.getMessage() for r in audit_records.records]
    assert any("refresh_replay_detected" in t for t in texts)
    print("\n[decision basis]", [t for t in texts if "replay" in t][:2])


def test_replay_of_old_generation_kills_even_newest_token(store, settings):
    """Stolen old token + attacker replay revokes the legitimate chain too."""
    from app.errors import AuthErrorCode
    from app.tokens import rotate_refresh_token

    user = store.get_user_by_username("bob")
    session = Session(id="s-conc-2", user_id=user.id, created_at=0, last_rotated_at=0)
    store.add_session(session)
    pair = issue_token_pair(store, user, session, settings)

    legit = rotate_refresh_token(pair.refresh_token, store, settings)   # gen1
    legit2 = rotate_refresh_token(legit.refresh_token, store, settings)  # gen2

    # Attacker replays gen0.
    try:
        rotate_refresh_token(pair.refresh_token, store, settings)
        raise AssertionError("replay should fail")
    except Exception as exc:
        assert exc.code is AuthErrorCode.TOKEN_REPLAYED

    # Legitimate gen2 (never directly replayed) must now be rejected too.
    try:
        rotate_refresh_token(legit2.refresh_token, store, settings)
        raise AssertionError("family should be revoked")
    except Exception as exc:
        assert exc.code is AuthErrorCode.TOKEN_REPLAYED


def test_revoked_session_rejects_existing_access_token_immediately(
    client, store, helper,
):
    from app.errors import AuthErrorCode

    at, _, _ = helper.login(client, "alice", "alice-pass")
    assert client.get("/auth/me", headers=helper.auth_header(at)).status_code == 200

    # Admin revokes all of alice's sessions.
    admin_at, _, _ = helper.login(client, "admin", "admin-pass-123")
    r = client.post(
        "/auth/users/u-alice/revoke", headers=helper.auth_header(admin_at)
    )
    assert r.status_code == 200

    r = client.get("/auth/me", headers=helper.auth_header(at))
    assert r.status_code == 401
    assert r.json()["error"]["code"] == AuthErrorCode.SESSION_REVOKED.value


def test_non_admin_cannot_revoke(client, helper):
    at, _, _ = helper.login(client, "alice", "alice-pass")
    r = client.post("/auth/users/u-bob/revoke", headers=helper.auth_header(at))
    assert r.status_code == 403
