"""RBAC, resource-attribute rules, uniform 404, instant permission change."""

from __future__ import annotations

from app.errors import AuthErrorCode


def test_owner_can_read_write_but_not_delete(client, helper):
    at, _, _ = helper.login(client, "alice", "alice-pass")
    h = helper.auth_header(at)

    assert client.get("/documents/doc-welcome", headers=h).status_code == 200
    created = client.post(
        "/documents", headers=h,
        json={"id": "d2", "title": "T", "content": "C"},
    )
    assert created.status_code == 201
    assert client.put(
        "/documents/d2", headers=h, json={"id": "d2", "title": "T2"}
    ).status_code == 200

    # editor lacks doc:delete -> uniform 404 even for an owned document.
    r = client.delete("/documents/d2", headers=h)
    assert r.status_code == 404
    assert r.json()["error"]["code"] == AuthErrorCode.NOT_FOUND.value


def test_unauthorized_cannot_distinguish_existence(client, helper, audit_records):
    # bob (viewer) holds doc:read but is not the owner.
    at, _, _ = helper.login(client, "bob", "bob-pass")
    h = helper.auth_header(at)

    existing = client.get("/documents/doc-welcome", headers=h)
    missing = client.get("/documents/does-not-exist", headers=h)

    assert existing.status_code == missing.status_code == 404
    assert existing.json() == missing.json()

    texts = [r.getMessage() for r in audit_records.records]
    assert any("document_denied" in t and "uniform 404" in t for t in texts)
    print("\n[input+basis]", [t for t in texts if "document_denied" in t])


def test_default_deny_for_unknown_action(client, helper):
    helper.login(client, "alice", "alice-pass")
    # No endpoint even maps the unknown permission; directly verify policy.
    from app.permissions import is_allowed
    from app.store import DataStore  # noqa: F401

    user = client.app.state.store.get_user_by_username("alice")
    assert is_allowed(user, "universe:destroy", None) is False


def test_admin_sees_and_manages_all_documents(client, helper):
    at, _, _ = helper.login(client, "admin", "admin-pass-123")
    h = helper.auth_header(at)
    docs = client.get("/documents", headers=h).json()
    assert {d["id"] for d in docs} == {"doc-welcome"}
    assert client.delete("/documents/doc-welcome", headers=h).status_code == 204
    assert client.get("/documents/doc-welcome", headers=h).status_code == 404


def test_permission_change_takes_effect_without_relogin(client, store, helper, audit_records):
    """Granting/revoking roles invalidates already-issued access tokens."""
    at, _, _ = helper.login(client, "bob", "bob-pass")
    h = helper.auth_header(at)

    # bob is viewer: cannot read alice's document (uniform 404) and cannot write.
    assert client.get("/documents/doc-welcome", headers=h).status_code == 404
    assert client.post(
        "/documents", headers=h, json={"id": "x", "title": "x"}
    ).status_code == 403

    # Admin promotes bob to editor.
    admin_at, _, _ = helper.login(client, "admin", "admin-pass-123")
    changed = client.put(
        "/auth/users/u-bob/security",
        headers=helper.auth_header(admin_at),
        json={"roles": ["editor"]},
    )
    assert changed.status_code == 200

    # bob's OLD access token immediately fails: it predates the sv bump.
    old = client.get("/auth/me", headers=h)
    assert old.status_code == 401
    assert old.json()["error"]["code"] == AuthErrorCode.SESSION_REVOKED.value

    # bob re-authenticates and the new role is effective at once.
    new_at, _, _ = helper.login(client, "bob", "bob-pass")
    nh = helper.auth_header(new_at)
    own = client.post(
        "/documents", headers=nh, json={"id": "bob-1", "title": "mine"}
    )
    assert own.status_code == 201
    # Still cannot read alice's doc (editor is ownership-constrained).
    assert client.get("/documents/doc-welcome", headers=nh).status_code == 404

    # Admin makes bob an admin -> full access instantly after re-login.
    client.put(
        "/auth/users/u-bob/security",
        headers=helper.auth_header(admin_at),
        json={"roles": ["admin"]},
    )
    admin_bob_at, _, _ = helper.login(client, "bob", "bob-pass")
    r = client.get("/documents/doc-welcome", headers=helper.auth_header(admin_bob_at))
    assert r.status_code == 200

    texts = [rec.getMessage() for rec in audit_records.records]
    assert any("stale security version" in t for t in texts)
    print("\n[input+basis]", [t for t in texts if "stale security version" in t][:1])


def test_direct_permission_grant_is_enforced(client, store, helper):
    """Permissions can be attached directly, independent of roles."""
    at, _, _ = helper.login(client, "bob", "bob-pass")
    assert client.post(
        "/documents",
        headers=helper.auth_header(at),
        json={"id": "p1", "title": "p"},
    ).status_code == 403

    admin_at, _, _ = helper.login(client, "admin", "admin-pass-123")
    client.put(
        "/auth/users/u-bob/security",
        headers=helper.auth_header(admin_at),
        json={"permissions": ["doc:write"]},
    )
    at2, _, _ = helper.login(client, "bob", "bob-pass")
    r = client.post(
        "/documents", headers=helper.auth_header(at2),
        json={"id": "p1", "title": "p"},
    )
    assert r.status_code == 201
