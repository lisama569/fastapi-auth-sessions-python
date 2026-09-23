"""Role/permission based and resource-attribute based access decisions.

Rules are evaluated in this order with a **deny by default** posture:

1. Direct user permissions grant actions.
2. Role -> permission mappings grant actions.
3. A permission may carry a resource constraint (e.g. ``"doc:read"`` only
   when the resource is owned by, or shared with, the principal).

Anything not explicitly granted is denied.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from app.logging_utils import audit
from app.models import User

# A resource constraint receives (user, resource) and returns whether the
# attribute-level condition holds (ownership/tenancy/etc.).
Constraint = Callable[[User, object], bool]


@dataclass(frozen=True)
class PermissionRule:
    action: str
    constraint: Constraint | None = None  # None = global, no resource check


# Default role catalogue; applications can extend/replace it.
DEFAULT_ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {
        "doc:read",
        "doc:write",
        "doc:delete",
        "user:manage",
    },
    "editor": {"doc:read", "doc:write"},
    "viewer": {"doc:read"},
}


def effective_permissions(user: User,
                          role_map: dict[str, set[str]] | None = None) -> set[str]:
    role_map = DEFAULT_ROLE_PERMISSIONS if role_map is None else role_map
    granted: set[str] = set(user.permissions)
    for role in user.roles:
        granted.update(role_map.get(role, set()))
    return granted


def has_action(user: User, action: str,
               role_map: dict[str, set[str]] | None = None) -> bool:
    return action in effective_permissions(user, role_map)


def is_allowed(
    user: User,
    action: str,
    resource: object | None = None,
    *,
    constraints: dict[str, Constraint] | None = None,
    role_map: dict[str, set[str]] | None = None,
    source: str = "-",
    audit_log: bool = True,
) -> bool:
    """Decide whether *user* may perform *action* on *resource*.

    Ownership/tenancy constraints live in ``constraints`` keyed by action.
    A globally granted action needs no constraint; an action whose rule
    requires a constraint fails when no resource (or constraint) is given.
    """
    role_map = DEFAULT_ROLE_PERMISSIONS if role_map is None else role_map
    constraints = constraints or {}
    granted = action in effective_permissions(user, role_map)

    if not granted:
        if audit_log:
            audit(
                "accessz_denied",
                inputs={"user_id": user.id, "action": action, "source": source},
                decision="deny",
                basis="default-deny: action not in effective permissions",
            )
        return False

    constraint = constraints.get(action)
    if constraint is None:
        if audit_log:
            audit(
                "accessz_allowed",
                inputs={"user_id": user.id, "action": action, "source": source},
                decision="allow",
                basis="action granted globally by role/user permission",
            )
        return True

    if resource is None:
        if audit_log:
            audit(
                "accessz_denied",
                inputs={"user_id": user.id, "action": action, "source": source},
                decision="deny",
                basis="resource-scoped action without a resource",
            )
        return False

    ok = bool(constraint(user, resource))
    if audit_log:
        audit(
            "accessz_allowed" if ok else "accessz_denied",
            inputs={"user_id": user.id, "action": action, "source": source},
            decision="allow" if ok else "deny",
            basis="resource attribute constraint " + ("passed" if ok else "failed"),
        )
    return ok


def require_any_role(user: User, roles: Iterable[str]) -> bool:
    return bool(user.roles.intersection(roles))
