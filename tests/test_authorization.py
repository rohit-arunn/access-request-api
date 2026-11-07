"""Authorization tests: roles (RBAC), ownership (object-level), and privilege escalation."""

from app.permissions import ROLE_PERMISSIONS, Permission, Role

NEW_REQUEST = {"resource": "prod-db:read", "justification": "Investigating a production incident."}


def _create(client, headers, payload=None):
    resp = client.post("/requests", headers=headers, json=payload or NEW_REQUEST)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ---------- the permissions table itself ----------

def test_permissions_table_matches_documentation():
    assert ROLE_PERMISSIONS[Role.EMPLOYEE] == {Permission.REQUEST_CREATE, Permission.REQUEST_READ_OWN}
    assert ROLE_PERMISSIONS[Role.APPROVER] == {
        Permission.REQUEST_CREATE, Permission.REQUEST_READ_OWN,
        Permission.REQUEST_READ_ALL, Permission.REQUEST_DECIDE,
    }
    assert ROLE_PERMISSIONS[Role.ADMIN] == set(Permission)


# ---------- happy paths ----------

def test_employee_creates_and_reads_own_request(client, make_user, login):
    make_user("alice@example.test")
    headers = login("alice@example.test")
    request_id = _create(client, headers)
    resp = client.get(f"/requests/{request_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending"


def test_requester_id_comes_from_the_token(client, make_user, login):
    alice_id = make_user("alice@example.test")
    headers = login("alice@example.test")
    request_id = _create(client, headers)
    assert client.get(f"/requests/{request_id}", headers=headers).json()["requester_id"] == alice_id


def test_approver_can_approve_someone_elses_request(client, make_user, login):
    make_user("alice@example.test")
    carol_id = make_user("carol@example.test", "approver")
    request_id = _create(client, login("alice@example.test"))
    resp = client.post(
        f"/requests/{request_id}/decision",
        headers=login("carol@example.test"),
        json={"decision": "approve", "note": "ok"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "approved"
    assert resp.json()["decided_by"] == carol_id


def test_owner_can_edit_and_cancel_pending_request(client, make_user, login):
    make_user("alice@example.test")
    headers = login("alice@example.test")
    request_id = _create(client, headers)
    edited = client.patch(f"/requests/{request_id}", headers=headers, json={"justification": "A clearer reason, please."})
    assert edited.status_code == 200
    assert client.post(f"/requests/{request_id}/cancel", headers=headers).json()["status"] == "cancelled"


# ---------- role-based access control ----------

def test_employee_cannot_list_all_requests(client, make_user, login):
    make_user("alice@example.test")
    assert client.get("/requests?scope=all", headers=login("alice@example.test")).status_code == 403


def test_employee_cannot_approve(client, make_user, login):
    make_user("alice@example.test")
    make_user("bob@example.test")
    request_id = _create(client, login("bob@example.test"))
    resp = client.post(
        f"/requests/{request_id}/decision", headers=login("alice@example.test"), json={"decision": "approve"}
    )
    assert resp.status_code == 403
    assert client.get(f"/requests/{request_id}", headers=login("bob@example.test")).json()["status"] == "pending"


def test_employee_cannot_use_admin_endpoints(client, make_user, login):
    alice_id = make_user("alice@example.test")
    make_user("bob@example.test")
    headers = login("alice@example.test")
    assert client.put("/admin/users/2/role", headers=headers, json={"role": "admin"}).status_code == 403
    assert client.get("/admin/audit", headers=headers).status_code == 403
    assert alice_id == 1  # sanity: the ids used above are what we think they are


def test_approver_cannot_use_admin_endpoints(client, make_user, login):
    make_user("carol@example.test", "approver")
    make_user("bob@example.test")
    headers = login("carol@example.test")
    assert client.put("/admin/users/2/role", headers=headers, json={"role": "admin"}).status_code == 403
    assert client.get("/admin/audit", headers=headers).status_code == 403


def test_admin_can_change_roles_and_read_audit_log(client, make_user, login):
    make_user("dave@example.test", "admin")
    bob_id = make_user("bob@example.test")
    headers = login("dave@example.test")
    resp = client.put(f"/admin/users/{bob_id}/role", headers=headers, json={"role": "approver"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "approver"
    actions = [row["action"] for row in client.get("/admin/audit", headers=headers).json()]
    assert "user.role_change" in actions


def test_admin_cannot_change_own_role(client, make_user, login):
    dave_id = make_user("dave@example.test", "admin")
    resp = client.put(f"/admin/users/{dave_id}/role", headers=login("dave@example.test"), json={"role": "employee"})
    assert resp.status_code == 403


def test_role_comes_from_the_database_not_the_token(client, make_user, login):
    make_user("dave@example.test", "admin")
    bob_id = make_user("bob@example.test")
    bob = login("bob@example.test")  # token issued while bob is an employee
    assert client.get("/requests?scope=all", headers=bob).status_code == 403

    client.put(f"/admin/users/{bob_id}/role", headers=login("dave@example.test"), json={"role": "approver"})
    assert client.get("/requests?scope=all", headers=bob).status_code == 200  # same token, new power

    client.put(f"/admin/users/{bob_id}/role", headers=login("dave@example.test"), json={"role": "employee"})
    assert client.get("/requests?scope=all", headers=bob).status_code == 403  # revoked at once


# ---------- object-level authorization (IDOR / BOLA) ----------

def test_user_cannot_read_another_users_request(client, make_user, login):
    make_user("alice@example.test")
    make_user("bob@example.test")
    request_id = _create(client, login("alice@example.test"))
    assert client.get(f"/requests/{request_id}", headers=login("bob@example.test")).status_code == 404


def test_user_cannot_modify_another_users_request(client, make_user, login):
    make_user("alice@example.test")
    make_user("bob@example.test")
    alice, bob = login("alice@example.test"), login("bob@example.test")
    request_id = _create(client, alice)

    edit = client.patch(f"/requests/{request_id}", headers=bob, json={"justification": "Bob was here, overwriting."})
    cancel = client.post(f"/requests/{request_id}/cancel", headers=bob)
    assert edit.status_code == 404
    assert cancel.status_code == 404

    unchanged = client.get(f"/requests/{request_id}", headers=alice).json()
    assert unchanged["status"] == "pending"
    assert unchanged["justification"] == NEW_REQUEST["justification"]


def test_missing_and_foreign_requests_look_the_same(client, make_user, login):
    """A 404 for both means an attacker cannot learn which IDs exist."""
    make_user("alice@example.test")
    make_user("bob@example.test")
    request_id = _create(client, login("alice@example.test"))
    bob = login("bob@example.test")
    foreign = client.get(f"/requests/{request_id}", headers=bob)
    missing = client.get("/requests/99999", headers=bob)
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()


def test_default_listing_only_contains_own_requests(client, make_user, login):
    make_user("alice@example.test")
    make_user("bob@example.test")
    alice, bob = login("alice@example.test"), login("bob@example.test")
    _create(client, alice)
    bobs_id = _create(client, bob)
    listing = client.get("/requests", headers=bob).json()
    assert [row["id"] for row in listing] == [bobs_id]


def test_approver_can_read_but_not_edit_someone_elses_request(client, make_user, login):
    make_user("alice@example.test")
    make_user("carol@example.test", "approver")
    request_id = _create(client, login("alice@example.test"))
    carol = login("carol@example.test")
    assert client.get(f"/requests/{request_id}", headers=carol).status_code == 200
    resp = client.patch(f"/requests/{request_id}", headers=carol, json={"justification": "Rewriting alice's words."})
    assert resp.status_code == 403


def test_approver_cannot_approve_own_request(client, make_user, login):
    make_user("carol@example.test", "approver")
    carol = login("carol@example.test")
    request_id = _create(client, carol)
    resp = client.post(f"/requests/{request_id}/decision", headers=carol, json={"decision": "approve"})
    assert resp.status_code == 403
    assert client.get(f"/requests/{request_id}", headers=carol).json()["status"] == "pending"


def test_a_request_cannot_be_decided_twice(client, make_user, login):
    make_user("alice@example.test")
    make_user("carol@example.test", "approver")
    make_user("dave@example.test", "admin")
    request_id = _create(client, login("alice@example.test"))
    first = client.post(f"/requests/{request_id}/decision", headers=login("carol@example.test"), json={"decision": "reject"})
    second = client.post(f"/requests/{request_id}/decision", headers=login("dave@example.test"), json={"decision": "approve"})
    assert first.status_code == 200
    assert second.status_code == 409
    assert client.get(f"/requests/{request_id}", headers=login("carol@example.test")).json()["status"] == "rejected"


# ---------- privilege escalation through payloads (mass assignment) ----------

def test_user_cannot_set_status_through_update_payload(client, make_user, login):
    make_user("alice@example.test")
    headers = login("alice@example.test")
    request_id = _create(client, headers)
    resp = client.patch(
        f"/requests/{request_id}",
        headers=headers,
        json={"justification": "Please just approve this one.", "status": "approved"},
    )
    assert resp.status_code == 422
    assert client.get(f"/requests/{request_id}", headers=headers).json()["status"] == "pending"


def test_user_cannot_set_sensitive_fields_when_creating(client, make_user, login):
    make_user("alice@example.test")
    make_user("bob@example.test")
    headers = login("alice@example.test")
    for extra in ({"status": "approved"}, {"requester_id": 2}, {"decided_by": 1}):
        resp = client.post("/requests", headers=headers, json={**NEW_REQUEST, **extra})
        assert resp.status_code == 422, extra


def test_user_cannot_self_assign_a_privileged_role(client, make_user, login):
    from app import db

    alice_id = make_user("alice@example.test")
    headers = login("alice@example.test")

    via_admin_endpoint = client.put(f"/admin/users/{alice_id}/role", headers=headers, json={"role": "admin"})
    assert via_admin_endpoint.status_code == 403

    conn = db.connect()
    try:
        role = conn.execute("SELECT role FROM users WHERE id = ?", (alice_id,)).fetchone()[0]
    finally:
        conn.close()
    assert role == "employee"
    assert client.get("/auth/me", headers=headers).json()["role"] == "employee"


def test_invalid_input_is_rejected(client, make_user, login):
    make_user("alice@example.test")
    headers = login("alice@example.test")
    bad_payloads = [
        {"resource": "ab", "justification": "Too short a resource name."},
        {"resource": "x" * 81, "justification": "Resource name is far too long."},
        {"resource": "bad;DROP TABLE users", "justification": "Illegal characters in resource."},
        {"resource": "prod-db:read", "justification": "short"},
        {"resource": "prod-db:read", "justification": "x" * 501},
    ]
    for payload in bad_payloads:
        assert client.post("/requests", headers=headers, json=payload).status_code == 422, payload
    assert client.get("/requests/not-a-number", headers=headers).status_code == 422
