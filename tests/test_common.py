import base64
import json

from rlsgate.rules._common import (
    classify_table, has_ownership, is_placeholder, jwt_role, secret_name,
)


def _jwt(role):
    def b(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b({'alg':'HS256'})}.{b({'role':role})}.sig"


def test_jwt_role():
    assert jwt_role(_jwt("service_role")) == "service_role"
    assert jwt_role(_jwt("anon")) == "anon"
    assert jwt_role("not-a-jwt") is None


def test_is_placeholder():
    assert is_placeholder("your-key-here")
    assert is_placeholder("xxxxxxx")
    assert is_placeholder("<changeme>")
    assert is_placeholder("")
    assert not is_placeholder("sb_secret_8f3a9c2b7e1d4f6a0c5b8e2d")


def test_classify_table():
    assert classify_table("widgets", ["id", "email"]) == "sensitive"
    assert classify_table("pa_profiles", ["id", "username", "bio"]) == "identity"
    assert classify_table("profiles", ["id"]) == "identity"
    assert classify_table("orders_items", ["id", "user_id"]) == "owned"
    assert classify_table("badges", ["slug", "name", "icon"]) == ""
    assert classify_table("colors", ["id", "hex"]) == ""


def test_has_ownership():
    assert has_ownership("auth.uid() = user_id")
    assert has_ownership("user_id = auth.uid()")
    assert not has_ownership("auth.role() = 'authenticated'")
    assert not has_ownership("true")


def test_secret_name():
    assert secret_name("SUPABASE_SERVICE_ROLE_KEY")
    assert secret_name("STRIPE_SECRET_KEY")
    assert secret_name("DATABASE_URL")
    assert not secret_name("SUPABASE_URL")
    assert not secret_name("NEXT_PUBLIC_SUPABASE_ANON_KEY")
