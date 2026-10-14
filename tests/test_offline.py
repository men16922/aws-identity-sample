"""AWS 없이 실행하는 오프라인 검증.

- 고정 요청만 서명하는지(임의 요청 서명 방지)
- SecretAccessKey / SSO accessToken 이 응답·로그에 나가지 않는지
- Host/Content-Length 를 빼고 전달해도 서명이 재현되는지(독립 SigV4 구현으로 확인)
- boto3 SSO credential provider 경로(토큰 캐시 → GetRoleCredentials)와 만료 처리

GetRoleCredentials 응답은 botocore before-send 이벤트로 가짜 응답을 돌려준다. 네트워크 호출 없음.
"""

import hashlib
import hmac
import inspect
import json
import logging
import re
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import boto3
import botocore.credentials
import botocore.tokens
import pytest
from botocore.awsrequest import AWSResponse
from botocore.credentials import ReadOnlyCredentials
from fastapi.testclient import TestClient

from app.__main__ import configure_logging
from app.credentials import LoginRequired, ResolvedCredentials, SsoCredentialSource
from app.main import create_app
from app.signer import DESCRIBE_INSTANCES_BODY, EC2_ENDPOINT, sign_describe_instances

ROOT = Path(__file__).resolve().parent.parent

FAKE_AKID = "ASIAFAKEACCESSKEY123"
FAKE_SECRET = "FAKE/SECRET+ACCESS+KEY+do+not+leak+0123456789"
FAKE_SESSION_TOKEN = "FAKESESSIONTOKEN//expected-in-x-amz-security-token=="
FAKE_SSO_ACCESS_TOKEN = "FAKE-SSO-ACCESS-TOKEN-must-never-reach-browser"

CLIENT_HEADERS = {"X-Requested-With": "sigv4-poc"}


# ---------------------------------------------------------------- helpers


class FakeSource:
    profile = "fake"

    def __init__(self, login_required=False):
        self.login_required = login_required

    def profile_info(self):
        from app.credentials import ProfileInfo

        return ProfileInfo("fake", "us-east-1", "corp", "111122223333", "ReadOnly")

    def get(self):
        if self.login_required:
            raise LoginRequired("fake", "SSO 세션이 없거나 만료되었습니다.")
        return ResolvedCredentials(
            ReadOnlyCredentials(FAKE_AKID, FAKE_SECRET, FAKE_SESSION_TOKEN),
            datetime.now(timezone.utc) + timedelta(hours=1),
        )


def make_client(source):
    return TestClient(create_app(credential_source=source, allowed_hosts=["localhost"]), base_url="http://localhost")


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def verify_sigv4(request: dict, secret: str):
    """botocore를 쓰지 않는 독립 SigV4 검증. 브라우저가 Host를 URL에서 채운다고 가정한다."""
    headers = {k.lower(): v for k, v in request["headers"].items()}
    _, params = headers["authorization"].split(" ", 1)
    parts = dict(p.strip().split("=", 1) for p in params.split(","))
    _akid, date, region, service, _term = parts["Credential"].split("/")
    signed_headers = parts["SignedHeaders"].split(";")
    url = urlsplit(request["url"])

    def value(name):
        return url.hostname if name == "host" else " ".join(headers[name].split())

    canonical_request = "\n".join(
        [
            request["method"],
            url.path or "/",
            url.query,
            "".join(f"{n}:{value(n)}\n" for n in signed_headers),
            ";".join(signed_headers),
            hashlib.sha256(request["body"].encode("utf-8")).hexdigest(),
        ]
    )
    scope = f"{date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", headers["x-amz-date"], scope, hashlib.sha256(canonical_request.encode()).hexdigest()]
    )
    key = _hmac(("AWS4" + secret).encode(), date)
    for part in (region, service, "aws4_request"):
        key = _hmac(key, part)
    expected = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    return parts["Signature"] == expected, signed_headers, (region, service)


# ---------------------------------------------------------------- 서명 결과


def test_prepare_returns_fixed_signed_request():
    res = make_client(FakeSource()).post("/api/prepare", headers=CLIENT_HEADERS)
    assert res.status_code == 200
    assert res.headers["cache-control"] == "no-store"
    data = res.json()
    assert set(data) == {"requestId", "request"}
    req = data["request"]
    assert set(req) == {"url", "method", "headers", "body"}
    assert req["url"] == "https://ec2.ap-northeast-2.amazonaws.com/"
    assert req["method"] == "POST"
    assert req["body"] == "Action=DescribeInstances&Version=2016-11-15&MaxResults=5"
    lower = {k.lower() for k in req["headers"]}
    assert "host" not in lower and "content-length" not in lower
    assert req["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    # X-Amz-Security-Token 은 AWS 요청에 필요한 서명 헤더로 전달된다.
    assert req["headers"]["X-Amz-Security-Token"] == FAKE_SESSION_TOKEN


def test_signature_reproducible_without_host_and_content_length():
    req = make_client(FakeSource()).post("/api/prepare", headers=CLIENT_HEADERS).json()["request"]
    ok, signed_headers, scope = verify_sigv4(req, FAKE_SECRET)
    assert ok
    assert scope == ("ap-northeast-2", "ec2")
    assert "host" in signed_headers
    assert "content-length" not in signed_headers
    assert "x-amz-security-token" in signed_headers
    delivered = {k.lower() for k in req["headers"]}
    assert set(signed_headers) - {"host"} <= delivered


def test_modified_body_breaks_signature():
    req = make_client(FakeSource()).post("/api/prepare", headers=CLIENT_HEADERS).json()["request"]
    tampered = dict(req, body=req["body"].replace("MaxResults=5", "MaxResults=6"))
    assert verify_sigv4(tampered, FAKE_SECRET)[0] is False
    reencoded = dict(req, body=req["body"].replace("=", "%3D", 1))
    assert verify_sigv4(reencoded, FAKE_SECRET)[0] is False


# ---------------------------------------------------------------- 누출 방지


def test_secret_never_in_prepare_or_status_response():
    client = make_client(FakeSource())
    for res in (client.post("/api/prepare", headers=CLIENT_HEADERS), client.get("/api/status")):
        text = res.text
        assert FAKE_SECRET not in text
        assert json.dumps(FAKE_SECRET)[1:-1] not in text
        assert "SecretAccessKey" not in text and "secret" not in text.lower()
        assert "accessToken" not in text
    status = client.get("/api/status").json()
    assert FAKE_SESSION_TOKEN not in json.dumps(status)
    assert FAKE_AKID not in json.dumps(status)  # 마스킹됨
    assert status["accessKeyId"] == "ASIA…Y123"


def test_logs_do_not_contain_token_signature_or_secret(caplog):
    configure_logging()
    caplog.set_level(logging.DEBUG)
    client = make_client(FakeSource())
    data = client.post("/api/prepare", headers=CLIENT_HEADERS).json()
    client.post(
        "/api/result",
        headers=CLIENT_HEADERS,
        json={"requestId": data["requestId"], "status": 200, "payload": "<x/>"},
    )
    signature = data["request"]["headers"]["Authorization"].rsplit("Signature=", 1)[1]
    logs = caplog.text
    assert data["requestId"] in logs  # 로그 수집 자체는 동작함
    for forbidden in (FAKE_SECRET, FAKE_SESSION_TOKEN, signature, "Authorization", DESCRIBE_INSTANCES_BODY):
        assert forbidden not in logs


# ---------------------------------------------------------------- 임의 요청 서명 방지


def test_signer_accepts_only_credentials():
    assert list(inspect.signature(sign_describe_instances).parameters) == ["credentials"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"json": {"url": "https://evil.example/", "body": "Action=TerminateInstances"}},
        {"json": {"action": "RunInstances"}},
        {"content": b"Action=TerminateInstances&Version=2016-11-15",
         "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
        {"params": {"Action": "TerminateInstances"}},
        {"params": {"url": "https://sts.amazonaws.com/"}},
    ],
)
def test_prepare_rejects_any_input(kwargs):
    headers = {**CLIENT_HEADERS, **kwargs.pop("headers", {})}
    res = make_client(FakeSource()).post("/api/prepare", headers=headers, **kwargs)
    assert res.status_code == 400
    assert "Authorization" not in res.text


def test_prepare_requires_client_header_and_trusted_host():
    client = make_client(FakeSource())
    assert client.post("/api/prepare").status_code == 403
    res = client.post("/api/prepare", headers={**CLIENT_HEADERS, "Host": "attacker.example"})
    assert res.status_code == 400
    assert "Authorization" not in res.text


def test_only_expected_routes_exist():
    app = create_app(credential_source=FakeSource(), allowed_hosts=["localhost"])
    routes = {(m, r.path) for r in app.routes for m in getattr(r, "methods", None) or ()}
    assert {r for r in routes if r[0] == "POST"} == {("POST", "/api/prepare"), ("POST", "/api/result")}


def test_result_requires_issued_id_and_is_marked_browser_reported():
    client = make_client(FakeSource())
    unknown = client.post("/api/result", headers=CLIENT_HEADERS, json={"requestId": "x", "status": 200, "payload": ""})
    assert unknown.status_code == 404
    extra = client.post(
        "/api/result", headers=CLIENT_HEADERS,
        json={"requestId": "x", "status": 200, "payload": "", "url": "https://evil.example/"},
    )
    assert extra.status_code == 422

    rid = client.post("/api/prepare", headers=CLIENT_HEADERS).json()["requestId"]
    ok = client.post("/api/result", headers=CLIENT_HEADERS, json={"requestId": rid, "status": 0, "payload": "fetch failed"})
    assert ok.status_code == 200 and ok.json()["source"] == "browser"
    dup = client.post("/api/result", headers=CLIENT_HEADERS, json={"requestId": rid, "status": 200, "payload": ""})
    assert dup.status_code == 409
    stored = client.get("/api/results").json()["results"][0]
    assert stored["source"] == "browser" and stored["status"] == 0
    assert "브라우저가 전달한 값" in stored["note"]


def test_login_required_returns_device_code_command():
    res = make_client(FakeSource(login_required=True)).post("/api/prepare", headers=CLIENT_HEADERS)
    assert res.status_code == 401
    assert res.json()["loginCommand"] == "aws sso login --profile fake --use-device-code --no-browser"


# ---------------------------------------------------------------- 브라우저 코드 정적 검사


def test_index_csp_limits_connect_targets():
    res = make_client(FakeSource()).get("/")
    assert res.status_code == 200
    assert "connect-src 'self' https://ec2.ap-northeast-2.amazonaws.com;" in res.headers["content-security-policy"]


def test_browser_js_uses_signed_request_verbatim_and_no_storage():
    js = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
    code = re.sub(r"^\s*//.*$", "", js, flags=re.M)
    assert re.search(r'mode:\s*"cors"', code)
    assert re.search(r'credentials:\s*"omit"', code)
    assert re.search(r"headers:\s*request\.headers,", code)
    assert re.search(r"body:\s*request\.body,", code)
    for forbidden in ("localStorage", "sessionStorage", "indexedDB", "console.", "document.cookie"):
        assert forbidden not in code


# ---------------------------------------------------------------- 실제 boto3 SSO provider 경로


class _Raw:
    def __init__(self, data: bytes):
        self._data = data

    def stream(self, **_):
        yield self._data


@pytest.fixture
def sso_env(tmp_path, monkeypatch):
    config = tmp_path / "config"
    config.write_text(
        textwrap.dedent(
            """
            [profile poc]
            sso_session = corp
            sso_account_id = 111122223333
            sso_role_name = ReadOnlyWithIpRestriction
            region = us-west-2

            [sso-session corp]
            sso_start_url = https://d-0000000000.awsapps.com/start
            sso_region = us-east-1
            sso_registration_scopes = sso:account:access
            """
        )
    )
    cache_dir = tmp_path / "sso-cache"
    cache_dir.mkdir()
    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setattr(botocore.tokens.SSOTokenProvider, "_SSO_TOKEN_CACHE_DIR", str(cache_dir))
    monkeypatch.setattr(botocore.credentials.SSOProvider, "_SSO_TOKEN_CACHE_DIR", str(cache_dir))

    calls = []

    def write_token(expires_in: timedelta):
        key = hashlib.sha1(b"corp").hexdigest()
        expires = (datetime.now(timezone.utc) + expires_in).strftime("%Y-%m-%dT%H:%M:%SZ")
        (cache_dir / f"{key}.json").write_text(
            json.dumps({"startUrl": "https://d-0000000000.awsapps.com/start", "region": "us-east-1",
                        "accessToken": FAKE_SSO_ACCESS_TOKEN, "expiresAt": expires})
        )

    def session_factory(**kwargs):
        session = boto3.Session(**kwargs)

        def fake_get_role_credentials(request, **_):
            bearer = request.headers.get("x-amz-sso_bearer_token")
            calls.append({"url": request.url, "bearer": bearer.decode() if isinstance(bearer, bytes) else bearer})
            expiry_ms = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp() * 1000)
            body = json.dumps({"roleCredentials": {
                "accessKeyId": FAKE_AKID, "secretAccessKey": FAKE_SECRET,
                "sessionToken": FAKE_SESSION_TOKEN, "expiration": expiry_ms}}).encode()
            return AWSResponse(request.url, 200, {"Content-Type": "application/json"}, _Raw(body))

        session._session.register("before-send.sso.GetRoleCredentials", fake_get_role_credentials)
        return session

    return write_token, session_factory, calls


def test_real_sso_provider_path_and_reuse(sso_env):
    write_token, factory, calls = sso_env
    write_token(timedelta(hours=8))
    source = SsoCredentialSource("poc", session_factory=factory)

    info = source.profile_info()
    assert info.sso_region == "us-east-1"  # SSO 리전과 EC2 리전(ap-northeast-2)은 별개

    client = make_client(source)
    res = client.post("/api/prepare", headers=CLIENT_HEADERS)
    assert res.status_code == 200
    req = res.json()["request"]
    assert verify_sigv4(req, FAKE_SECRET)[0]
    assert req["url"] == EC2_ENDPOINT  # 프로필 region=us-west-2 이어도 EC2 리전은 고정
    assert FAKE_SECRET not in res.text and FAKE_SSO_ACCESS_TOKEN not in res.text

    assert len(calls) == 1
    assert calls[0]["url"].startswith("https://portal.sso.us-east-1.amazonaws.com/")
    assert calls[0]["bearer"] == FAKE_SSO_ACCESS_TOKEN

    client.post("/api/prepare", headers=CLIENT_HEADERS)
    client.get("/api/status")
    assert len(calls) == 1  # 유효한 역할 자격증명은 재사용


def test_missing_sso_token_requires_login(sso_env):
    _, factory, calls = sso_env
    res = make_client(SsoCredentialSource("poc", session_factory=factory)).post("/api/prepare", headers=CLIENT_HEADERS)
    assert res.status_code == 401
    assert "--use-device-code --no-browser" in res.json()["loginCommand"]
    assert calls == []


def test_expired_sso_token_requires_login_then_recovers(sso_env):
    write_token, factory, calls = sso_env
    write_token(timedelta(hours=-1))
    client = make_client(SsoCredentialSource("poc", session_factory=factory))
    res = client.post("/api/prepare", headers=CLIENT_HEADERS)
    assert res.status_code == 401
    assert res.json()["error"] == "login_required"
    assert calls == []

    write_token(timedelta(hours=8))  # aws sso login 을 다시 한 상황
    assert client.post("/api/prepare", headers=CLIENT_HEADERS).status_code == 200
