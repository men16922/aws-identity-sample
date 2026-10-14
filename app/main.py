"""SigV4 브라우저 직접 호출 PoC 서버.

- 이 서버는 DescribeInstances 요청을 서명만 하고 AWS로 보내지 않는다.
- 서명된 요청은 브라우저가 AWS EC2 API로 직접 보낸다.
- Authorization, X-Amz-Security-Token, 서명된 요청 전체는 로그에 남기지 않는다.
"""

import logging
import os
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .credentials import (
    CredentialError,
    LoginRequired,
    SsoCredentialSource,
    login_command,
    mask_access_key_id,
)
from .signer import EC2_ENDPOINT, EC2_REGION, sign_describe_instances

logger = logging.getLogger("sigv4poc")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
CLIENT_HEADER = "X-Requested-With"
CLIENT_HEADER_VALUE = "sigv4-poc"
MAX_TRACKED = 200
BROWSER_RESULT_NOTE = (
    "브라우저가 전달한 값입니다. 서버가 AWS에서 직접 확인한 결과가 아닙니다."
)

CSP = (
    "default-src 'none'; "
    "script-src 'self'; style-src 'self'; img-src 'self'; "
    f"connect-src 'self' {EC2_ENDPOINT.rstrip('/')}; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


class BrowserResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requestId: str = Field(max_length=64)
    status: int = Field(ge=0, le=599, description="0 = fetch 자체 실패(CORS/네트워크)")
    payload: str = Field(max_length=1_000_000)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require_client_header(request: Request) -> None:
    # 다른 origin의 페이지는 preflight 없이 이 헤더를 붙일 수 없고,
    # 이 서버는 CORS를 허용하지 않으므로 교차 출처 POST가 차단된다.
    if request.headers.get(CLIENT_HEADER) != CLIENT_HEADER_VALUE:
        raise HTTPException(status_code=403, detail="missing client header")


def create_app(
    credential_source: Optional[SsoCredentialSource] = None,
    allowed_hosts: Optional[list[str]] = None,
) -> FastAPI:
    source = credential_source or SsoCredentialSource(os.environ.get("AWS_PROFILE"))
    if allowed_hosts is None:
        allowed_hosts = [
            h.strip()
            for h in os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
            if h.strip()
        ]

    # requestId -> 발급 시각. 서명 값은 보관하지 않는다.
    issued: "OrderedDict[str, str]" = OrderedDict()
    results: "OrderedDict[str, dict]" = OrderedDict()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def credential_error_response(exc: Exception) -> JSONResponse:
        if isinstance(exc, LoginRequired):
            return JSONResponse(
                status_code=401,
                content={"error": "login_required", "message": str(exc), "loginCommand": exc.command},
            )
        return JSONResponse(status_code=500, content={"error": "config_error", "message": str(exc)})

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/status")
    def status():
        info = source.profile_info()
        body = {
            "profile": info.profile,
            "ssoSession": info.sso_session,
            "ssoRegion": info.sso_region,
            "accountId": info.account_id,
            "roleName": info.role_name,
            "ec2Region": EC2_REGION,
            "endpoint": EC2_ENDPOINT,
            "loginCommand": login_command(info.profile),
        }
        try:
            resolved = source.get()
        except (LoginRequired, CredentialError) as exc:
            body.update(credentials="unavailable", message=str(exc))
            return body
        body.update(
            credentials="valid",
            accessKeyId=mask_access_key_id(resolved.credentials.access_key),
            expiresAt=resolved.expires_at.isoformat() if resolved.expires_at else None,
        )
        return body

    @app.post("/api/prepare")
    async def prepare(request: Request):
        _require_client_header(request)
        # 요청은 DescribeInstances로 고정이다. 어떤 입력도 받지 않는다.
        if request.query_params or (await request.body()).strip() not in (b"", b"{}"):
            raise HTTPException(status_code=400, detail="this endpoint accepts no parameters")
        try:
            resolved = source.get()
        except (LoginRequired, CredentialError) as exc:
            logger.warning("prepare failed: %s", type(exc).__name__)
            return credential_error_response(exc)

        request_id = str(uuid.uuid4())
        signed = sign_describe_instances(resolved.credentials)
        issued[request_id] = _now()
        while len(issued) > MAX_TRACKED:
            issued.popitem(last=False)
        logger.info("prepared requestId=%s", request_id)
        return JSONResponse(
            content={"requestId": request_id, "request": signed},
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    @app.post("/api/result")
    def result(item: BrowserResult, request: Request):
        _require_client_header(request)
        if item.requestId not in issued:
            raise HTTPException(status_code=404, detail="unknown requestId")
        if item.requestId in results:
            raise HTTPException(status_code=409, detail="result already reported")
        results[item.requestId] = {
            "requestId": item.requestId,
            "status": item.status,
            "payload": item.payload,
            "issuedAt": issued[item.requestId],
            "receivedAt": _now(),
            "source": "browser",
            "note": BROWSER_RESULT_NOTE,
        }
        while len(results) > MAX_TRACKED:
            results.popitem(last=False)
        logger.info("browser-reported result requestId=%s status=%s", item.requestId, item.status)
        return {"stored": True, "source": "browser", "note": BROWSER_RESULT_NOTE}

    @app.get("/api/results")
    def list_results():
        return {"note": BROWSER_RESULT_NOTE, "results": list(reversed(results.values()))}

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


app = create_app()
