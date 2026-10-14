"""AWS CLI SSO 프로필에서 임시 역할 자격증명을 얻는다.

- `aws sso login --use-device-code` 가 남긴 토큰 캐시(~/.aws/sso/cache)를 boto3의
  SSO credential provider가 읽어 sso:GetRoleCredentials 로 역할 자격증명을 받는다.
- boto3 Session과 자격증명 객체를 재사용하므로, 유효한 동안에는 재호출하지 않고
  만료가 가까워지면 botocore가 자동으로 갱신한다.
- SSO 토큰이 없거나 만료되면 LoginRequired 를 던져 재로그인 명령을 안내한다.
- SSO accessToken 자체는 이 모듈 밖으로 나가지 않는다.
"""

import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional

import boto3
from botocore.credentials import ReadOnlyCredentials
from botocore.exceptions import (
    NoCredentialsError,
    ProfileNotFound,
    SSOTokenLoadError,
    TokenRetrievalError,
    UnauthorizedSSOTokenError,
)

_LOGIN_ERRORS = (
    SSOTokenLoadError,
    UnauthorizedSSOTokenError,
    TokenRetrievalError,
    NoCredentialsError,
)


def login_command(profile: Optional[str]) -> str:
    return f"aws sso login --profile {profile or '<profile>'} --use-device-code --no-browser"


class CredentialError(Exception):
    """설정 오류. 재로그인으로 해결되지 않는다."""


class LoginRequired(Exception):
    """SSO 세션이 없거나 만료되었다. Device Code 재로그인이 필요하다."""

    def __init__(self, profile: Optional[str], reason: str):
        self.command = login_command(profile)
        super().__init__(f"{reason} 재로그인: {self.command}")


@dataclass(frozen=True)
class ResolvedCredentials:
    credentials: ReadOnlyCredentials
    expires_at: Optional[datetime]


@dataclass(frozen=True)
class ProfileInfo:
    profile: Optional[str]
    sso_region: Optional[str]
    sso_session: Optional[str]
    account_id: Optional[str]
    role_name: Optional[str]


def mask_access_key_id(access_key_id: str) -> str:
    return f"{access_key_id[:4]}…{access_key_id[-4:]}"


class SsoCredentialSource:
    def __init__(
        self,
        profile: Optional[str],
        session_factory: Callable[..., boto3.Session] = boto3.Session,
    ):
        self.profile = profile
        self._session_factory = session_factory
        self._session: Optional[boto3.Session] = None
        self._lock = threading.Lock()

    def _get_session(self) -> boto3.Session:
        if not self.profile:
            raise CredentialError("AWS_PROFILE 환경변수가 설정되지 않았습니다.")
        if self._session is None:
            try:
                self._session = self._session_factory(profile_name=self.profile)
            except ProfileNotFound as exc:
                raise CredentialError(f"프로필을 찾을 수 없습니다: {self.profile}") from exc
        return self._session

    def profile_info(self) -> ProfileInfo:
        """~/.aws/config 의 SSO 설정을 읽는다. 네트워크 호출 없음."""
        with self._lock:
            try:
                botocore_session = self._get_session()._session
            except CredentialError:
                return ProfileInfo(self.profile, None, None, None, None)
        config = botocore_session.get_scoped_config()
        sso_session = config.get("sso_session")
        sso_region = config.get("sso_region")
        if sso_session:
            sessions = botocore_session.full_config.get("sso_sessions", {})
            sso_region = sessions.get(sso_session, {}).get("sso_region", sso_region)
        return ProfileInfo(
            profile=self.profile,
            sso_region=sso_region,
            sso_session=sso_session,
            account_id=config.get("sso_account_id"),
            role_name=config.get("sso_role_name"),
        )

    def get(self) -> ResolvedCredentials:
        with self._lock:
            session = self._get_session()
            try:
                creds = session.get_credentials()
                if creds is None:
                    raise LoginRequired(self.profile, "자격증명을 찾을 수 없습니다.")
                if creds.method != "sso":
                    raise CredentialError(
                        f"SSO 자격증명이 아닙니다(method={creds.method}). "
                        "AWS_ACCESS_KEY_ID 등 다른 자격증명 설정을 제거하세요."
                    )
                frozen = creds.get_frozen_credentials()
            except _LOGIN_ERRORS as exc:
                # 재로그인 후 새 토큰 캐시를 깨끗하게 읽도록 세션을 버린다.
                self._session = None
                raise LoginRequired(
                    self.profile, f"SSO 세션이 없거나 만료되었습니다({type(exc).__name__})."
                ) from exc
            return ResolvedCredentials(frozen, getattr(creds, "_expiry_time", None))
