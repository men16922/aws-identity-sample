# SigV4 브라우저 직접 호출 PoC

EC2에서 실행하는 백엔드가 IAM Identity Center(SSO) 역할 자격증명으로 **`ec2:DescribeInstances` 요청을 서명만** 하고,
사용자 PC의 브라우저가 그 서명된 요청을 **AWS EC2 API로 직접** 보내는 흐름을 검증하는 최소 샘플입니다.

목적: Permission Set의 `aws:SourceIp` Deny 조건(회사 공인 IP만 허용)을 바꾸지 않고, 허용된 PC 출구 IP에서
AWS 요청이 나가도록 할 수 있는지 확인합니다.

```
 사용자 PC                                   EC2 (TA Bot)
┌──────────────────────┐   SSH -L 8080      ┌───────────────────────────────┐
│ 브라우저              │ ─────────────────▶ │ FastAPI 127.0.0.1:8000         │
│  http://localhost:8080│  UI + 서명 전달만   │  POST /api/prepare  (서명만)   │
│                      │ ◀───────────────── │  POST /api/result   (결과 보관)│
│                      │                    │  boto3 SSO provider            │
│                      │                    │   └ ~/.aws/sso/cache (device code 로그인) │
└─────────┬────────────┘                    └───────────────┬───────────────┘
          │ fetch(mode:"cors", credentials:"omit")          │ sso:GetRoleCredentials
          │ 출발지 IP = PC 인터넷 출구 IP (허용 대상)          │ (portal.sso.<sso_region>)
          ▼                                                 ▼
   https://ec2.ap-northeast-2.amazonaws.com/          IAM Identity Center
```

- SSH 터널은 UI와 서명 전달용입니다. **AWS API 요청은 PC 브라우저에서 AWS로 직접** 나갑니다.
- 백엔드는 DescribeInstances를 호출하지 않습니다. (비교용 `scripts/direct_call.py`는 별도 수동 도구)
- DB, S3, 프록시, 추가 AWS 인프라 없음. 단일 사용자, 계정 하나, 리전 `ap-northeast-2`.

## 검증 상태

| 항목 | 상태 |
|---|---|
| 오프라인 테스트 `pytest` 20건 (아래 [오프라인 검증](#오프라인-검증)) | 이 저장소 작성 시 macOS / Python 3.13.5 / boto3·botocore 1.43.113 / FastAPI 0.143.0 에서 **통과** |
| 서버 기동, `/`, `/static/*`, `/api/status`, 프로필 없음 시 `/api/prepare` 오류 응답 | 로컬에서 curl로 확인 |
| EC2 엔드포인트 CORS | **비인증 curl 요청으로만 확인** (2026-10-14): `OPTIONS` preflight에 `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods: POST`, `Access-Control-Allow-Headers: authorization,content-type,x-amz-date,x-amz-security-token` 응답. 비인증 `POST` 오류 응답에도 `Access-Control-Allow-Origin: *` 포함. 실제 브라우저에서 서명된 요청으로는 **미확인** |
| 실제 SSO Device Code 로그인, EC2에서 GetRoleCredentials | **미검증** |
| 브라우저 → EC2 API 서명 요청 성공(HTTP 200) | **미검증** |
| EC2에서 직접 호출 시 `aws:SourceIp` Deny로 거부 | **미검증** |

실제 AWS 환경에서 아래 [검증 절차](#검증-절차)를 수행해 표를 채우세요.

## 파일 구조

```
app/
  signer.py        고정 DescribeInstances 요청 서명 (botocore AWSRequest + SigV4Auth)
  credentials.py   boto3 SSO credential provider, 세션 재사용, 만료 시 재로그인 안내
  main.py          FastAPI: /, /api/status, /api/prepare, /api/result, /api/results
  __main__.py      python -m app 진입점 (기본 127.0.0.1:8000)
static/            index.html, app.js, style.css (vanilla JS, 동일 origin)
scripts/
  direct_call.py   [비교용] 같은 서명 요청을 EC2에서 직접 전송
tests/
  test_offline.py  AWS 없이 실행하는 검증
```

## 1. SSO 프로필 설정 (EC2)

EC2의 `~/.aws/config` 에 기존 Permission Set을 쓰는 프로필을 둡니다. 예시:

```ini
[profile ta-bot-sso]
sso_session = corp
sso_account_id = 111122223333
sso_role_name = ExistingPermissionSetName
region = ap-northeast-2

[sso-session corp]
sso_start_url = https://d-xxxxxxxxxx.awsapps.com/start
sso_region = us-east-1                 # IAM Identity Center가 있는 리전
sso_registration_scopes = sso:account:access
```

- **SSO 리전(`sso_region`)과 EC2 조회 리전은 별개입니다.** SSO 리전은 토큰/역할 자격증명 발급(`portal.sso.<sso_region>.amazonaws.com`)에만 쓰입니다.
  EC2 조회 리전은 코드에 `ap-northeast-2`로 고정되어 있으며 프로필의 `region` 값과 무관합니다.
- `sso-session` 형식에서는 botocore가 캐시된 refresh token으로 SSO 토큰을 자동 갱신할 수 있습니다.
  레거시 형식(프로필에 `sso_start_url` 직접 기재)도 boto3가 지원하지만 자동 갱신은 없습니다.
- `AWS_ACCESS_KEY_ID` 등 정적 자격증명 환경변수가 있으면 제거하세요. 서버는 자격증명 `method`가 `sso`가 아니면 서명하지 않습니다.

로그인 (EC2에서):

```bash
aws sso login --profile ta-bot-sso --use-device-code --no-browser
```

출력되는 URL과 코드를 PC 브라우저에서 열어 승인합니다. 토큰은 `~/.aws/sso/cache/` 에 저장되고, 서버는 이를 boto3 SSO credential provider로 읽습니다.

> 전제(미검증): Device Code 로그인과 `sso:GetRoleCredentials` 는 Permission Set의 IAM 정책이 아니라 SSO 토큰으로 인가되므로
> EC2 IP에서도 성공해야 이 PoC가 동작합니다. 1단계 검증에서 확인하세요.

## 2. 설치·실행 (EC2)

Python 3.10 이상.

```bash
cd aws-identity-sample
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # AWS_PROFILE 수정
python -m app                 # 127.0.0.1:8000
```

`.env` 를 쓰지 않고 `AWS_PROFILE=ta-bot-sso python -m app` 처럼 실행해도 됩니다.
서버는 루프백(127.0.0.1)에만 바인드하므로 외부에서 직접 접근할 수 없습니다.

## 3. SSH 터널과 접속 (사용자 PC)

```bash
ssh -N -L 8080:127.0.0.1:8000 <user>@<ec2>
```

PC 브라우저에서 **http://localhost:8080** 접속. (`ALLOWED_HOSTS` 기본값은 `localhost,127.0.0.1` 이며 다른 Host 헤더는 400으로 거부됩니다.)

## 동작 방식

### `POST /api/prepare`

- 요청 본문/쿼리를 받지 않습니다. 무엇이든 넘기면 400. 헤더 `X-Requested-With: sigv4-poc` 필수(교차 출처 페이지의 호출 차단).
- 서명 대상은 고정입니다.
  - `POST https://ec2.ap-northeast-2.amazonaws.com/`
  - `Content-Type: application/x-www-form-urlencoded`
  - 본문 `Action=DescribeInstances&Version=2016-11-15&MaxResults=5`
- `botocore.awsrequest.AWSRequest` + `botocore.auth.SigV4Auth(credentials, "ec2", "ap-northeast-2")` 로 Authorization 헤더를 만듭니다.
- 응답 (`Cache-Control: no-store`):

```json
{
  "requestId": "uuid",
  "request": {
    "url": "https://ec2.ap-northeast-2.amazonaws.com/",
    "method": "POST",
    "headers": {
      "Content-Type": "application/x-www-form-urlencoded",
      "X-Amz-Date": "20261014T000000Z",
      "X-Amz-Security-Token": "<세션 토큰>",
      "Authorization": "AWS4-HMAC-SHA256 Credential=ASIA.../20261014/ap-northeast-2/ec2/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, Signature=..."
    },
    "body": "Action=DescribeInstances&Version=2016-11-15&MaxResults=5"
  }
}
```

- **Host와 Content-Length는 전달 헤더에서 제외**합니다. Host는 서명(`SignedHeaders`)에 포함되지만 브라우저가 목적지 URL에 맞춰 설정하며,
  fetch로 지정할 수 없는 헤더입니다. Content-Length는 서명 대상이 아니며 브라우저가 본문으로 계산합니다.

### 브라우저 (`static/app.js`)

- prepare 응답의 URL·메서드·헤더·본문을 **그대로** `fetch` 에 넘깁니다. `mode: "cors"`, `credentials: "omit"`. 본문 재인코딩·헤더 수정 없음.
- HTTP 상태와 EC2 XML 응답을 표시하고 `POST /api/result` 로 `{requestId, status, payload}` 를 전달합니다.
  fetch 자체가 실패하면(CORS/네트워크) `status: 0` 과 오류 문자열을 보냅니다.
- 화면의 요청 요약에서 Authorization, X-Amz-Security-Token 값은 `<redacted>` 로 가립니다.
  console, localStorage, sessionStorage, IndexedDB, 쿠키에 기록하지 않습니다.
- CSP `connect-src 'self' https://ec2.ap-northeast-2.amazonaws.com` 으로 페이지가 연결할 수 있는 대상을 제한합니다.

### `POST /api/result`, `GET /api/results`

- 발급된 `requestId` 만 받고, 같은 ID는 한 번만 저장합니다. 메모리(최근 200건)에만 보관하며 재시작 시 사라집니다.
- 저장되는 결과에는 `"source": "browser"` 와 *브라우저가 전달한 값이며 서버가 AWS에서 직접 확인한 결과가 아님* 이라는 표시가 붙습니다.

### `GET /api/status`

프로필, SSO 세션/리전, 계정/역할(설정 파일 기준), EC2 리전, 자격증명 상태, 마스킹된 Access Key ID, 만료 시각, 재로그인 명령을 반환합니다.

## 보안 경계

- **브라우저로 가지 않는 것**: SecretAccessKey, SSO accessToken(및 refresh token). 이 값들은 EC2 프로세스와 `~/.aws/sso/cache` 에만 있습니다.
- **브라우저로 가는 것**: `X-Amz-Security-Token`(세션 토큰), Authorization(Access Key ID와 서명 포함). AWS 요청에 필요한 서명 헤더입니다.
  세션 토큰만으로는 SecretAccessKey 없이 새 요청을 서명할 수 없습니다.
- **서명된 요청은 일회용이 아닙니다.** SigV4는 재전송 방지를 제공하지 않습니다. 서명된 요청을 가진 누구든
  `X-Amz-Date` 기준으로 AWS가 허용하는 시간 범위 안에서, 세션 토큰이 유효한 동안 같은 요청을 다시 보낼 수 있습니다.
  `requestId` 는 결과를 짝짓는 용도일 뿐 서명을 무효화하지 않습니다. 이 PoC는 그 위험을 줄이기 위해 서명 대상을 읽기 전용
  `DescribeInstances` 하나로 고정하고, 서명된 요청을 로그·브라우저 저장소에 남기지 않습니다.
- **로그**: 앱 로그에는 requestId와 상태 코드만 남깁니다. botocore DEBUG 로그에는 canonical request(세션 토큰 포함)가 찍히므로
  `python -m app` 은 botocore 로거를 WARNING으로 고정합니다. 디버그 로깅을 켜지 마세요.
- **접근 제어**: 서버는 127.0.0.1에만 바인드, Host 헤더 허용 목록(DNS rebinding 방지), 커스텀 헤더 요구(교차 출처 POST 방지),
  CORS 미허용. 단일 사용자 PoC 이므로 별도 사용자 인증은 없습니다. EC2에 SSH로 접근 가능한 사람은 이 서버도 쓸 수 있습니다.

## 검증 절차

실제 AWS에서 수행하고 결과를 기록하세요.

### 1단계. SSO 자격증명 (EC2)

```bash
aws sso login --profile ta-bot-sso --use-device-code --no-browser
aws sts get-caller-identity --profile ta-bot-sso
```

`get-caller-identity` 는 IAM 정책의 Deny로 막을 수 없는 API라 EC2에서도 성공해야 하며, 역할 ARN(`AWSReservedSSO_...`)을 확인합니다.
서버 실행 후 `curl -s http://127.0.0.1:8000/api/status` 에서 `"credentials": "valid"` 와 만료 시각이 보이면 boto3 SSO provider 경로가 동작한 것입니다.

### 2단계. 브라우저 호출 (PC)

1. SSH 터널을 열고 http://localhost:8080 접속.
2. "백엔드 SSO 상태"에서 자격증명 `valid`, Access Key ID(마스킹) 확인.
3. "DescribeInstances 실행" 클릭.
4. 기대 결과: HTTP 200, `DescribeInstancesResponse` XML, 판정 "성공".
5. DevTools > Network에서 `OPTIONS` (preflight) 후 `POST` 가 `ec2.ap-northeast-2.amazonaws.com` 으로 직접 나갔는지 확인
   (localhost:8080 경유가 아님).
6. `curl -s http://127.0.0.1:8000/api/results` (EC2) 로 브라우저 전달 결과가 저장되었는지 확인.

### 3단계. 동일 역할로 EC2 직접 호출 vs 브라우저 호출 비교

같은 SSO 프로필(같은 역할, 같은 임시 자격증명)로 출발지만 다르게 비교합니다.

```bash
# (EC2) 출구 IP
curl -s https://checkip.amazonaws.com

# (EC2) AWS CLI 직접 호출
aws ec2 describe-instances --profile ta-bot-sso --region ap-northeast-2 --max-results 5

# (EC2) 브라우저에 주는 것과 같은 서명 요청을 EC2에서 직접 전송
AWS_PROFILE=ta-bot-sso python -m scripts.direct_call
```

```bash
# (PC) 출구 IP
curl -s https://checkip.amazonaws.com
```

| 비교 항목 | EC2 직접 (`aws ec2 ...` / `direct_call`) | PC 브라우저 |
|---|---|---|
| 출구 IP | EC2 공인 IP | PC 출구 IP |
| Access Key ID (마스킹) | `direct_call` 출력 | UI 상태 패널 |
| 기대 결과 | `UnauthorizedOperation` (explicit deny, SourceIp) | HTTP 200 |
| 실제 결과 | _기록_ | _기록_ |

- `direct_call` 과 브라우저의 Access Key ID가 같으면 **같은 임시 자격증명**으로 서명된 요청입니다.
- `direct_call` 이 `UnauthorizedOperation`(서명 오류가 아님)을 받으면, 같은 서명기 출력이 AWS에서 유효한 서명으로 받아들여진 뒤
  정책에서 거부된 것이므로 차이가 출발지 IP에 있음을 보여줍니다.
- 가장 확실한 확인은 **CloudTrail** 입니다. 콘솔 Event history(ap-northeast-2)에서 이벤트 이름 `DescribeInstances` 로 필터링하고
  `sourceIPAddress`, `userIdentity.accessKeyId`, `errorCode`, `userAgent`(브라우저 UA vs aws-cli/python) 를 비교하세요.
  이벤트 반영까지 수 분 걸릴 수 있습니다. CLI로 볼 경우 EC2 IP에서는 거부될 수 있으니 허용 IP에서 실행합니다.

  ```bash
  aws cloudtrail lookup-events --region ap-northeast-2 --profile <profile> \
    --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeInstances --max-results 10
  ```

## 오류 구분 가이드

| 화면 판정 | 의미 | 확인할 것 |
|---|---|---|
| **서명 실패 (HTTP 401) + 재로그인 명령** | `/api/prepare` 단계. SSO 토큰 없음/만료 | EC2에서 표시된 `aws sso login ... --use-device-code --no-browser` 실행 후 재시도. 재시작 불필요 |
| **서명 실패 (HTTP 500)** | 프로필 없음, `AWS_PROFILE` 미설정, SSO가 아닌 자격증명 | `.env`, `~/.aws/config` |
| **CORS/네트워크 오류** (`status: 0`, `TypeError: Failed to fetch`) | 브라우저가 AWS 응답을 읽지 못함. AWS가 요청을 받았는지도 불확실 | DevTools Console의 `blocked by CORS policy` 메시지, Network의 `OPTIONS` 상태와 `Access-Control-Allow-*` 헤더. 회사 프록시/SSL 검사, 보안 확장 프로그램, DNS. PC에서 아래 preflight curl 비교 |
| **서명 불일치** (`SignatureDoesNotMatch`, `IncompleteSignature`) | AWS가 받은 요청이 서명된 요청과 다름 | 본문/헤더가 바뀌지 않았는지(프록시의 Content-Type 재작성 등). EC2에서 `direct_call` 이 서명 오류 없이 처리되면 서명기는 정상이고 브라우저 경로에서 변형된 것. `pytest` 의 서명 재현 테스트 |
| **권한 거부** (`UnauthorizedOperation`, `AccessDenied`) | 서명은 유효, IAM 정책 평가에서 거부 | 메시지에 `explicit deny` 가 있으면 SourceIp Deny 가능성. 브라우저에서 났다면 PC 출구 IP(`checkip`)가 허용 목록에 있는지, VPN 분할 터널 여부. 인코딩된 메시지는 허용 IP에서 `aws sts decode-authorization-message` (해당 권한 필요). Permission Set에 `ec2:DescribeInstances` 가 없을 수도 있음 |
| **자격증명/시간 문제** (`AuthFailure`, `RequestExpired`, `ExpiredToken`) | 세션 토큰 만료 또는 `X-Amz-Date` 와 AWS 시각 차이 | 다시 실행해 새로 서명. EC2 시계 동기화(`chronyc tracking`) |

PC에서 CORS preflight만 따로 확인 (자격증명 불필요):

```bash
curl -s -i -X OPTIONS https://ec2.ap-northeast-2.amazonaws.com/ \
  -H "Origin: http://localhost:8080" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: authorization,content-type,x-amz-date,x-amz-security-token"
```

참고: CORS 응답 헤더가 오류 응답에 없으면 브라우저는 4xx 응답을 읽지 못해 "CORS/네트워크 오류"로 보입니다. 이 경우 DevTools Network의
응답 상태를 직접 확인하세요.

## 오프라인 검증

AWS 접속 없이 실행합니다. SSO `GetRoleCredentials` 는 botocore `before-send` 이벤트로 가짜 응답을 돌려주며, SSO 토큰 캐시/설정 파일은 임시 디렉터리를 씁니다.

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

| 분류 | 테스트 |
|---|---|
| 임의 요청 서명 방지 | `sign_describe_instances` 는 자격증명 하나만 인자로 받음 / `/api/prepare` 에 JSON·form 본문·쿼리(`url`, `Action=TerminateInstances` 등)를 넘기면 400 / 커스텀 헤더 없으면 403 / 허용되지 않은 Host는 400 / POST 라우트는 `/api/prepare`, `/api/result` 뿐 / `/api/result` 는 발급된 requestId만, 추가 필드 거부 |
| SecretAccessKey·SSO 토큰 누출 방지 | `/api/prepare`, `/api/status` 응답에 가짜 SecretAccessKey·SSO accessToken 문자열이 없음 / status의 Access Key ID 마스킹 / `configure_logging()` 적용 후 DEBUG 수준까지 수집한 로그에 Secret, 세션 토큰, 서명, Authorization, 요청 본문이 없음 |
| 서명 정합성 | botocore를 쓰지 않는 독립 SigV4 구현으로, Host·Content-Length를 뺀 전달값 + URL의 Host만으로 서명이 재현됨 / `host` 는 SignedHeaders에 포함, `content-length` 는 미포함 / 본문 변경·재인코딩 시 서명 불일치 |
| 고정 요청 | URL, POST, Content-Type, 본문 고정 / 프로필 `region` 이 다른 값이어도 EC2 리전 `ap-northeast-2` 유지 / `Cache-Control: no-store` |
| SSO provider 경로 | 실제 boto3 SSO credential provider가 토큰 캐시를 읽어 `portal.sso.<sso_region>` 으로 GetRoleCredentials 호출 / 유효한 동안 재호출 없음(재사용) / 토큰 없음·만료 시 401 + Device Code 재로그인 명령, 재로그인 후 재시작 없이 복구 |
| 브라우저 코드 정적 검사 | `mode:"cors"`, `credentials:"omit"`, `request.headers`/`request.body` 를 그대로 사용 / localStorage·sessionStorage·IndexedDB·console·cookie 미사용 / CSP connect-src |

오프라인 테스트는 AWS가 실제로 서명을 받아들이는지, CORS가 브라우저에서 통과하는지, SourceIp 조건이 기대대로 평가되는지는 검증하지 않습니다.
