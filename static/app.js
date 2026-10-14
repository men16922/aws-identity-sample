"use strict";

// 서명된 요청, Authorization, X-Amz-Security-Token 은 console/localStorage/sessionStorage 에 남기지 않는다.

const CLIENT_HEADERS = { "X-Requested-With": "sigv4-poc" };
const SENSITIVE_HEADERS = new Set(["authorization", "x-amz-security-token"]);

const $ = (id) => document.getElementById(id);

function renderStatus(data) {
  const dl = $("status");
  dl.replaceChildren();
  const rows = [
    ["프로필", data.profile],
    ["SSO 세션", data.ssoSession],
    ["SSO 리전", data.ssoRegion],
    ["계정 / 역할", [data.accountId, data.roleName].filter(Boolean).join(" / ")],
    ["EC2 조회 리전", data.ec2Region],
    ["목적지", data.endpoint],
    ["자격증명", data.credentials],
    ["Access Key ID", data.accessKeyId],
    ["만료 시각", data.expiresAt],
    ["메시지", data.message],
  ];
  if (data.credentials !== "valid") rows.push(["EC2에서 실행", data.loginCommand]);
  for (const [k, v] of rows) {
    if (v === undefined || v === null || v === "") continue;
    const dt = document.createElement("dt");
    dt.textContent = k;
    const dd = document.createElement("dd");
    dd.textContent = v;
    dl.append(dt, dd);
  }
}

async function loadStatus() {
  try {
    const res = await fetch("/api/status");
    renderStatus(await res.json());
  } catch (e) {
    renderStatus({ message: `상태 조회 실패: ${e}` });
  }
}

function summarize(request) {
  const lines = [`${request.method} ${request.url}`];
  for (const [name, value] of Object.entries(request.headers)) {
    lines.push(`${name}: ${SENSITIVE_HEADERS.has(name.toLowerCase()) ? "<redacted>" : value}`);
  }
  lines.push("", request.body);
  return lines.join("\n");
}

function errorCode(xml) {
  try {
    const doc = new DOMParser().parseFromString(xml, "application/xml");
    const code = doc.querySelector("Error > Code");
    const msg = doc.querySelector("Error > Message");
    return { code: code ? code.textContent : null, message: msg ? msg.textContent : null };
  } catch {
    return { code: null, message: null };
  }
}

function classify(status, payload) {
  if (status === 0) {
    return {
      level: "err",
      text:
        "CORS/네트워크 오류: 브라우저가 AWS 응답을 읽지 못했습니다.\n" +
        "DevTools > Network 에서 OPTIONS(preflight)와 POST 요청의 상태, " +
        "Access-Control-Allow-* 응답 헤더, 프록시/방화벽 차단 여부를 확인하세요.",
    };
  }
  if (status >= 200 && status < 300) {
    const doc = new DOMParser().parseFromString(payload, "application/xml");
    const n = doc.querySelectorAll("reservationSet > item > instancesSet > item").length;
    return { level: "ok", text: `성공 (HTTP ${status}): 이 응답에 인스턴스 ${n}개 (MaxResults=5).` };
  }
  const { code, message } = errorCode(payload);
  const detail = `\nCode=${code}\n${message ?? ""}`;
  switch (code) {
    case "SignatureDoesNotMatch":
    case "IncompleteSignature":
    case "InvalidSignature":
      return {
        level: "err",
        text: "서명 불일치: AWS가 받은 요청이 서명된 요청과 다릅니다(본문 재인코딩, 헤더 변경 등)." + detail,
      };
    case "UnauthorizedOperation":
    case "AccessDenied":
    case "AccessDeniedException":
      return {
        level: "warn",
        text:
          "권한 거부: 서명은 유효하고 IAM 정책 평가에서 거부되었습니다. " +
          "aws:SourceIp Deny 라면 이 PC의 출구 IP가 허용 목록에 없는 것입니다." + detail,
      };
    case "AuthFailure":
    case "InvalidClientTokenId":
    case "ExpiredToken":
    case "RequestExpired":
    case "RequestTimeTooSkewed":
      return {
        level: "err",
        text: "자격증명/시간 문제: 토큰 만료 또는 X-Amz-Date 시간 차이. 다시 실행해 새로 서명받으세요." + detail,
      };
    default:
      return { level: "err", text: `기타 오류 (HTTP ${status}).` + detail };
  }
}

function showVerdict({ level, text }) {
  const el = $("verdict");
  el.className = `verdict ${level}`;
  el.textContent = text;
  el.hidden = false;
}

async function run() {
  const button = $("run");
  button.disabled = true;
  $("verdict").hidden = true;
  for (const id of ["request-summary", "aws-response", "report"]) $(id).textContent = "-";
  $("http-status").textContent = "";

  try {
    // 1) 백엔드에서 서명된 요청 받기
    const prep = await fetch("/api/prepare", { method: "POST", headers: CLIENT_HEADERS });
    const prepBody = await prep.json();
    if (!prep.ok) {
      const cmd = prepBody.loginCommand ? `\n\nEC2에서 실행:\n${prepBody.loginCommand}` : "";
      showVerdict({ level: "err", text: `서명 실패 (HTTP ${prep.status}): ${prepBody.message ?? prepBody.detail}${cmd}` });
      await loadStatus();
      return;
    }
    const requestId = prepBody.requestId;
    let request = prepBody.request;
    $("request-summary").textContent = summarize(request);

    // 2) 받은 URL/메서드/헤더/본문을 그대로 사용해 AWS로 직접 호출
    let status = 0;
    let payload;
    try {
      const res = await fetch(request.url, {
        method: request.method,
        headers: request.headers,
        body: request.body,
        mode: "cors",
        credentials: "omit",
      });
      status = res.status;
      payload = await res.text();
    } catch (e) {
      payload = `fetch failed: ${e.name}: ${e.message}`;
    } finally {
      request = null;
    }

    $("http-status").textContent = status ? `HTTP ${status}` : "(응답 없음)";
    $("aws-response").textContent = payload;
    showVerdict(classify(status, payload));

    // 3) 결과를 백엔드에 전달
    const rep = await fetch("/api/result", {
      method: "POST",
      headers: { ...CLIENT_HEADERS, "Content-Type": "application/json" },
      body: JSON.stringify({ requestId, status, payload }),
    });
    $("report").textContent = `HTTP ${rep.status}\n${JSON.stringify(await rep.json(), null, 2)}`;
  } catch (e) {
    showVerdict({ level: "err", text: `PoC 서버 통신 오류: ${e}` });
  } finally {
    button.disabled = false;
  }
}

$("run").addEventListener("click", run);
$("refresh-status").addEventListener("click", loadStatus);
loadStatus();
