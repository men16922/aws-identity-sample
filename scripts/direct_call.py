"""[비교용] 브라우저에 내려주는 것과 동일한 서명 요청을 이 호스트(EC2)에서 직접 보낸다.

PoC 서버는 DescribeInstances를 호출하지 않는다. 이 스크립트는 README의
"EC2 직접 호출 vs 브라우저 호출" 비교 절차에서만 수동으로 실행한다.
서명/토큰 값은 출력하지 않는다.

    AWS_PROFILE=<profile> python -m scripts.direct_call
"""

import os
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from dotenv import load_dotenv

from app.credentials import CredentialError, LoginRequired, SsoCredentialSource, mask_access_key_id
from app.signer import sign_describe_instances


def main() -> int:
    load_dotenv()
    source = SsoCredentialSource(os.environ.get("AWS_PROFILE"))
    try:
        resolved = source.get()
    except (LoginRequired, CredentialError) as exc:
        print(exc, file=sys.stderr)
        return 2

    signed = sign_describe_instances(resolved.credentials)
    print(f"profile      : {source.profile}")
    print(f"accessKeyId  : {mask_access_key_id(resolved.credentials.access_key)}")
    print(f"request      : {signed['method']} {signed['url']}")

    req = urllib.request.Request(
        signed["url"],
        data=signed["body"].encode("utf-8"),
        headers=signed["headers"],
        method=signed["method"],
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            status, body = res.status, res.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        status, body = err.code, err.read().decode("utf-8", "replace")

    print(f"HTTP status  : {status}")
    if 200 <= status < 300:
        root = ET.fromstring(body)
        ns = {"ec2": root.tag.split("}")[0].strip("{")}
        count = len(root.findall("ec2:reservationSet/ec2:item/ec2:instancesSet/ec2:item", ns))
        print(f"instances    : {count}")
    else:
        root = ET.fromstring(body)
        print(f"error code   : {root.findtext('Errors/Error/Code')}")
        print(f"error message: {root.findtext('Errors/Error/Message')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
