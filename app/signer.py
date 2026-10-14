"""고정된 EC2 DescribeInstances 요청 하나만 SigV4로 서명한다.

이 모듈은 URL, 메서드, 본문, 서비스, 리전을 외부 입력으로 받지 않는다.
임의 요청 서명기로 쓰일 수 없도록 함수 시그니처를 자격증명 하나로 제한한다.
"""

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import ReadOnlyCredentials

EC2_REGION = "ap-northeast-2"
EC2_SERVICE = "ec2"
EC2_ENDPOINT = f"https://ec2.{EC2_REGION}.amazonaws.com/"
HTTP_METHOD = "POST"
CONTENT_TYPE = "application/x-www-form-urlencoded"
DESCRIBE_INSTANCES_BODY = "Action=DescribeInstances&Version=2016-11-15&MaxResults=5"

# Host는 서명에 포함되지만 브라우저가 목적지 URL로 직접 설정한다.
# Content-Length도 브라우저가 본문 길이로 설정한다. 둘 다 fetch에서 지정할 수 없다.
BROWSER_MANAGED_HEADERS = frozenset({"host", "content-length"})


def sign_describe_instances(credentials: ReadOnlyCredentials) -> dict:
    """서명된 DescribeInstances 요청을 브라우저 전달용 dict로 반환한다.

    실제 AWS 호출은 하지 않는다.
    """
    request = AWSRequest(
        method=HTTP_METHOD,
        url=EC2_ENDPOINT,
        data=DESCRIBE_INSTANCES_BODY.encode("utf-8"),
        headers={"Content-Type": CONTENT_TYPE},
    )
    SigV4Auth(credentials, EC2_SERVICE, EC2_REGION).add_auth(request)

    headers = {
        name: value
        for name, value in request.headers.items()
        if name.lower() not in BROWSER_MANAGED_HEADERS
    }
    return {
        "url": EC2_ENDPOINT,
        "method": HTTP_METHOD,
        "headers": headers,
        "body": DESCRIBE_INSTANCES_BODY,
    }
