import logging
import os

import uvicorn
from dotenv import load_dotenv


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # botocore DEBUG 로그에는 canonical request(X-Amz-Security-Token 포함)가 찍히므로 WARNING 이상만 남긴다.
    logging.getLogger("botocore").setLevel(logging.WARNING)


def main() -> None:
    load_dotenv()
    configure_logging()
    uvicorn.run(
        "app.main:app",
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8000")),
        log_level="info",
    )


if __name__ == "__main__":
    main()
