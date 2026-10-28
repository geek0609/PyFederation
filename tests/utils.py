import inspect
from typing import Any

import httpx

ENDPOINT = "https://federation.example"
ACCESS_TOKEN = "abcdefghijklmnopqrstuvwxyz123456"


async def run(result: Any) -> Any:
    """Returns the result of a client call, awaiting it for the asynchronous client."""
    return await result if inspect.isawaitable(result) else result


def multipart_parts(request: httpx.Request) -> dict[str, tuple[str | None, bytes]]:
    """Returns the file name, None for a part without a file, and the content of each part of a
    multipart request by name."""
    content_type, _, boundary = request.headers["Content-Type"].partition("; boundary=")
    assert content_type == "multipart/form-data"

    parts = {}
    for part in request.content.split(b"--" + boundary.encode())[1:-1]:
        headers, _, body = part.partition(b"\r\n\r\n")
        name = headers.split(b'name="')[1].split(b'"')[0].decode()
        file_name = (
            headers.split(b'filename="')[1].split(b'"')[0].decode()
            if b"filename=" in headers
            else None
        )
        parts[name] = (file_name, body[:-2])

    return parts
