import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from pyfederation import FederationClientException

from . import payloads
from .utils import run

pytestmark = pytest.mark.anyio

ATTACHMENT = f"/attachments/{payloads.ATTACHMENT_UUID}"
UPLOAD_RESULT = {
    "uuid": payloads.ATTACHMENT_UUID,
    "url": f"https://federation.example/attachments/{payloads.ATTACHMENT_UUID}",
}


def uploaded_file(request: httpx.Request) -> tuple[str, bytes]:
    """Returns the file name and content of the multipart upload, checking its evidence UUID."""
    content_type, _, boundary = request.headers["Content-Type"].partition("; boundary=")
    assert content_type == "multipart/form-data"

    fields = {}
    for part in request.content.split(b"--" + boundary.encode())[1:-1]:
        headers, _, body = part.partition(b"\r\n\r\n")
        fields[headers.split(b'name="')[1].split(b'"')[0].decode()] = (headers, body[:-2])

    assert fields["evidence_uuid"][1] == payloads.EVIDENCE_UUID.encode()
    file_headers, file_content = fields["file"]
    return file_headers.split(b'filename="')[1].split(b'"')[0].decode(), file_content


async def test_get_attachment_info(client: Any, api: respx.MockRouter) -> None:
    api.get(f"{ATTACHMENT}/info").respond(json=payloads.attachment())

    attachment = await run(client.get_attachment_info(payloads.ATTACHMENT_UUID))

    assert attachment.file_name == "screenshot.png"


async def test_list_attachments(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/attachments").respond(json=[payloads.attachment()])

    await run(client.list_attachments(category="IMAGE", by="file_size", order="DESC"))

    assert dict(route.calls.last.request.url.params) == {
        "page": "1",
        "limit": "100",
        "category": "IMAGE",
        "by": "file_size",
        "order": "DESC",
    }


async def test_search_attachments(client: Any, api: respx.MockRouter) -> None:
    route = api.get("/attachments/search").respond(json=[payloads.attachment()])

    attachments = await run(client.search_attachments("screenshot"))

    assert route.calls.last.request.url.params["q"] == "screenshot"
    assert attachments[0].evidence == payloads.EVIDENCE_UUID


async def test_delete_attachment(client: Any, api: respx.MockRouter) -> None:
    route = api.delete(ATTACHMENT).respond(json={"success": True})

    await run(client.delete_attachment(payloads.ATTACHMENT_UUID))

    assert route.called


async def test_upload_file_attachment(client: Any, api: respx.MockRouter, tmp_path: Path) -> None:
    route = api.post("/attachments").respond(201, json=UPLOAD_RESULT)
    file_path = tmp_path / "screenshot.png"
    file_path.write_bytes(b"\x89PNG")

    result = await run(client.upload_file_attachment(payloads.EVIDENCE_UUID, file_path))

    assert uploaded_file(route.calls.last.request) == ("screenshot.png", b"\x89PNG")
    assert result.uuid == payloads.ATTACHMENT_UUID


async def test_upload_file_attachment_with_file_name(
    client: Any, api: respx.MockRouter, tmp_path: Path
) -> None:
    route = api.post("/attachments").respond(201, json=UPLOAD_RESULT)
    file_path = tmp_path / "tmp123.png"
    file_path.write_bytes(b"\x89PNG")

    await run(client.upload_file_attachment(payloads.EVIDENCE_UUID, file_path, "chat.png"))

    assert uploaded_file(route.calls.last.request)[0] == "chat.png"


@pytest.mark.parametrize("file_name", ["transcript", "transcript.txt"])
async def test_upload_note_attachment(client: Any, api: respx.MockRouter, file_name: str) -> None:
    route = api.post("/attachments").respond(201, json=UPLOAD_RESULT)

    await run(client.upload_note_attachment(payloads.EVIDENCE_UUID, file_name, "Hello there"))

    assert uploaded_file(route.calls.last.request) == ("transcript.txt", b"Hello there")


async def test_upload_file_attachment_from_url(client: Any, api: respx.MockRouter) -> None:
    download = api.get("https://files.example/images/photo.jpg").respond(content=b"JPEG")
    upload = api.post("/attachments").respond(201, json=UPLOAD_RESULT)

    await run(
        client.upload_file_attachment_from_url(
            payloads.EVIDENCE_UUID, "https://files.example/images/photo.jpg?size=large"
        )
    )

    assert "Authorization" not in download.calls.last.request.headers
    assert uploaded_file(upload.calls.last.request) == ("photo.jpg", b"JPEG")


async def test_upload_file_attachment_by_url(client: Any, api: respx.MockRouter) -> None:
    route = api.post("/attachments").respond(201, json=UPLOAD_RESULT)

    result = await run(
        client.upload_file_attachment_by_url(payloads.EVIDENCE_UUID, "https://cdn.example/a.png")
    )

    assert json.loads(route.calls.last.request.content) == {
        "evidence_uuid": payloads.EVIDENCE_UUID,
        "url": "https://cdn.example/a.png",
    }
    assert result.uuid == payloads.ATTACHMENT_UUID


async def test_upload_file_attachment_from_url_limits_the_size(
    client: Any, api: respx.MockRouter
) -> None:
    api.get("https://files.example/large.bin").respond(content=b"x" * 11)

    with pytest.raises(FederationClientException) as raised:
        await run(
            client.upload_file_attachment_from_url(
                payloads.EVIDENCE_UUID, "https://files.example/large.bin", max_file_size=10
            )
        )

    assert raised.value.status_code == 413


async def test_upload_file_attachment_from_url_download_error(
    client: Any, api: respx.MockRouter
) -> None:
    api.get("https://files.example/missing.png").respond(404)

    with pytest.raises(FederationClientException) as raised:
        await run(
            client.upload_file_attachment_from_url(
                payloads.EVIDENCE_UUID, "https://files.example/missing.png"
            )
        )

    assert raised.value.status_code == 404


async def test_download_attachment(client: Any, api: respx.MockRouter, tmp_path: Path) -> None:
    api.get(ATTACHMENT).respond(
        content=b"\x89PNG",
        headers={"Content-Disposition": 'attachment; filename="screenshot.png"'},
    )

    file_path = await run(client.download_attachment(payloads.ATTACHMENT_UUID, tmp_path))

    assert file_path == tmp_path / "screenshot.png"
    assert file_path.read_bytes() == b"\x89PNG"


@pytest.mark.parametrize(
    "file_name", ["../../escape.sh", "..\\..\\escape.sh", "C:escape.sh", "a.txt:escape.sh"]
)
async def test_download_attachment_stays_in_the_directory(
    client: Any, api: respx.MockRouter, tmp_path: Path, file_name: str
) -> None:
    api.get(ATTACHMENT).respond(
        content=b"data", headers={"Content-Disposition": f'attachment; filename="{file_name}"'}
    )

    file_path = await run(client.download_attachment(payloads.ATTACHMENT_UUID, tmp_path))

    assert file_path == tmp_path / "escape.sh"


async def test_download_attachment_falls_back_to_its_uuid(
    client: Any, api: respx.MockRouter, tmp_path: Path
) -> None:
    api.get(ATTACHMENT).respond(
        content=b"data", headers={"Content-Disposition": 'attachment; filename=".."'}
    )

    file_path = await run(client.download_attachment(payloads.ATTACHMENT_UUID, tmp_path))

    assert file_path == tmp_path / payloads.ATTACHMENT_UUID


async def test_download_attachment_requires_a_directory(client: Any, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Directory does not exist"):
        await run(client.download_attachment(payloads.ATTACHMENT_UUID, tmp_path / "missing"))


async def test_upload_file_attachment_rejects_empty_files(client: Any, tmp_path: Path) -> None:
    file_path = tmp_path / "empty.txt"
    file_path.touch()

    with pytest.raises(ValueError, match="Invalid file or empty file"):
        await run(client.upload_file_attachment(payloads.EVIDENCE_UUID, file_path))


async def test_download_attachment_error(
    client: Any, api: respx.MockRouter, tmp_path: Path
) -> None:
    api.get(ATTACHMENT).respond(
        404, json={"success": False, "code": 404, "message": "Attachment not found"}
    )

    with pytest.raises(FederationClientException, match="Attachment not found"):
        await run(client.download_attachment(payloads.ATTACHMENT_UUID, tmp_path))

    assert not any(tmp_path.iterdir())


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda client: client.get_attachment_info(""), "Attachment UUID cannot be empty"),
        (
            lambda client: client.upload_note_attachment(payloads.EVIDENCE_UUID, "", "Note"),
            "File name cannot be empty",
        ),
        (
            lambda client: client.upload_note_attachment(payloads.EVIDENCE_UUID, "note", ""),
            "Content cannot be empty",
        ),
        (
            lambda client: client.upload_file_attachment_from_url(payloads.EVIDENCE_UUID, ""),
            "Invalid URL provided",
        ),
        (
            lambda client: client.upload_file_attachment_from_url(
                payloads.EVIDENCE_UUID, "https://cdn.example/a.png", 0
            ),
            "Maximum file size must be greater than 0",
        ),
        (
            lambda client: client.upload_file_attachment_by_url(payloads.EVIDENCE_UUID, ""),
            "Invalid URL provided",
        ),
        (
            lambda client: client.upload_file_attachment_by_url(
                payloads.EVIDENCE_UUID, "file:///etc/passwd"
            ),
            "URL must be a valid HTTP or HTTPS URL",
        ),
        (
            lambda client: client.upload_file_attachment_by_url(
                payloads.EVIDENCE_UUID, "not-a-valid-url"
            ),
            "URL must be a valid HTTP or HTTPS URL",
        ),
        (
            lambda client: client.download_attachment(payloads.ATTACHMENT_UUID, ""),
            "Directory path cannot be empty",
        ),
        (
            lambda client: client.upload_file_attachment(payloads.EVIDENCE_UUID, "missing.png"),
            "File does not exist",
        ),
    ],
)
async def test_invalid_arguments(client: Any, call: Callable[[Any], Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        await run(call(client))
