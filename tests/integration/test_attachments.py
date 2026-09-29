from pathlib import Path
from typing import Any

import pytest

from ..utils import run
from .conftest import ENDPOINT, Records

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


async def test_file_attachment_lifecycle(client: Any, records: Records, tmp_path: Path) -> None:
    evidence_uuid = await records.evidence(await records.entity())
    upload_path = tmp_path / "upload" / "conversation.txt"
    upload_path.parent.mkdir()
    upload_path.write_text("Buy cheap watches")

    uploaded = records.track(
        "delete_attachment",
        (await run(client.upload_file_attachment(evidence_uuid, upload_path))).uuid,
    )
    info = await run(client.get_attachment_info(uploaded))
    attachments = await run(client.get_evidence_attachments(evidence_uuid))
    downloaded = await run(client.download_attachment(uploaded, tmp_path))

    assert info.evidence == evidence_uuid
    assert info.file_size == len("Buy cheap watches")
    assert [attachment.uuid for attachment in attachments] == [uploaded]
    assert downloaded.read_text() == "Buy cheap watches"


async def test_note_attachment(client: Any, records: Records) -> None:
    evidence_uuid = await records.evidence(await records.entity())

    uploaded = records.track(
        "delete_attachment",
        (await run(client.upload_note_attachment(evidence_uuid, "note", "Reported twice"))).uuid,
    )
    info = await run(client.get_attachment_info(uploaded))

    assert info.file_name == "note.txt"
    assert info.file_mime == "text/plain"


async def test_attachment_from_url(client: Any, records: Records) -> None:
    evidence_uuid = await records.evidence(await records.entity())

    uploaded = records.track(
        "delete_attachment",
        (
            await run(
                client.upload_file_attachment_from_url(evidence_uuid, f"{ENDPOINT}/specification")
            )
        ).uuid,
    )
    info = await run(client.get_attachment_info(uploaded))

    assert info.file_name == "specification"
    assert info.file_size > 0


async def test_list_and_delete_attachments(client: Any, records: Records) -> None:
    evidence_uuid = await records.evidence(await records.entity())
    uploaded = records.track(
        "delete_attachment",
        (await run(client.upload_note_attachment(evidence_uuid, "listed", "Listed note"))).uuid,
    )

    listed = await run(client.list_attachments(by="created", order="DESC"))

    assert uploaded in [attachment.uuid for attachment in listed]

    await run(client.delete_attachment(uploaded))
    assert await run(client.get_evidence_attachments(evidence_uuid)) == []
