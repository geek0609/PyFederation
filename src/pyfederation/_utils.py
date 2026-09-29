from collections.abc import Sequence
from dataclasses import asdict
from typing import Any, TypeVar
from urllib.parse import quote

from pydantic import BaseModel

from .records import ContentInput

M = TypeVar("M", bound=BaseModel)


def compact(**values: Any) -> dict[str, Any]:
    """Returns the given values without the ones that are unset."""
    return {key: value for key, value in values.items() if value is not None}


def require(value: str | None, name: str) -> None:
    """Raises a ValueError if the value is empty."""
    if not value:
        raise ValueError(f"{name} cannot be empty")


def page_params(
    page: int, limit: int, by: str | None = None, order: str | None = None, **filters: Any
) -> dict[str, Any]:
    """Returns the query parameters of a paginated request.

    The sort field is lowercased and the sort order uppercased, matching what the server expects.
    """
    if page < 1:
        raise ValueError("Page must be greater than 0")
    if limit < 1:
        raise ValueError("Limit must be greater than 0")

    return compact(
        page=page,
        limit=limit,
        **filters,
        by=by.lower() if by is not None else None,
        order=order.upper() if order is not None else None,
    )


def search_params(query: str, page: int, limit: int, **params: Any) -> dict[str, Any]:
    """Returns the query parameters of a paginated search."""
    if len(query) < 2:
        raise ValueError("Search query must be at least 2 characters")

    return {"q": query, **page_params(page, limit, **params)}


def path_segment(value: str) -> str:
    """Returns an identifier percent-encoded as one path segment, so it cannot address another
    endpoint."""
    if value in (".", ".."):
        raise ValueError("Identifier cannot be '.' or '..'")

    return quote(value, safe="")


def parse_list(model: type[M], data: list[Any]) -> list[M]:
    return [model.model_validate(item) for item in data]


def evidence_payload(
    evidence: str | ContentInput | Sequence[ContentInput],
) -> dict[str, Any] | list[dict[str, Any]]:
    if isinstance(evidence, str):
        evidence = ContentInput(evidence)

    if isinstance(evidence, ContentInput):
        return compact(**asdict(evidence))

    if not evidence:
        raise ValueError("Evidence cannot be empty")

    return [compact(**asdict(item)) for item in evidence]
