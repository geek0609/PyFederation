import httpx

from pyfederation.exceptions import FederationClientException


def test_status_code_defaults_to_no_response() -> None:
    exception = FederationClientException("Failed to get entity: connection refused")
    assert str(exception) == "Failed to get entity: connection refused"
    assert exception.status_code == 0


def test_from_response_includes_the_server_message() -> None:
    response = httpx.Response(
        403, json={"success": False, "code": 403, "message": "Forbidden: Insufficient permissions"}
    )

    exception = FederationClientException.from_response(response, "Failed to delete entity")

    assert str(exception) == "Failed to delete entity, Forbidden: Insufficient permissions"
    assert exception.status_code == 403


def test_from_response_falls_back_to_the_reason_phrase() -> None:
    response = httpx.Response(502, text="<html>Bad Gateway</html>")

    exception = FederationClientException.from_response(response, "Failed to delete entity")

    assert str(exception) == "Failed to delete entity, Bad Gateway"
    assert exception.status_code == 502
