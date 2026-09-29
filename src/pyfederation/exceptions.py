import httpx


class FederationClientException(Exception):
    """Raised when a request to the Federation server fails.

    Attributes:
        status_code: The HTTP status code of the response, or 0 if no response was received.
    """

    def __init__(self, message: str, status_code: int = 0) -> None:
        super().__init__(message)
        self.status_code = status_code

    @classmethod
    def from_response(cls, response: httpx.Response, message: str) -> "FederationClientException":
        """Builds an exception from an error response, including the server's error message."""
        try:
            reason = response.json()["message"]
        except (ValueError, KeyError):
            reason = response.reason_phrase

        return cls(f"{message}, {reason}", response.status_code)
