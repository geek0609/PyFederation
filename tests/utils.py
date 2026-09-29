import inspect
from typing import Any

ENDPOINT = "https://federation.example"
ACCESS_TOKEN = "abcdefghijklmnopqrstuvwxyz123456"


async def run(result: Any) -> Any:
    """Returns the result of a client call, awaiting it for the asynchronous client."""
    return await result if inspect.isawaitable(result) else result
