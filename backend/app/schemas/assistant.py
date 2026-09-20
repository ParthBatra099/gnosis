from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints


class AssistantQueryRequest(BaseModel):
    # Whitespace is stripped before the length check, so "   " fails min_length and returns 422.
    query: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1, max_length=500),
    ]


class AssistantQueryResponse(BaseModel):
    answer: str
    sources: list[str] = Field(default_factory=list)
    access_denied: bool = False