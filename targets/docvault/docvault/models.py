"""Request and response bodies."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Status = Literal["draft", "review", "published"]


class ReportCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    summary: str = Field(default="", max_length=4000)
    status: Status = "draft"


class ReportUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    summary: str | None = Field(default=None, max_length=4000)
    status: Status | None = None


class ReportOut(BaseModel):
    id: int
    title: str
    summary: str
    status: str
    owner_id: int
    team_id: int
    created_at: str
    updated_at: str


class DocumentOut(BaseModel):
    id: int
    report_id: int
    filename: str
    content_type: str
    size_bytes: int
    uploaded_at: str


class WebhookConfig(BaseModel):
    url: str = Field(max_length=2000)


class WebhookTest(BaseModel):
    event: str = Field(default="ping", max_length=64)
    payload: dict = Field(default_factory=dict)


class LogoImport(BaseModel):
    url: str = Field(max_length=2000)


class TemplateIn(BaseModel):
    """A report template, posted as JSON and validated before use."""

    name: str = Field(min_length=1, max_length=120)
    sections: list[str] = Field(default_factory=list, max_length=50)
    default_status: Status = "draft"
