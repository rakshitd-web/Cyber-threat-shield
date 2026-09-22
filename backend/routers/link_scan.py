from fastapi import APIRouter
from pydantic import BaseModel

from services.link_checker import scan_link as perform_link_scan

router = APIRouter()


class LinkScanRequest(BaseModel):
    url: str


@router.post("/")
def scan_link_endpoint(request: LinkScanRequest):
    return perform_link_scan(request.url)