from fastapi import APIRouter

router = APIRouter()

@router.post("/")
def scan_link(url: str):
    return {
        "url": url,
        "status": "Link scanner not integrated yet"
    }