from fastapi import APIRouter

router = APIRouter()


@router.post("/operation/create")
async def create_operation(request: dict):
    return permission_store.create(request)
