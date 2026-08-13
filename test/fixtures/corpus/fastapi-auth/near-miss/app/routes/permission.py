from fastapi import APIRouter, Depends

from app.security import get_current_user

router = APIRouter()


@router.post("/operation/create")
async def create_operation(request: dict, current_user=Depends(get_current_user)):
    return permission_store.create(request, actor=current_user)
