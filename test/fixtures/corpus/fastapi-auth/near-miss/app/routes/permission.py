from fastapi import APIRouter, Depends, HTTPException

from app.security import get_current_user

router = APIRouter()


@router.post("/operation/create")
async def create_operation(request: dict, current_user=Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403)
    return permission_store.create(request, actor=current_user)
