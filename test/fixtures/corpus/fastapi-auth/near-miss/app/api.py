from fastapi import APIRouter

from app.routes import permission

api_router = APIRouter()
api_router.include_router(permission.router, prefix="/permission")
