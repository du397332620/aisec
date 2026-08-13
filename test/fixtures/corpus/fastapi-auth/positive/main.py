from fastapi import FastAPI

from app.api import api_router
from app.auth import AuthMiddleware

app = FastAPI()
app.add_middleware(AuthMiddleware)
app.include_router(api_router)
