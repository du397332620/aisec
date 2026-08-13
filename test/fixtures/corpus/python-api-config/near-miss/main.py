from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse


def get_current_user():
    return {"id": 7}


app = FastAPI(
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    dependencies=[Depends(get_current_user)],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://console.example.test"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.exception_handler(Exception)
async def exception_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"message": "internal error"})


@app.post("/generate")
async def generate(payload: dict):
    return {"ok": True}
