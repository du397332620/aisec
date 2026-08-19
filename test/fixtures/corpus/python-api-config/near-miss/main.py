from fastapi import Depends, FastAPI, HTTPException, Request
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


@app.post("/projects/{project_id}")
async def project_detail(project_id: int):
    try:
        return load_project(project_id)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception as error:
        record_server_error(error)
        raise HTTPException(status_code=500, detail="internal error")


@app.get("/status-only")
async def status_only():
    try:
        return load_status()
    except Exception as error:
        raise HTTPException(status_code=int(str(error)), detail="internal error")
