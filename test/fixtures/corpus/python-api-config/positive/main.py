from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse


app = FastAPI(docs_url="/docs", openapi_url="/openapi.json")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"code": 500, "message": str(exc)},
    )


@app.post("/generate")
async def generate(payload: dict):
    return {"ok": True}


@app.put("/projects/{project_id}")
@app.post("/projects/{project_id}")
async def project_detail(project_id: int):
    try:
        return load_project(project_id)
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"project lookup failed: {error}")


@app.get("/reports")
async def report_list():
    try:
        return load_reports()
    except Exception as error:
        return {"message": str(error)}
