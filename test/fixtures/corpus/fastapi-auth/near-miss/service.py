from fastapi import Depends, FastAPI

from app.security import require_auth

app = FastAPI(dependencies=[Depends(require_auth)])


@app.post("/generate")
async def generate(payload: dict):
    return generator.run(payload)
