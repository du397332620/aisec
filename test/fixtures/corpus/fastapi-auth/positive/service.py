from fastapi import FastAPI

app = FastAPI()


@app.post("/generate")
async def generate(payload: dict):
    return generator.run(payload)
