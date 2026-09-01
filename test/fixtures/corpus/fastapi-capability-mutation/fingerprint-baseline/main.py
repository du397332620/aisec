from fastapi import FastAPI

app = FastAPI()


@app.patch("/profiles/{profile_id}")
async def update_profile(profile_id: str, data: CustomerUpdateData):
    return {"profile_id": profile_id, "data": data}
