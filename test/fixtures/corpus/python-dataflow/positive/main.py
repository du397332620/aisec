import os
import urllib.request
from fastapi import Depends, FastAPI
from sqlalchemy import text


def get_current_user():
    return {"id": 7}


class LLMClient:
    def __init__(self, base_url=None, api_key=None):
        self.base_url = base_url or os.getenv("MODEL_BASE_URL")
        self.api_key = api_key or os.getenv("MODEL_API_KEY")

    def chat(self):
        url = f"{self.base_url}/chat/completions"
        request = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        return urllib.request.urlopen(request)


app = FastAPI(dependencies=[Depends(get_current_user)])


@app.post("/fetch")
def fetch_remote(payload: dict):
    target_url = payload.get("url")
    return urllib.request.urlopen(target_url)


@app.post("/write")
def write_file(payload: dict):
    target_path = payload.get("path")
    with open(target_path, "w", encoding="utf-8") as output:
        output.write("fixture")
    return {"written": True}


@app.post("/query")
def query_reports(payload: dict, session=Depends(get_session)):
    report_type = payload.get("report_type")
    statement = text(f"select * from reports where report_type = '{report_type}'")
    return session.exec(statement).all()


@app.post("/generate")
def generate(payload: dict):
    client = LLMClient(base_url=payload.get("base_url"))
    return client.chat()
