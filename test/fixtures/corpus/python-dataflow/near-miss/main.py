import ipaddress
import os
import socket
import urllib.parse
import urllib.request
from fastapi import Depends, FastAPI
from sqlalchemy import text


def get_current_user():
    return {"id": 7}


def validate_public_url(value):
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or parsed.hostname not in {"files.example.test"}:
        raise ValueError("untrusted URL")
    addresses = socket.getaddrinfo(parsed.hostname, 443)
    if any(ipaddress.ip_address(item[4][0]).is_private for item in addresses):
        raise ValueError("private address")
    return value


def resolve_under_root(root, name):
    safe_name = os.path.basename(name)
    return os.path.join(root, safe_name)


class LLMClient:
    def __init__(self, base_url=None, api_key=None):
        self.base_url = base_url or os.getenv("MODEL_BASE_URL")
        self.api_key = api_key or os.getenv("MODEL_API_KEY")

    def chat(self):
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        return urllib.request.urlopen(request)


app = FastAPI(dependencies=[Depends(get_current_user)])


@app.post("/fetch")
def fetch_remote(payload: dict):
    trusted_url = validate_public_url(payload.get("url"))
    return urllib.request.urlopen(trusted_url)


@app.post("/write")
def write_file(payload: dict):
    target_path = resolve_under_root("/srv/uploads", payload.get("name"))
    with open(target_path, "w", encoding="utf-8") as output:
        output.write("fixture")
    return {"written": True}


@app.post("/query")
def query_reports(payload: dict, session=Depends(get_session)):
    statement = text("select * from reports where report_type = :report_type")
    return session.exec(statement, {"report_type": payload.get("report_type")}).all()


@app.post("/generate")
def generate(payload: dict):
    client = LLMClient(base_url="https://models.example.test/v1")
    return client.chat()
