from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from analyzer import analyze_token

app = FastAPI(title="JWT Security Analyzer", version="0.1.0")
templates = Jinja2Templates(directory="templates")


class AnalyzeRequest(BaseModel):
    token: str


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    try:
        return analyze_token(req.token)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
