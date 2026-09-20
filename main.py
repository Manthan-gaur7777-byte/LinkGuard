from fastapi import FastAPI
from pydantic import BaseModel#bass check 
from analyzer import analyze_url
app = FastAPI()
class URLRequest(BaseModel):
    url: str


@app.get("/")
def home():
    return {
        "message": "LinkGuard is running"
    }


@app.post("/analyze")
def analyze(request: URLRequest):
    return analyze_url(request.url)