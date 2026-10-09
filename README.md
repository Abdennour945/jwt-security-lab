# JWT Security Analyzer

FastAPI web application for inspecting JWT headers and payloads and reporting basic security findings. This is a static inspection tool; it does **not** cryptographically verify JWT signatures. Do not enter production tokens containing sensitive information into untrusted deployments.

## Local setup

```bash
python -m venv .venv
pip install -r requirements.txt
uvicorn main:app --reload
```

Open http://127.0.0.1:8000

## Tests

```bash
pytest test_analyzer.py
```
