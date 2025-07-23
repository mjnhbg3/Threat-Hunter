import asyncio
import os

import uvicorn
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import PlainTextResponse

from threat_hunter.api import dashboard, chat, issues, logs
from threat_hunter.settings import get_threat_hunter_core
from threat_hunter.utils.logger import logger

security = HTTPBasic()
app = FastAPI()
core = None
app.mount(
    "/static", StaticFiles(directory="threat_hunter/static"), name="static"
)


def check_auth(credentials: HTTPBasicCredentials = Depends(security)):
    """Simple HTTP basic auth using environment variables."""
    user = os.environ.get("BASIC_AUTH_USER")
    pwd = os.environ.get("BASIC_AUTH_PASS")
    if credentials.username != user or credentials.password != pwd:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return credentials.username

app.include_router(dashboard.router, dependencies=[Depends(check_auth)])
app.include_router(chat.router, dependencies=[Depends(check_auth)])
app.include_router(issues.router, dependencies=[Depends(check_auth)])
app.include_router(logs.router, dependencies=[Depends(check_auth)])


@app.on_event("startup")
async def startup_event():
    """Initialize core and start the periodic worker."""
    logger.info("Starting Threat Hunter application...")
    global core
    core = get_threat_hunter_core()

    interval = int(os.environ.get("PROCESS_INTERVAL", 300))

    async def periodic():
        while True:
            logs = await core.process_logs()
            await core.analyze(logs)
            await asyncio.sleep(interval)

    asyncio.create_task(periodic())


@app.get("/metrics")
async def metrics_endpoint():
    if core:
        text = await core.metrics.render()
        return PlainTextResponse(text)
    return PlainTextResponse("")


if __name__ == "__main__":
    # Verify required environment variables before starting
    api_keys = os.environ.get("GEMINI_API_KEYS") or os.environ.get("GEMINI_API_KEY")
    basic_user = os.environ.get("BASIC_AUTH_USER")
    basic_pass = os.environ.get("BASIC_AUTH_PASS")

    if not api_keys or not any(k.strip() for k in api_keys.split(",")):
        logger.error("No GEMINI_API_KEY provided. Set GEMINI_API_KEYS or GEMINI_API_KEY.")
        raise SystemExit(1)

    if not basic_user or not basic_pass:
        logger.error("BASIC_AUTH_USER and BASIC_AUTH_PASS must be set.")
        raise SystemExit(1)

    uvicorn.run(app, host="0.0.0.0", port=8000)
