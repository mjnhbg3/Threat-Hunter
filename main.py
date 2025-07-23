
import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from threat_hunter.api import dashboard, chat, issues, logs
from threat_hunter.settings import get_threat_hunter_core
from threat_hunter.utils.logger import logger

app = FastAPI()

app.mount("/static", StaticFiles(directory="threat_hunter/static"), name="static")

app.include_router(dashboard.router)
app.include_router(chat.router)
app.include_router(issues.router)
app.include_router(logs.router)

@app.on_event("startup")
async def startup_event():
    logger.info("Starting Threat Hunter application...")
    core = get_threat_hunter_core()
    # In a real application, you might want to run an initial log fetch here
    # asyncio.create_task(core.fetch_and_process_logs())

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
