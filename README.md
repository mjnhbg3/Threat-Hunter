# Threat Hunter

This project collects security logs from a Wazuh manager, stores them in a FAISS vector database and uses Gemini AI for analysis. A small dashboard allows viewing issues and running ad-hoc analyses.

## Persistent settings

Runtime options such as processing interval and batch sizes are persisted to `settings.json` in the configured database directory. They can be viewed and updated via the dashboard API:

- `GET /api/settings` returns the current settings.
- `POST /api/settings` accepts a JSON body with any of the configurable values.
- `POST /api/clear_db` clears all stored vectors and dashboard state.

These settings control the worker loop interval and other limits at runtime.
