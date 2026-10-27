from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from backend import storage
from backend.api import router
from backend.config import ALLOWED_ORIGINS, FRONTEND_DIST_DIR, validate_target


@asynccontextmanager
async def lifespan(app):
    validate_target()
    for record in storage.attacks():
        if record['status'] == 'running':
            record.update(status='interrupted', error='Backend restarted before completion')
            storage.save_attack(record)
    yield


app = FastAPI(title='Honeyguard Attack Panel', lifespan=lifespan)


@app.middleware('http')
async def local_access(request: Request, call_next):
    if request.client.host not in ('127.0.0.1', '::1', 'testclient'):
        return JSONResponse(status_code=403, content={'detail': 'This lab panel is restricted to local access'})
    host = request.headers.get('host', '').split(':')[0].strip('[]')
    if host not in ('localhost', '127.0.0.1', 'testserver', '') and not request.headers.get('host', '').startswith('[::1]'):
        return JSONResponse(status_code=403, content={'detail': 'Unapproved host'})
    origin = request.headers.get('origin')
    if origin and origin not in ALLOWED_ORIGINS:
        return JSONResponse(status_code=403, content={'detail': 'Unapproved browser origin'})
    return await call_next(request)


app.include_router(router)
# check_dir=False allows a first frontend build after the backend has started.
app.mount('/assets', StaticFiles(directory=FRONTEND_DIST_DIR / 'assets', check_dir=False), name='assets')


@app.get('/', response_model=None)
async def index():
    index_file = FRONTEND_DIST_DIR / 'index.html'
    if not index_file.exists():
        return JSONResponse(status_code=503, content={'error': 'Frontend build not found.', 'hint': 'Run npm install and npm run build inside frontend/.'})
    return FileResponse(index_file)
