import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from backend.config import DB_FILE


def now():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connect():
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_FILE)
    db.row_factory = sqlite3.Row
    db.execute('CREATE TABLE IF NOT EXISTS attacks (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, data TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, data TEXT NOT NULL)')
    try:
        with db:
            yield db
    finally:
        db.close()


def prune(db):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    for table, limit in [('attacks', 1000), ('events', 5000)]:
        db.execute(f'DELETE FROM {table} WHERE timestamp < ?', (cutoff,))
        db.execute(f'DELETE FROM {table} WHERE id NOT IN (SELECT id FROM {table} ORDER BY timestamp DESC, id DESC LIMIT ?)', (limit,))


def save_attack(record):
    with connect() as db:
        db.execute('INSERT OR REPLACE INTO attacks VALUES (?, ?, ?)', (record['attack_id'], record['timestamp'], json.dumps(record)))
        prune(db)


def save_event(event):
    with connect() as db:
        cursor = db.execute('INSERT INTO events (timestamp, data) VALUES (?, ?)', (event['timestamp'], json.dumps(event)))
        event['id'] = cursor.lastrowid
        prune(db)
    return event


def attacks():
    with connect() as db:
        prune(db)
        return [json.loads(row['data']) for row in db.execute('SELECT data FROM attacks ORDER BY timestamp DESC, id DESC LIMIT 1000')]


def events():
    with connect() as db:
        prune(db)
        return [{**json.loads(row['data']), 'id': row['id']} for row in db.execute('SELECT id, data FROM events ORDER BY id DESC LIMIT 5000')]
