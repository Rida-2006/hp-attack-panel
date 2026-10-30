import json
import sqlite3
import time
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
    db.execute('CREATE TABLE IF NOT EXISTS execution_slot (slot INTEGER PRIMARY KEY CHECK(slot=1), attack_id TEXT NOT NULL, expires REAL NOT NULL)')
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


def expire_execution(db):
    """Called inside an immediate transaction so expiry cannot delete a new claim."""
    clock = time.time()
    expired = db.execute('SELECT attack_id FROM execution_slot WHERE expires <= ?', (clock,)).fetchall()
    for row in expired:
        record = db.execute('SELECT data FROM attacks WHERE id=?', (row['attack_id'],)).fetchone()
        if record:
            data = json.loads(record['data'])
            if data['status'] == 'running':
                data.update(status='interrupted', outcome='FAILED', success=False, error='Execution lease expired after backend interruption')
                db.execute('UPDATE attacks SET data=? WHERE id=?', (json.dumps(data), row['attack_id']))
    db.execute('DELETE FROM execution_slot WHERE expires <= ?', (clock,))


def claim_execution(attack_id, seconds):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        expire_execution(db)
        cursor = db.execute('INSERT OR IGNORE INTO execution_slot VALUES (1, ?, ?)', (attack_id, time.time() + seconds))
        return cursor.rowcount == 1


def release_execution(attack_id):
    with connect() as db:
        db.execute('DELETE FROM execution_slot WHERE attack_id = ?', (attack_id,))


def active_execution():
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        expire_execution(db)
        row = db.execute('SELECT attack_id FROM execution_slot WHERE slot=1').fetchone()
        if row:
            record = db.execute('SELECT data FROM attacks WHERE id=?', (row['attack_id'],)).fetchone()
            return json.loads(record['data']) if record else {'attack_id': row['attack_id'], 'status': 'running', 'operation': 'vpn' if row['attack_id'].startswith('VPN-') else 'attack'}
    return None


def recover_executions():
    """Startup recovery must not race a different process acquiring its lease."""
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        expire_execution(db)
        active = db.execute('SELECT attack_id FROM execution_slot WHERE slot=1').fetchone()
        for row in db.execute('SELECT id, data FROM attacks').fetchall():
            data = json.loads(row['data'])
            if data['status'] == 'running' and (not active or row['id'] != active['attack_id']):
                data.update(status='interrupted', outcome='FAILED', success=False, error='Backend restarted before completion')
                db.execute('UPDATE attacks SET data=? WHERE id=?', (json.dumps(data), row['id']))
