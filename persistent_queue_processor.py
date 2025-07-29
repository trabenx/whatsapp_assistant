import sqlite3
import threading
import json
import time
import os
import logging
from datetime import datetime, timedelta
from typing import Callable, Dict


class PersistentQueueProcessor:
    def __init__(self, db_file: str, process_callback: Callable[[Dict], None], archive_dir='archive', failed_dir='failed', cleanup_interval_sec=3600):
        self.db_file = db_file
        self.process_callback = process_callback
        self.archive_dir = archive_dir
        self.failed_dir = failed_dir
        self.cleanup_interval = cleanup_interval_sec

        os.makedirs(self.archive_dir, exist_ok=True)
        os.makedirs(self.failed_dir, exist_ok=True)

        self._setup_db()
        self._load_unfinished_items()

        self.stop_event = threading.Event()

        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)

        self.worker_thread.start()
        self.cleanup_thread.start()

    def _setup_db(self):
        self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload BLOB  NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('queued', 'processing', 'processed', 'failed')),
                retries INTEGER DEFAULT 0,
                processed_at DATETIME
            )
        ''')
        self.conn.commit()

    def append(self, payload):
        conn = sqlite3.connect(self.db_file)
        try:
            conn.execute(
                'INSERT INTO queue (payload, status, retries) VALUES (?, ?, ?)',
                (payload, 'queued', 0)
            )
            conn.commit()
        finally:
            conn.close()


    def _load_unfinished_items(self):
        with self.conn:
            self.conn.execute("UPDATE queue SET status = 'queued' WHERE status = 'processing'")

    def _worker(self):
        while not self.stop_event.is_set():
            row = None
            with self.conn:
                cursor = self.conn.execute(
                    "SELECT id, payload, retries FROM queue WHERE status = 'queued' ORDER BY id LIMIT 1"
                )
                row = cursor.fetchone()

            if row:
                item_id, payload, retries = row
                try:
                    with self.conn:
                        self.conn.execute(
                            "UPDATE queue SET status = 'processing' WHERE id = ?",
                            (item_id,)
                        )
                    process_result = self.process_callback(payload)
                    self._archive_processed(payload, process_result[0], process_result[1])
                    # Remove from main queue
                    with self.conn:
                        self.conn.execute("DELETE FROM queue WHERE id = ?", (item_id,))

                except Exception as e:
                    logging.error(f"[ERROR] Failed to process id={item_id}: {e}", exc_info=True)
                    retries += 1

                    if retries < 3:
                        with self.conn:
                            self.conn.execute(
                                "UPDATE queue SET status = 'queued', retries = ? WHERE id = ?",
                                (retries, item_id)
                            )
                    else:
                        try:
                            # First, try to decode from byte array to string:
                            payload_str = payload.decode('utf-8')
                            try:
                                # Check if valid json:
                                payload_json = json.loads(payload_str)

                                # If successful, format and save as .json
                                filename = os.path.join(
                                    self.failed_dir,
                                    f"{datetime.utcnow().isoformat(timespec='seconds').replace(':','-')}_failed_id_{item_id}.json"
                                )
                                with open(filename, 'w') as f:
                                    json.dump(payload_json, f, indent=2)
                            except json.JSONDecodeError:
                                # If it's not valid JSON, save as plain .txt                          
                                filename = os.path.join(
                                    self.failed_dir,
                                    f"{datetime.utcnow().isoformat(timespec='seconds').replace(':', '-')}_failed_id_{item_id}.txt"
                                )
                                with open(filename, 'w', encoding='utf-8') as f:
                                    f.write(payload_str)
                        except UnicodeDecodeError as e:
                            # If it's not valid string, save as binary file .bin
                            filename = os.path.join(
                                self.failed_dir,
                                f"{datetime.utcnow().isoformat(timespec='seconds').replace(':', '-')}_failed_id_{item_id}.bin"
                            )
                            with open(filename, 'wb') as f:
                                f.write(payload)
                        with self.conn:
                            self.conn.execute("DELETE FROM queue WHERE id = ?", (item_id,))
            else:
                time.sleep(1)

    def _cleanup_worker(self):
        while not self.stop_event.is_set():
            try:
                cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()
                with self.conn:
                    self.conn.execute(
                        "DELETE FROM queue WHERE status = 'processed' AND processed_at < ?",
                        (cutoff,)
                    )
            except Exception as e:
                print(f"[ERROR] During cleanup: {e}")
            time.sleep(self.cleanup_interval)

    def _archive_processed(self, payload, table_prefix, extra_data):
        date_str = datetime.utcnow().date().isoformat()
        db_filename = os.path.join(self.archive_dir, f"processed_{date_str}.db")
        conn = sqlite3.connect(db_filename)
        conn.execute(f'''
            CREATE TABLE IF NOT EXISTS {table_prefix}_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                processed_at DATETIME NOT NULL,
                payload BLOB NOT NULL,
                extra_data TEXT
            )
        ''')
        conn.execute(
            f'INSERT INTO {table_prefix}_items (processed_at, payload, extra_data) VALUES (?, ?, ?)',
            (datetime.utcnow().isoformat(), payload, extra_data)
        )
        conn.commit()
        conn.close()        

    def stop(self):
        self.stop_event.set()
        self.worker_thread.join()
        self.cleanup_thread.join()
        self.conn.close()
