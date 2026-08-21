from __future__ import annotations

import argparse
import configparser
import datetime as dt
import os
import re
import secrets
import sqlite3
import ssl
import sys
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import unquote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import kmc_pb2


PROTOBUF_CONTENT_TYPE = "application/x-protobuf"
ROTATION_PATH = re.compile(r"^/api/v1/work-keys/([^/]+)/rotations$")


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    key_ttl_seconds: int
    database: Path
    master_key: Path
    ca_cert: Path
    server_cert: Path
    server_key: Path


def load_settings(config_path: Path) -> Settings:
    parser = configparser.ConfigParser()
    if not parser.read(config_path, encoding="utf-8"):
        raise RuntimeError(f"cannot read configuration: {config_path}")
    base = config_path.resolve().parent

    def resolve(value: str) -> Path:
        path = Path(value)
        return path if path.is_absolute() else (base / path).resolve()

    return Settings(
        host=parser.get("server", "host"),
        port=parser.getint("server", "port"),
        key_ttl_seconds=parser.getint("server", "key_ttl_seconds"),
        database=resolve(parser.get("server", "database")),
        master_key=resolve(parser.get("server", "master_key")),
        ca_cert=resolve(parser.get("tls", "ca_cert")),
        server_cert=resolve(parser.get("tls", "server_cert")),
        server_key=resolve(parser.get("tls", "server_key")),
    )


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_time(value: dt.datetime) -> str:
    return value.isoformat(timespec="seconds")


class KeyStore:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        settings.database.parent.mkdir(parents=True, exist_ok=True)
        settings.master_key.parent.mkdir(parents=True, exist_ok=True)
        self._master_key = self._load_or_create_master_key(settings.master_key)
        self._database = sqlite3.connect(settings.database, check_same_thread=False)
        self._database.row_factory = sqlite3.Row
        self._initialize_schema()

    @staticmethod
    def _load_or_create_master_key(path: Path) -> bytes:
        if path.exists():
            key = path.read_bytes()
            if len(key) != 32:
                raise RuntimeError(f"invalid KMS master key length: {path}")
            return key
        key = secrets.token_bytes(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(key)
        return key

    def _initialize_schema(self) -> None:
        self._database.executescript(
            """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS work_keys (
                key_id TEXT PRIMARY KEY,
                terminal_id TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                key_length INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                expires_at_unix INTEGER NOT NULL,
                encrypted_material BLOB NOT NULL,
                material_nonce BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_work_key_lookup
                ON work_keys(terminal_id, algorithm, key_length, status, expires_at_unix);
            CREATE TABLE IF NOT EXISTS terminal_counters (
                terminal_id TEXT PRIMARY KEY,
                next_value INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS request_records (
                terminal_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                request_fingerprint TEXT NOT NULL,
                key_id TEXT NOT NULL,
                PRIMARY KEY (terminal_id, request_id)
            );
            """
        )
        self._database.commit()

    def get_or_create(
        self, terminal_id: str, request_id: str, algorithm: str, key_length: int
    ) -> kmc_pb2.WorkKeyResponse:
        fingerprint = f"apply:{algorithm}:{key_length}"
        with self._lock:
            self._database.execute("BEGIN IMMEDIATE")
            try:
                replay = self._lookup_request(terminal_id, request_id, fingerprint)
                if replay is not None:
                    self._database.commit()
                    return self._response(replay, request_id)

                now_unix = int(utc_now().timestamp())
                row = self._database.execute(
                    """
                    SELECT * FROM work_keys
                    WHERE terminal_id = ? AND algorithm = ? AND key_length = ?
                      AND status = 'ACTIVE' AND expires_at_unix > ?
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (terminal_id, algorithm, key_length, now_unix),
                ).fetchone()
                if row is None:
                    row = self._insert_key(terminal_id, algorithm, key_length)
                self._record_request(terminal_id, request_id, "APPLY", fingerprint, row["key_id"])
                self._database.commit()
                return self._response(row, request_id)
            except Exception:
                self._database.rollback()
                raise

    def rotate(
        self,
        terminal_id: str,
        request_id: str,
        old_key_id: str,
        algorithm: str,
        key_length: int,
    ) -> kmc_pb2.WorkKeyResponse:
        fingerprint = f"rotate:{old_key_id}:{algorithm}:{key_length}"
        with self._lock:
            self._database.execute("BEGIN IMMEDIATE")
            try:
                replay = self._lookup_request(terminal_id, request_id, fingerprint)
                if replay is not None:
                    self._database.commit()
                    return self._response(replay, request_id)

                old_key = self._database.execute(
                    "SELECT * FROM work_keys WHERE key_id = ? AND terminal_id = ?",
                    (old_key_id, terminal_id),
                ).fetchone()
                if old_key is None:
                    raise KeyError("the current key does not belong to this terminal")
                if old_key["algorithm"] != algorithm or old_key["key_length"] != key_length:
                    raise ValueError("rotation parameters do not match the current key")

                self._database.execute(
                    "UPDATE work_keys SET status = 'TRANSITION' WHERE key_id = ?",
                    (old_key_id,),
                )
                row = self._insert_key(terminal_id, algorithm, key_length)
                self._record_request(
                    terminal_id, request_id, "ROTATE", fingerprint, row["key_id"]
                )
                self._database.commit()
                return self._response(row, request_id)
            except Exception:
                self._database.rollback()
                raise

    def _lookup_request(
        self, terminal_id: str, request_id: str, fingerprint: str
    ) -> sqlite3.Row | None:
        record = self._database.execute(
            "SELECT * FROM request_records WHERE terminal_id = ? AND request_id = ?",
            (terminal_id, request_id),
        ).fetchone()
        if record is None:
            return None
        if record["request_fingerprint"] != fingerprint:
            raise ValueError("X-Request-Id was reused with different request data")
        return self._database.execute(
            "SELECT * FROM work_keys WHERE key_id = ?", (record["key_id"],)
        ).fetchone()

    def _insert_key(
        self, terminal_id: str, algorithm: str, key_length: int
    ) -> sqlite3.Row:
        if algorithm != "AES" or key_length != 256:
            raise ValueError("this lab server only supports AES-256")
        key_id = self._next_key_id(terminal_id)
        material = secrets.token_bytes(key_length // 8)
        nonce = secrets.token_bytes(12)
        encrypted = AESGCM(self._master_key).encrypt(nonce, material, key_id.encode("utf-8"))
        created = utc_now()
        expires = created + dt.timedelta(seconds=self._settings.key_ttl_seconds)
        self._database.execute(
            """
            INSERT INTO work_keys(
                key_id, terminal_id, algorithm, key_length, status,
                created_at, expires_at, expires_at_unix,
                encrypted_material, material_nonce
            ) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?)
            """,
            (
                key_id,
                terminal_id,
                algorithm,
                key_length,
                iso_time(created),
                iso_time(expires),
                int(expires.timestamp()),
                encrypted,
                nonce,
            ),
        )
        return self._database.execute(
            "SELECT * FROM work_keys WHERE key_id = ?", (key_id,)
        ).fetchone()

    def _next_key_id(self, terminal_id: str) -> str:
        row = self._database.execute(
            "SELECT next_value FROM terminal_counters WHERE terminal_id = ?",
            (terminal_id,),
        ).fetchone()
        number = row["next_value"] if row else 1
        if row:
            self._database.execute(
                "UPDATE terminal_counters SET next_value = ? WHERE terminal_id = ?",
                (number + 1, terminal_id),
            )
        else:
            self._database.execute(
                "INSERT INTO terminal_counters(terminal_id, next_value) VALUES (?, ?)",
                (terminal_id, 2),
            )
        normalized = re.sub(r"[^A-Za-z0-9]+", "", terminal_id).lower() or "terminal"
        return f"wk_{normalized}_{number:06d}"

    def _record_request(
        self,
        terminal_id: str,
        request_id: str,
        operation: str,
        fingerprint: str,
        key_id: str,
    ) -> None:
        self._database.execute(
            """
            INSERT INTO request_records(
                terminal_id, request_id, operation, request_fingerprint, key_id
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (terminal_id, request_id, operation, fingerprint, key_id),
        )

    def _response(self, row: sqlite3.Row, request_id: str) -> kmc_pb2.WorkKeyResponse:
        material = AESGCM(self._master_key).decrypt(
            row["material_nonce"],
            row["encrypted_material"],
            row["key_id"].encode("utf-8"),
        )
        return kmc_pb2.WorkKeyResponse(
            request_id=request_id,
            key_id=row["key_id"],
            algorithm=row["algorithm"],
            key_length=row["key_length"],
            status=row["status"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            expires_at_unix=row["expires_at_unix"],
            key_material=material,
        )


class KmsHttpServer(HTTPServer):
    def __init__(self, address: tuple[str, int], store: KeyStore) -> None:
        super().__init__(address, KmsRequestHandler)
        self.store = store


class KmsRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "KMSLab/0.1"

    @property
    def key_store(self) -> KeyStore:
        return self.server.store  # type: ignore[attr-defined]

    def do_POST(self) -> None:
        try:
            terminal_id = self._terminal_identity()
            request_id = self.headers.get("X-Request-Id", "").strip()
            if not request_id:
                self._send_error(400, "MISSING_REQUEST_ID", "X-Request-Id is required")
                return
            if self.headers.get_content_type() != PROTOBUF_CONTENT_TYPE:
                self._send_error(415, "UNSUPPORTED_MEDIA_TYPE", PROTOBUF_CONTENT_TYPE)
                return
            body = self._read_body()

            if self.path == "/api/v1/work-keys":
                request = kmc_pb2.ApplyWorkKeyRequest()
                request.ParseFromString(body)
                response = self.key_store.get_or_create(
                    terminal_id, request_id, request.algorithm, request.key_length
                )
                self._send_protobuf(200, response.SerializeToString())
                return

            match = ROTATION_PATH.match(self.path)
            if match:
                request = kmc_pb2.RotateWorkKeyRequest()
                request.ParseFromString(body)
                response = self.key_store.rotate(
                    terminal_id,
                    request_id,
                    unquote(match.group(1)),
                    request.algorithm,
                    request.key_length,
                )
                self._send_protobuf(200, response.SerializeToString())
                return
            self._send_error(404, "NOT_FOUND", "unknown endpoint")
        except KeyError as error:
            self._send_error(404, "KEY_NOT_FOUND", str(error))
        except ValueError as error:
            self._send_error(409, "CONFLICT", str(error))
        except Exception as error:
            self._send_error(500, "INTERNAL_ERROR", str(error))

    def _terminal_identity(self) -> str:
        certificate = self.connection.getpeercert()  # type: ignore[attr-defined]
        for relative_name in certificate.get("subject", ()):
            for key, value in relative_name:
                if key == "commonName":
                    return value
        raise ValueError("client certificate has no common name")

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 1024 * 1024:
            raise ValueError("invalid request body length")
        return self.rfile.read(length)

    def _send_protobuf(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", PROTOBUF_CONTENT_TYPE)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_error(self, status: int, code: str, message: str) -> None:
        payload = kmc_pb2.ErrorResponse(code=code, message=message).SerializeToString()
        self._send_protobuf(status, payload)

    def log_message(self, format_string: str, *args: object) -> None:
        print(f"[KMS] {self.client_address[0]} - {format_string % args}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Minimal mTLS protobuf KMS")
    parser.add_argument(
        "--config", type=Path, default=Path(__file__).with_name("config.ini")
    )
    arguments = parser.parse_args()
    settings = load_settings(arguments.config)
    store = KeyStore(settings)
    server = KmsHttpServer((settings.host, settings.port), store)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(settings.server_cert, settings.server_key)
    context.load_verify_locations(settings.ca_cert)
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"[KMS] listening on https://{settings.host}:{settings.port}")
    print(f"[KMS] database: {settings.database}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[KMS] stopping")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
