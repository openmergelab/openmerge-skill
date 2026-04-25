# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "cryptography>=41.0",
#   "requests>=2.28",
#   "h3>=4.0",
# ]
# ///
"""Merge CLI — upload signal or check matches."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import struct
import sys
import threading
import time
import uuid
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import h3
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_BROKER_URL = "http://localhost:8080"

ALLOWED_SIGNAL_FIELDS = frozenset(
    {
        "anonymousId",
        "locationH3",
        "gender",
        "seeking",
        "age",
        "ageRange",
        "publicKey",
        "encryptedVector",
        "discordIdHash",
        "pushToken",
    }
)

# Ordinal maps for categorical → float encoding
_COMMUNICATION_STYLE_MAP: dict[str, float] = {
    "direct": 0.0,
    "thoughtful": 0.33,
    "playful": 0.66,
    "reserved": 1.0,
}

_VIBE_MAP: dict[str, float] = {
    "serious": 0.0,
    "casual": 0.33,
    "adventurous": 0.66,
    "chill": 1.0,
}

# ---------------------------------------------------------------------------
# Output helpers  (T003 / T004)
# ---------------------------------------------------------------------------


def output_success(data: dict) -> None:
    """Write structured JSON success to stdout and exit 0."""
    json.dump({"status": "ok", **data}, sys.stdout)
    sys.stdout.write("\n")
    sys.stdout.flush()


def output_error(message: str, code: int) -> None:
    """Write structured JSON error to stdout, diagnostic to stderr, then exit."""
    json.dump({"status": "error", "message": message, "code": code}, sys.stdout)
    sys.stdout.write("\n")
    sys.stdout.flush()
    log(f"ERROR: {message}")
    sys.exit(code)


def log(message: str) -> None:
    """Write diagnostic message to stderr only — never to stdout."""
    print(message, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# File loading  (T005)
# ---------------------------------------------------------------------------


def load_json(path: str) -> dict:
    """Read and parse a JSON file.  Exit 1 if missing or malformed."""
    p = Path(path)
    if not p.exists():
        output_error(f"{p.name} not found — run setup first", 1)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        output_error(f"Failed to read {p.name}: {exc}", 1)
    return {}  # unreachable — satisfies type checker


# ---------------------------------------------------------------------------
# Validation  (T006)
# ---------------------------------------------------------------------------


def validate_profile(profile: dict) -> None:
    """Validate profile readiness per V-001 through V-006.  Exit 1 on failure."""
    # if not profile.get("ageVerified"):
    #     output_error("Age verification required before uploading signal", 1)
    if not profile.get("setupComplete"):
        output_error("Setup incomplete — finish onboarding first", 1)
    if not profile.get("locationH3"):
        output_error("Location required — set your location first", 1)
    if not profile.get("discordId"):
        output_error("Discord ID required — link your Discord account", 1)


# ---------------------------------------------------------------------------
# Key management  (T007)
# ---------------------------------------------------------------------------


def generate_or_load_key(key_path: str = "merge_key.bin") -> bytes:
    """Generate a 32-byte AES key or load existing.  Set 0600 permissions."""
    p = Path(key_path)
    if p.exists():
        log("Loading existing encryption key")
        return p.read_bytes()
    log("Generating new encryption key")
    key = os.urandom(32)
    p.write_bytes(key)
    os.chmod(p, 0o600)
    return key


# ---------------------------------------------------------------------------
# Anonymous ID  (T008)
# ---------------------------------------------------------------------------


def get_or_create_anonymous_id(id_path: str = "anonymous_id") -> str:
    """Generate a UUID v4 or load existing.  Persist to file."""
    p = Path(id_path)
    if p.exists():
        return p.read_text(encoding="utf-8").strip()
    anon_id = str(uuid.uuid4())
    p.write_text(anon_id, encoding="utf-8")
    log(f"Generated anonymous ID: {anon_id}")
    return anon_id


# ---------------------------------------------------------------------------
# Preference vector  (T009 / T010)
# ---------------------------------------------------------------------------


def _hash_categorical(items: list | str, seed: int = 0) -> float:
    """Hash categorical values to a stable float in [0, 1]."""
    if isinstance(items, str):
        items = [items]
    if not items:
        return 0.0
    raw = "|".join(sorted(str(i) for i in items))
    h = hashlib.sha256(f"{seed}:{raw}".encode()).digest()
    return int.from_bytes(h[:4], "big") / 0xFFFFFFFF


def build_preference_vector(preferences: dict) -> list[float]:
    """Map 10 preference dimensions to a float array per data-model.md."""
    lifestyle = preferences.get("lifestyleDealbreakers", {})
    return [
        _hash_categorical(preferences.get("values", []), seed=0),
        _hash_categorical(preferences.get("dealbreakers", []), seed=1),
        _COMMUNICATION_STYLE_MAP.get(
            preferences.get("communicationStyle", ""), 0.5
        ),
        _VIBE_MAP.get(preferences.get("lookingForVibe", ""), 0.5),
        _normalize_interest_weights(preferences.get("interestWeights", {})),
        1.0 if lifestyle.get("smoking") else 0.0,
        1.0 if lifestyle.get("kids") else 0.0,
        1.0 if lifestyle.get("drinking") else 0.0,
        _hash_categorical(preferences.get("preferredPersonality", []), seed=8),
        _hash_categorical(preferences.get("avoidPersonality", []), seed=9),
    ]


def _normalize_interest_weights(weights: dict) -> float:
    """Normalize interest weights to a single composite float in [0, 1]."""
    if not weights:
        return 0.0
    vals = [float(v) for v in weights.values()]
    total = sum(vals)
    if total == 0:
        return 0.0
    return min(sum(v / total for v in vals) / len(vals), 1.0)


def vector_to_bytes(vector: list[float]) -> bytes:
    """Encode a 10-float vector as a 40-byte struct."""
    return struct.pack("10f", *vector)


# ---------------------------------------------------------------------------
# Encryption  (T011)
# ---------------------------------------------------------------------------


def encrypt_vector(key: bytes, vector_bytes: bytes) -> str:
    """AES-256-GCM encrypt, return base64-encoded nonce+ciphertext."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, vector_bytes, None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


# ---------------------------------------------------------------------------
# Discord ID hash  (T012)
# ---------------------------------------------------------------------------


def hash_discord_id(discord_id: str) -> str:
    """SHA-256 hash of Discord ID, returned as 64-char hex string."""
    return hashlib.sha256(discord_id.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Discord OAuth  (auth)
# ---------------------------------------------------------------------------

DISCORD_OAUTH_BASE = "https://discord.com/api/v10"
DISCORD_OAUTH_AUTHORIZE = "https://discord.com/oauth2/authorize"
DISCORD_REDIRECT_PORT = 9876
DISCORD_REDIRECT_URI = f"http://localhost:{DISCORD_REDIRECT_PORT}/callback"


def _open_incognito(url: str) -> None:
    """Open URL in an incognito/private window. Falls back to default browser."""
    if sys.platform == "darwin":
        # Try Chrome incognito
        try:
            subprocess.Popen(
                ["open", "-na", "Google Chrome", "--args", "--incognito", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        except FileNotFoundError:
            pass
        # Try Firefox private
        try:
            subprocess.Popen(
                ["open", "-na", "Firefox", "--args", "-private-window", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        except FileNotFoundError:
            pass
    # Fallback: default browser (no incognito)
    webbrowser.open(url)


class _OAuthCallbackHandler(BaseHTTPRequestHandler):
    """Handles the OAuth redirect, extracts the authorization code."""

    code: str | None = None
    error: str | None = None
    error_description: str | None = None

    def do_GET(self) -> None:
        qs = parse_qs(urlparse(self.path).query)
        code = qs.get("code", [None])[0]
        error = qs.get("error", [None])[0]
        error_desc = qs.get("error_description", [None])[0]

        if code:
            _OAuthCallbackHandler.code = code
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body><h2>Done &#8212; you can close this tab.</h2></body></html>"
            )
        elif error:
            _OAuthCallbackHandler.error = error
            _OAuthCallbackHandler.error_description = error_desc
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            msg = error_desc or error
            self.wfile.write(
                f"<html><body><h2>Login failed: {msg}</h2>"
                f"<p>You can close this tab.</p></body></html>".encode()
            )
        else:
            self.send_response(400)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h2>Error: no code received.</h2></body></html>")

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # silence request logs


def _exchange_code_via_broker(code: str, broker_url: str) -> dict:
    """Send OAuth code to broker for server-side exchange. Secret never leaves the broker."""
    url = f"{broker_url.rstrip('/')}/auth/discord"
    try:
        log(f"POST {url}")
        resp = requests.post(
            url,
            json={"code": code, "redirectUri": DISCORD_REDIRECT_URI},
            headers={"Content-Type": "application/json"},
            timeout=(5, 15),
        )
    except requests.ConnectionError:
        output_error("Cannot reach broker — check your connection", 3)
    except requests.Timeout:
        output_error("Cannot reach broker — connection timed out", 3)
    except requests.RequestException as exc:
        output_error(f"Cannot reach broker — {exc}", 3)

    if resp.status_code == 200:
        return resp.json()
    if resp.status_code == 503:
        output_error("Discord OAuth not configured on the broker", 3)
    if resp.status_code == 502:
        output_error("Broker could not reach Discord — try again", 3)
    output_error(f"Broker error ({resp.status_code}) — try again later", 4)
    return {}  # unreachable


def _mark_age_unverified(profile_path: str) -> None:
    """Record that Discord age verification was not completed."""
    p = Path(profile_path)
    profile = json.loads(p.read_text(encoding="utf-8"))
    profile["ageVerified"] = False
    profile["verificationProvider"] = "discord"
    profile["updatedAt"] = datetime.now(timezone.utc).isoformat()
    p.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    log(f"Marked age unverified in {p.name}")


def _update_profile_discord(profile_path: str, discord_id: str, discord_handle: str) -> None:
    """Write discordId and discordHandle into profile.json."""
    p = Path(profile_path)
    profile = json.loads(p.read_text(encoding="utf-8"))
    profile["discordId"] = discord_id
    profile["discordHandle"] = discord_handle
    profile["ageVerified"] = True
    profile["verifiedAt"] = datetime.now(timezone.utc).isoformat()
    profile["verificationProvider"] = "discord"
    profile["updatedAt"] = datetime.now(timezone.utc).isoformat()
    p.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    log(f"Updated {p.name} with Discord identity")


# ---------------------------------------------------------------------------
# Signal payload  (T013 + T017 allowlist)
# ---------------------------------------------------------------------------


def build_signal_payload(
    profile: dict,
    encrypted_b64: str,
    key: bytes,
    anonymous_id: str,
) -> dict:
    """Construct anonymous signal payload — only allowed fields."""
    # Normalize seeking: profile may use long-form ("male", "female", "nonbinary")
    _seeking_map = {"male": "M", "female": "F", "nonbinary": "NB", "non-binary": "NB"}
    raw_seeking = profile.get("seeking", "any")
    seeking = _seeking_map.get(raw_seeking.lower(), raw_seeking)

    # Normalize gender: profile uses "Woman", "Man", "Non-binary"
    _gender_map = {"woman": "F", "man": "M", "non-binary": "NB", "male": "M", "female": "F", "nonbinary": "NB"}
    raw_gender = profile.get("gender")
    if raw_gender is None:
        raise RuntimeError("Profile must include 'gender' for signal upload")
    gender = _gender_map.get(raw_gender.lower(), raw_gender)

    age_range = profile.get("ageRange", [18, 99])
    user_age = profile.get("age")
    if user_age is None:
        raise RuntimeError("Profile must include 'age' for signal upload")
    # Broker requires resolution 9; profile may store coarser resolution
    raw_h3 = profile["locationH3"]
    if h3.get_resolution(raw_h3) != 9:
        raw_h3 = h3.cell_to_center_child(raw_h3, 9)

    payload = {
        "anonymousId": anonymous_id,
        "locationH3": raw_h3,
        "gender": gender,
        "seeking": seeking,
        "age": int(user_age),
        "ageRange": {"min": age_range[0], "max": age_range[1]},
        "publicKey": hashlib.sha256(key).hexdigest(),
        "encryptedVector": encrypted_b64,
        "discordIdHash": hash_discord_id(profile["discordId"]),
        "pushToken": profile.get("pushToken"),
    }
    # T017 — privacy allowlist enforcement
    extra = set(payload.keys()) - ALLOWED_SIGNAL_FIELDS
    if extra:
        raise RuntimeError(f"Signal payload contains disallowed fields: {extra}")
    return payload


# ---------------------------------------------------------------------------
# Session token  (T014)
# ---------------------------------------------------------------------------


def get_session_token() -> str:
    """Read Bearer token from env or .merge_session file.  Exit 2 if missing."""
    token = os.environ.get("MERGE_SESSION_TOKEN", "").strip()
    if token:
        return token
    session_path = Path(".merge_session")
    if session_path.exists():
        token = session_path.read_text(encoding="utf-8").strip()
        if token:
            return token
    output_error(
        "Session token not found — set MERGE_SESSION_TOKEN or create .merge_session",
        2,
    )
    return ""  # unreachable


# ---------------------------------------------------------------------------
# Upload  (T015)
# ---------------------------------------------------------------------------


def upload_signal(payload: dict, token: str, broker_url: str) -> dict:
    """PUT signal to broker (upsert semantics).  Returns response data."""
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    url = f"{broker_url.rstrip('/')}/signal"

    try:
        log(f"PUT {url}")
        resp = requests.put(
            url,
            json=payload,
            headers=headers,
            timeout=(5, 10),
        )
    except requests.ConnectionError:
        output_error("Cannot reach broker — check your connection", 3)
    except requests.Timeout:
        output_error("Cannot reach broker — connection timed out", 3)
    except requests.RequestException as exc:
        output_error(f"Cannot reach broker — {exc}", 3)

    if resp.status_code == 200:
        return resp.json()
    if resp.status_code == 401:
        output_error("Authentication failed — re-authenticate first", 2)
    if resp.status_code == 429:
        output_error("Too many requests — try again later", 4)
    try:
        body = resp.json()
        detail = body.get("message", "") or body.get("error", "")
        fields = body.get("fields", [])
        msg = f"Broker error ({resp.status_code}): {detail}"
        if fields:
            msg += f" — fields: {', '.join(fields)}"
    except Exception:
        msg = f"Broker error ({resp.status_code}) — try again later"
    output_error(msg, 4)
    return {}  # unreachable


def fetch_matches(token: str, broker_url: str) -> dict:
    """GET /matches from broker.  Returns envelope {matches, signalActive}."""
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{broker_url.rstrip('/')}/matches"

    try:
        log(f"GET {url}")
        resp = requests.get(url, headers=headers, timeout=(5, 10))
    except requests.ConnectionError:
        output_error("Cannot reach broker — check your connection", 3)
    except requests.Timeout:
        output_error("Cannot reach broker — connection timed out", 3)
    except requests.RequestException as exc:
        output_error(f"Cannot reach broker — {exc}", 3)

    if resp.status_code == 200:
        return resp.json()
    if resp.status_code == 401:
        output_error("Authentication failed — re-authenticate first", 2)
    if resp.status_code == 429:
        output_error("Too many requests — try again later", 4)
    output_error(f"Broker error ({resp.status_code}) — try again later", 4)
    return {}  # unreachable


def delete_signal(token: str, broker_url: str) -> dict:
    """DELETE /signal from broker.  Removes the user's active signal."""
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{broker_url.rstrip('/')}/signal"

    try:
        log(f"DELETE {url}")
        resp = requests.delete(url, headers=headers, timeout=(5, 10))
    except requests.ConnectionError:
        output_error("Cannot reach broker — check your connection", 3)
    except requests.Timeout:
        output_error("Cannot reach broker — connection timed out", 3)
    except requests.RequestException as exc:
        output_error(f"Cannot reach broker — {exc}", 3)

    if resp.status_code == 200:
        return resp.json()
    if resp.status_code == 401:
        output_error("Authentication failed — re-authenticate first", 2)
    if resp.status_code == 429:
        output_error("Too many requests — try again later", 4)
    output_error(f"Broker error ({resp.status_code}) — try again later", 4)
    return {}  # unreachable


def delete_account(token: str, broker_url: str) -> dict:
    """DELETE /account from broker.  Removes the user's account entirely."""
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{broker_url.rstrip('/')}/account"

    try:
        log(f"DELETE {url}")
        resp = requests.delete(url, headers=headers, timeout=(5, 10))
    except requests.ConnectionError:
        output_error("Cannot reach broker — check your connection", 3)
    except requests.Timeout:
        output_error("Cannot reach broker — connection timed out", 3)
    except requests.RequestException as exc:
        output_error(f"Cannot reach broker — {exc}", 3)

    if resp.status_code == 200:
        return resp.json()
    if resp.status_code == 401:
        output_error("Authentication failed — re-authenticate first", 2)
    if resp.status_code == 429:
        output_error("Too many requests — try again later", 4)
    output_error(f"Broker error ({resp.status_code}) — try again later", 4)
    return {}  # unreachable


# ---------------------------------------------------------------------------
# Signal record  (T018)
# ---------------------------------------------------------------------------


def save_signal_record(
    response_data: dict,
    anonymous_id: str,
    output_path: str = "assets/signal.json",
) -> None:
    """Write local signal record after successful upload."""
    record = {
        "signalId": response_data["signalId"],
        "expiresAt": response_data["expiresAt"],
        "uploadedAt": datetime.now(timezone.utc).isoformat(),
        "anonymousId": anonymous_id,
    }
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    log(f"Signal record saved to {output_path}")


# ---------------------------------------------------------------------------
# CLI  (T002 + T020 + T021)
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="merge.py",
        description="Merge CLI — upload signal or check matches.",
        epilog=(
            "examples:\n"
            "  uv run scripts/merge.py upload\n"
            "  uv run scripts/merge.py upload --profile path/to/profile.json\n"
            "  uv run scripts/merge.py matches\n"
            "  uv run scripts/merge.py matches --broker-url https://broker.example.com\n"
            "\n"
            "exit codes:\n"
            "  0  success\n"
            "  1  validation error — missing file or incomplete profile\n"
            "  2  auth error — missing or invalid session token\n"
            "  3  network error — broker unreachable\n"
            "  4  broker error — 4xx/5xx response\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--broker-url",
        default=os.environ.get("MERGE_BROKER_URL", DEFAULT_BROKER_URL),
        help=(
            "Broker URL (default: MERGE_BROKER_URL env var, "
            f"or {DEFAULT_BROKER_URL})"
        ),
    )
    sub = parser.add_subparsers(dest="command")

    # upload subcommand
    upload_p = sub.add_parser("upload", help="Encrypt and upload signal")
    upload_p.add_argument(
        "--profile",
        default="assets/profile.json",
        help="Path to profile JSON (default: assets/profile.json)",
    )
    upload_p.add_argument(
        "--preferences",
        default="assets/preferences.json",
        help="Path to preferences JSON (default: assets/preferences.json)",
    )

    # matches subcommand
    sub.add_parser("matches", help="Fetch current matches from broker")

    # pause subcommand
    sub.add_parser("pause", help="Remove signal and pause matching")

    # delete subcommand
    sub.add_parser("delete", help="Delete account and all local data")

    # auth subcommand (Discord OAuth → broker session in one step)
    auth_p = sub.add_parser("auth", help="Authenticate via Discord OAuth")
    auth_p.add_argument(
        "--profile",
        default="assets/profile.json",
        help="Path to profile JSON (default: assets/profile.json)",
    )
    auth_p.add_argument(
        "--client-id",
        default=os.environ.get("DISCORD_CLIENT_ID", ""),
        help="Discord OAuth client ID (default: DISCORD_CLIENT_ID env var)",
    )

    return parser


# ---------------------------------------------------------------------------
# Main  (T016 + T019)
# ---------------------------------------------------------------------------


def cmd_upload(args: argparse.Namespace) -> None:
    """Upload subcommand: validate → encrypt → upload → save."""
    log("Loading profile and preferences…")
    profile = load_json(args.profile)
    _preferences = load_json(args.preferences)
    validate_profile(profile)

    key = generate_or_load_key()
    anonymous_id = get_or_create_anonymous_id()

    log("Building preference vector…")
    vector = build_preference_vector(_preferences)
    vector_bytes = vector_to_bytes(vector)
    encrypted_b64 = encrypt_vector(key, vector_bytes)

    log("Constructing signal payload…")
    payload = build_signal_payload(profile, encrypted_b64, key, anonymous_id)

    token = get_session_token()
    log("Uploading signal…")
    response_data = upload_signal(payload, token, args.broker_url)

    save_signal_record(response_data, anonymous_id)

    output_success(
        {
            "signalId": response_data["signalId"],
            "expiresAt": response_data["expiresAt"],
        }
    )


def cmd_matches(args: argparse.Namespace) -> None:
    """Matches subcommand: fetch and display current matches."""
    token = get_session_token()
    log("Fetching matches…")
    data = fetch_matches(token, args.broker_url)

    output_success(
        {
            "matches": data.get("matches", []),
            "signalActive": data.get("signalActive", False),
        }
    )

def cmd_pause(args: argparse.Namespace) -> None:
    """Pause subcommand: remove signal from broker."""
    token = get_session_token()
    log("Removing signal\u2026")
    delete_signal(token, args.broker_url)

    # Remove local signal record
    signal_path = Path("assets/signal.json")
    if signal_path.exists():
        signal_path.unlink()
        log("Removed local signal record")

    output_success({"removed": True})


def cmd_delete(args: argparse.Namespace) -> None:
    """Delete subcommand: remove broker account and local files."""
    token = get_session_token()
    log("Deleting account\u2026")
    delete_account(token, args.broker_url)

    # Remove local files
    for f in ["assets/profile.json", "assets/preferences.json", "assets/signal.json",
              ".merge_session", "merge_key.bin", "anonymous_id"]:
        p = Path(f)
        if p.exists():
            p.unlink()
            log(f"Removed {f}")

    output_success({"deleted": True})


def cmd_auth(args: argparse.Namespace) -> None:
    """Auth subcommand: Discord OAuth via broker."""
    client_id = args.client_id

    if not client_id:
        output_error("Discord client ID required — set DISCORD_CLIENT_ID or use --client-id", 1)

    # Start local callback server
    _OAuthCallbackHandler.code = None
    _OAuthCallbackHandler.error = None
    _OAuthCallbackHandler.error_description = None
    server = HTTPServer(("localhost", DISCORD_REDIRECT_PORT), _OAuthCallbackHandler)
    server.timeout = 2  # handle_request returns every 2 s so we can check

    def _serve_until_done(timeout_secs: int = 120) -> None:
        deadline = time.monotonic() + timeout_secs
        while time.monotonic() < deadline:
            server.handle_request()
            if _OAuthCallbackHandler.code or _OAuthCallbackHandler.error:
                return

    server_thread = threading.Thread(target=_serve_until_done, daemon=True)
    server_thread.start()

    # Open browser to Discord authorize URL
    auth_url = (
        f"{DISCORD_OAUTH_AUTHORIZE}"
        f"?client_id={client_id}"
        f"&redirect_uri={DISCORD_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=identify"
    )
    log("Opening browser for Discord login…")
    log(f"Auth URL: {auth_url}")
    _open_incognito(auth_url)

    # Wait for callback (server thread exits on code, error, or 120 s timeout)
    server_thread.join(timeout=125)
    server.server_close()

    # Check for OAuth error (e.g. age verification, access_denied)
    if _OAuthCallbackHandler.error:
        desc = _OAuthCallbackHandler.error_description or _OAuthCallbackHandler.error
        _mark_age_unverified(args.profile)
        output_error(f"Discord denied login: {desc}", 2)

    code = _OAuthCallbackHandler.code
    if not code:
        _mark_age_unverified(args.profile)
        output_error("Discord login timed out — complete the login in your browser within 30 seconds", 2)

    # Send code to broker — broker exchanges it server-side (holds the secret)
    log("Sending authorization code to broker…")
    data = _exchange_code_via_broker(code, args.broker_url)

    discord_id = data.get("discordId", "")
    discord_handle = data.get("discordHandle", "")
    if not discord_id:
        output_error("Broker returned no Discord ID", 3)

    # Update profile
    _update_profile_discord(args.profile, discord_id, discord_handle)

    # Save session token from broker response
    token = data.get("token", "")
    if token:
        session_path = Path(".merge_session")
        session_path.write_text(token + "\n", encoding="utf-8")
        os.chmod(session_path, 0o600)
        log("Session token saved to .merge_session")

    # Persist broker-resolved anonymous ID
    resolved_id = data.get("anonymousId", "")
    if resolved_id:
        Path("anonymous_id").write_text(resolved_id, encoding="utf-8")

    result: dict = {
        "discordId": discord_id,
        "discordHandle": discord_handle,
        "anonymousId": resolved_id,
    }
    if data.get("serverInvite"):
        result["serverInvite"] = data["serverInvite"]

    output_success(result)


def main() -> None:
    """Entry point: dispatch to upload or matches subcommand."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "upload":
        cmd_upload(args)
    elif args.command == "matches":
        cmd_matches(args)
    elif args.command == "auth":
        cmd_auth(args)
    elif args.command == "pause":
        cmd_pause(args)
    elif args.command == "delete":
        cmd_delete(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
