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
import struct
import sys
import time
import uuid
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

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
        "telegramIdHash",
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
    if not profile.get("telegramId"):
        output_error("Telegram ID required — link your Telegram account", 1)


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
# Telegram ID hash  (T012)
# ---------------------------------------------------------------------------


def hash_telegram_id(telegram_id: str) -> str:
    """SHA-256 hash of Telegram ID, returned as 64-char hex string."""
    return hashlib.sha256(str(telegram_id).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Telegram bot deep-link auth
# ---------------------------------------------------------------------------

TELEGRAM_BOT_API = "https://api.telegram.org"
TELEGRAM_AUTH_URL = "https://oauth.telegram.org/auth"


def _mark_age_unverified(profile_path: str) -> None:
    """Record that Telegram age verification was not completed."""
    p = Path(profile_path)
    profile = json.loads(p.read_text(encoding="utf-8"))
    profile["ageVerified"] = False
    profile["verificationProvider"] = "telegram"
    profile["updatedAt"] = datetime.now(timezone.utc).isoformat()
    p.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    log(f"Marked age unverified in {p.name}")


def _update_profile_telegram(profile_path: str, telegram_id: str, telegram_handle: str) -> None:
    """Write telegramId and telegramHandle into profile.json."""
    p = Path(profile_path)
    profile = json.loads(p.read_text(encoding="utf-8"))
    profile["telegramId"] = telegram_id
    profile["telegramHandle"] = telegram_handle
    profile["ageVerified"] = True
    profile["verifiedAt"] = datetime.now(timezone.utc).isoformat()
    profile["verificationProvider"] = "telegram"
    profile["updatedAt"] = datetime.now(timezone.utc).isoformat()
    p.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    log(f"Updated {p.name} with Telegram identity")


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
    _seeking_map = {"male": "M", "female": "F", "nonbinary": "NB", "non-binary": "NB", "woman": "F", "man": "M", "women": "F", "men": "M"}
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
        "telegramIdHash": hash_telegram_id(profile["telegramId"]),
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

    # card subcommand
    card_p = sub.add_parser("card", help="Build introduction card from local profile")
    card_p.add_argument(
        "--profile",
        default="assets/profile.json",
        help="Path to profile JSON (default: assets/profile.json)",
    )
    card_p.add_argument(
        "--output",
        default="assets/card.txt",
        help="Path to write card file (default: assets/card.txt)",
    )

    # delete subcommand
    sub.add_parser("delete", help="Delete account and all local data")

    # auth subcommand (Telegram OIDC → broker session in one step)
    auth_p = sub.add_parser("auth", help="Authenticate via Telegram OIDC")
    auth_p.add_argument(
        "--profile",
        default="assets/profile.json",
        help="Path to profile JSON (default: assets/profile.json)",
    )
    auth_p.add_argument(
        "--client-id",
        default=os.environ.get("TELEGRAM_CLIENT_ID", "8667905487"),
        help="Telegram OIDC client ID (default: TELEGRAM_CLIENT_ID env var)",
    )
    auth_p.add_argument(
        "--dev",
        action="store_true",
        default=False,
        help="Dev mode: skip OIDC browser flow, create session via /auth/session",
    )
    auth_p.add_argument(
        "--telegram-id",
        default=os.environ.get("TELEGRAM_ID", ""),
        help="Telegram user ID for --dev mode (default: TELEGRAM_ID env var)",
    )
    auth_p.add_argument(
        "--telegram-handle",
        default=os.environ.get("TELEGRAM_HANDLE", ""),
        help="Telegram username for --dev mode (default: TELEGRAM_HANDLE env var)",
    )
    auth_p.add_argument(
        "--redirect-url",
        default=os.environ.get("MERGE_REDIRECT_URL", ""),
        help=(
            "Public redirect URL for OAuth callback (e.g. from cloudflared tunnel). "
            "The local server still listens on localhost; the tunnel forwards traffic. "
            "(default: MERGE_REDIRECT_URL env var, or http://localhost:<port>/callback)"
        ),
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


def cmd_card(args: argparse.Namespace) -> None:
    """Card subcommand: build introduction card from local profile."""
    profile_path = Path(args.profile)
    if not profile_path.exists():
        output_error("No profile found. Run setup first.", 1)

    profile = json.loads(profile_path.read_text(encoding="utf-8"))

    # Pick the most interesting signals
    highlights: list[str] = []
    hobbies = profile.get("hobbies", [])
    interests = profile.get("interests", [])

    if hobbies:
        highlights.append(hobbies[0])
    elif interests:
        highlights.append(interests[0])

    if interests and len(highlights) < 2:
        # avoid duplicating if hobby == first interest
        candidate = interests[0]
        if candidate not in highlights:
            highlights.append(candidate)

    # Intent line
    looking_for = profile.get("lookingFor", "unsure")
    if looking_for == "relationship":
        intent = "looking for something real"
    elif looking_for == "dating":
        intent = "seeing where things go"
    else:
        intent = "figuring it out"

    highlight_str = (', '.join(highlights) + ', ') if highlights else ''
    first_name = profile.get("firstName", "") or "Anonymous"
    age = profile.get("age", "?")
    first_line = f"{first_name}, {age} \u2014 {highlight_str}{intent}."

    tagline = profile.get("tagline", "")
    second_line = f'\u201c{tagline}\u201d' if tagline else ""

    card = "\n".join(line for line in [first_line, second_line] if line)

    # Write card file
    card_path = Path(args.output)
    card_path.parent.mkdir(parents=True, exist_ok=True)
    card_path.write_text(card, encoding="utf-8")
    log(f"Card written to {card_path}")

    output_success({"card": card})


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
    """Auth subcommand: Telegram OIDC Authorization Code Flow with PKCE."""

    # --- Dev bypass: skip OIDC, create session directly via /auth/session ---
    if getattr(args, "dev", False):
        telegram_id = args.telegram_id
        telegram_handle = args.telegram_handle
        if not telegram_id:
            output_error("--telegram-id required in dev mode (or set TELEGRAM_ID env)", 1)

        anonymous_id = get_or_create_anonymous_id()
        telegram_id_hash = hash_telegram_id(telegram_id)

        log(f"Dev mode: creating session for telegram_id={telegram_id}")
        url = f"{args.broker_url.rstrip('/')}/auth/session"
        try:
            resp = requests.post(
                url,
                json={"anonymousId": anonymous_id, "telegramIdHash": telegram_id_hash},
                headers={"Content-Type": "application/json"},
                timeout=(5, 15),
            )
        except requests.RequestException as exc:
            output_error(f"Cannot reach broker — {exc}", 3)

        if resp.status_code != 200:
            try:
                msg = resp.json().get("message", resp.text)
            except Exception:
                msg = resp.text
            output_error(f"Broker error ({resp.status_code}): {msg}", 4)

        data = resp.json()
        token = data.get("token", "")
        resolved_id = data.get("anonymousId", anonymous_id)

        # Update profile with telegram identity
        _update_profile_telegram(args.profile, telegram_id, telegram_handle)

        # Save session token
        if token:
            session_path = Path(".merge_session")
            session_path.write_text(token + "\n", encoding="utf-8")
            os.chmod(session_path, 0o600)
            log("Session token saved to .merge_session")

        Path("anonymous_id").write_text(resolved_id, encoding="utf-8")

        output_success({
            "telegramId": telegram_id,
            "telegramHandle": telegram_handle,
            "anonymousId": resolved_id,
        })
        return

    # --- Standard OIDC flow (broker-mediated with polling) ---
    # The broker handles the Telegram redirect; the CLI just polls for the result.
    broker_base = args.broker_url.rstrip("/")

    # Step 1: Request auth session from broker
    start_url = f"{broker_base}/auth/telegram/start"
    try:
        resp = requests.post(start_url, timeout=(5, 15))
    except requests.RequestException as exc:
        output_error(f"Cannot reach broker — {exc}", 3)

    if resp.status_code != 200:
        try:
            msg = resp.json().get("message", resp.text)
        except Exception:
            msg = resp.text
        output_error(f"Broker error ({resp.status_code}): {msg}", 3)

    start_data = resp.json()
    auth_url = start_data.get("authUrl", "")
    state = start_data.get("state", "")
    if not auth_url or not state:
        output_error("Broker returned invalid auth start response", 3)

    # Step 2: Open browser to Telegram auth
    log("Opening Telegram authorization…")
    log(f"Auth URL: {auth_url}")
    webbrowser.open(auth_url)

    # Step 3: Poll broker for result
    poll_url = f"{broker_base}/auth/telegram/poll?" + urlencode({"state": state})
    log("Waiting for authorization (poll every 2s, timeout 2min)…")
    deadline = time.monotonic() + 120
    data = None
    while time.monotonic() < deadline:
        time.sleep(2)
        try:
            poll_resp = requests.get(poll_url, timeout=(5, 10))
        except requests.RequestException:
            continue  # transient error, retry

        if poll_resp.status_code == 200:
            poll_data = poll_resp.json()
            status = poll_data.get("status", "")
            if status == "complete":
                data = poll_data
                break
            elif status == "error":
                err_msg = poll_data.get("error", "unknown error")
                _mark_age_unverified(args.profile)
                output_error(f"Telegram login failed: {err_msg}", 2)
            elif status == "expired":
                _mark_age_unverified(args.profile)
                output_error("Auth session expired — try again", 2)
            # status == "pending" → continue polling
        elif poll_resp.status_code in (404, 410):
            _mark_age_unverified(args.profile)
            output_error("Auth session expired or not found — try again", 2)

    if data is None:
        _mark_age_unverified(args.profile)
        output_error("Telegram login timed out — authorize within 2 minutes", 2)

    telegram_id = data.get("telegramId", "")
    telegram_handle = data.get("telegramHandle", "")
    if not telegram_id:
        output_error("Broker returned no Telegram ID", 3)

    # Update profile
    _update_profile_telegram(args.profile, telegram_id, telegram_handle)

    # Save session token
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
        "telegramId": telegram_id,
        "telegramHandle": telegram_handle,
        "anonymousId": resolved_id,
    }

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
    elif args.command == "card":
        cmd_card(args)
    elif args.command == "delete":
        cmd_delete(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
