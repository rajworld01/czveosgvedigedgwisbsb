# Telegram VC Monitor + Safe Network Diagnostics (Termux)

> This project is designed for **defensive monitoring and diagnostics only**. It does **not** support public-target DDoS behavior. UDP/TCP diagnostics are restricted to private/loopback/reserved ranges.

## What this rewrite provides

- Dual-client architecture (Bot + User session)
- On-demand VC scan (`/scan`) only (no background scraping)
- Inline group selection and manual approval flow
- VC join + raw metadata extraction + clean leave
- Async diagnostics engine (`asyncio` + `run_in_executor`) with buffer pooling
- Live progress dashboard updates every 5 seconds
- Global stop and structured logging to `bot.log`

## File Layout

- `main.py` — dual-client bootstrap and lifecycle
- `config.py` — dotenv config loading and validation
- `vc_detector.py` — raw API voice chat detection and metadata extraction
- `attack_engine.py` — async diagnostics engine (safe target guardrails)
- `bot_handler.py` — state machine and Telegram interaction layer
- `utils.py` — helpers (bytes formatter, resolver, IP safety checks)

## Termux Setup

```bash
pkg update -y && pkg upgrade -y
pkg install -y python rust clang libffi openssl
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip wheel
pip install -r requirements.txt
```

## .env Example

```env
API_ID=1234567
API_HASH=your_api_hash
BOT_TOKEN=123456:ABC-DEF...
SESSION_STRING=your_pyrogram_session_string
ADMIN_ID=123456789  # optional (used only for startup notification target)
MAX_DURATION=600
MAX_THREADS=100
SCAN_LIMIT=50
```

`ADMIN_ID` is optional and is only used as the startup notification chat target.

## Run

```bash
python main.py
```

## Command Flow

1. `/scan` → on-demand scan over top dialogs (configurable via `SCAN_LIMIT`)
2. Select active VC from inline buttons
3. Confirm join/extract (`✅ PROCEED` or `❌ CANCEL`)
4. Metadata extraction executes with raw methods
5. Optional diagnostics command:
   - `/diag <ip> <port> <duration>`
   - only private/loopback/reserved targets are permitted
6. `Leave VC` inline action performs clean exit
7. `/stop` triggers global stop for active diagnostic tasks

## Error Handling

- `FloodWait` lockout is surfaced in bot replies with wait seconds
- `ChatAdminRequired` during join is handled gracefully: metadata extraction still continues for active VC
- `UserAlreadyParticipant` is handled gracefully
- All runtime logs are written to `bot.log`

## Notes

- Keep this tool compliant with local laws and Telegram Terms.
- Do not run diagnostics against systems you do not own or explicitly control.
