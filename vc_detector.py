"""Enhanced On-demand Telegram voice chat detector with proper IP extraction."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import time
import ipaddress
from dataclasses import dataclass
from typing import Any, Optional, List, Dict, Set, Tuple

from pyrogram import Client
from pyrogram.errors import BadRequest, ChatAdminRequired, FloodWait, UserAlreadyParticipant
from pyrogram.raw import functions, types

LOGGER = logging.getLogger(__name__)


@dataclass
class VCRecord:
    dialog_id: int
    title: str
    peer: Any
    call: Any
    chat_id: int


@dataclass  
class VCConnectionInfo:
    """Structured VC connection information."""
    ip: str
    port: int
    type: str  # 'udp', 'tcp', 'relay', 'srflx', 'host', etc.
    region: str
    raw_endpoint: str
    source: str  # Where this IP was found


class VCDetector:
    def __init__(self, user_client: Client, scan_cooldown_seconds: int = 10) -> None:
        self.user_client = user_client
        self.scan_cooldown_seconds = scan_cooldown_seconds
        self._last_scan = 0.0

    async def scan_active_voice_chats(self, limit: int = 50) -> list[VCRecord]:
        now = time.time()
        if now - self._last_scan < self.scan_cooldown_seconds:
            await asyncio.sleep(self.scan_cooldown_seconds - (now - self._last_scan))

        self._last_scan = time.time()
        results: list[VCRecord] = []

        async for dialog in self.user_client.get_dialogs(limit=limit):
            chat = dialog.chat
            try:
                peer = await self.user_client.resolve_peer(chat.id)
                call = await self._extract_call(peer)
                if call:
                    results.append(VCRecord(
                        dialog_id=chat.id, 
                        title=chat.title or str(chat.id), 
                        peer=peer, 
                        call=call,
                        chat_id=chat.id
                    ))
            except FloodWait as wait_err:
                LOGGER.warning("FloodWait during scan: %s", wait_err.value)
                raise
            except Exception as exc:
                LOGGER.debug("Skipping dialog %s: %s", chat.id, exc)

        return results

    async def _extract_call(self, peer: Any) -> Optional[Any]:
        if isinstance(peer, types.InputPeerChannel):
            full = await self.user_client.invoke(
                functions.channels.GetFullChannel(channel=types.InputChannel(channel_id=peer.channel_id, access_hash=peer.access_hash))
            )
            return getattr(full.full_chat, "call", None)

        if isinstance(peer, types.InputPeerChat):
            full = await self.user_client.invoke(functions.messages.GetFullChat(chat_id=peer.chat_id))
            return getattr(full.full_chat, "call", None)

        return None

    async def join_and_extract_metadata(self, record: VCRecord) -> dict:
        """Join active VC and fetch complete metadata including IP addresses."""
        joined = False
        notice: Optional[str] = None
        candidates: List[str] = []
        participants: List[Any] = []

        try:
            await self.user_client.invoke(
                functions.phone.JoinGroupCall(
                    call=types.InputGroupCall(id=record.call.id, access_hash=record.call.access_hash),
                    join_as=record.peer,
                    params=types.DataJSON(data=json.dumps({
                        "ufrag": "vc_detector",
                        "pwd": "vc_test_123",
                        "fingerprints": [],
                        "ssrc": 11111111
                    })),
                    muted=True,
                    video_stopped=True,
                    invite_hash=None,
                )
            )
            joined = True
            LOGGER.info("Joined active VC in %s", record.title)
            await asyncio.sleep(2)  # Wait for connection establishment
        except UserAlreadyParticipant:
            joined = True
            LOGGER.info("Already joined in %s", record.title)
        except ChatAdminRequired as exc:
            notice = "Join blocked by Telegram admin restriction; fetched metadata without joining."
            LOGGER.warning("Admin restriction in %s: %s", record.title, exc)
        except BadRequest as exc:
            if "CHAT_ADMIN_REQUIRED" in str(exc):
                notice = "Join blocked by Telegram admin restriction; fetched metadata without joining."
                LOGGER.warning("Admin restriction in %s: %s", record.title, exc)
            else:
                LOGGER.warning("Join attempt failed: %s", exc)
                notice = f"Join failed: {exc}"
        except Exception as exc:
            LOGGER.warning("Join attempt failed: %s", exc)
            notice = f"Join failed: {exc}"

        # Fetch detailed group call info
        group_call = await self.user_client.invoke(
            functions.phone.GetGroupCall(
                call=types.InputGroupCall(id=record.call.id, access_hash=record.call.access_hash),
                limit=100,
            )
        )

        call = group_call.call
        params_raw = getattr(call, "params", None)
        params_data = getattr(params_raw, "data", "{}") if params_raw else "{}"

        try:
            parsed = json.loads(params_data)
        except json.JSONDecodeError:
            parsed = {"raw": params_data}

        # Extract IP addresses from multiple sources
        extracted_ips: List[VCConnectionInfo] = []
        seen_ips: Set[str] = set()
        
        def add_ip(ip_info: VCConnectionInfo) -> None:
            """Add IP if not already seen."""
            key = f"{ip_info.ip}:{ip_info.port}"
            if key not in seen_ips and ip_info.ip:
                seen_ips.add(key)
                extracted_ips.append(ip_info)
        
        # Source 1: endpoints in params (WebRTC ICE candidates)
        candidates = parsed.get("endpoints", []) if isinstance(parsed, dict) else []
        for endpoint in candidates:
            ip_info = self._parse_endpoint(endpoint, source="endpoints")
            if ip_info:
                add_ip(ip_info)

        # Source 2: servers list (relay servers)
        if isinstance(parsed, dict):
            servers = parsed.get("servers", [])
            for server in servers:
                if isinstance(server, dict):
                    ip = server.get("ip") or server.get("host") or server.get("address")
                    port = server.get("port", 0)
                    if ip:
                        ip_info = VCConnectionInfo(
                            ip=ip, port=port, type=server.get("type", "relay"),
                            region=server.get("region", "unknown"),
                            raw_endpoint=f"{ip}:{port}",
                            source="servers"
                        )
                        add_ip(ip_info)

        # Source 3: connection description - deep IP extraction
        if isinstance(parsed, dict):
            params_str = json.dumps(parsed)
            
            # IPv4 pattern with word boundaries
            ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            found_ips = re.findall(ipv4_pattern, params_str)
            
            for ip in found_ips:
                if not self._is_private_ip(ip):
                    add_ip(VCConnectionInfo(
                        ip=ip, port=0, type="extracted_public", 
                        region="unknown", raw_endpoint=ip,
                        source="deep_extraction"
                    ))

        # Source 4: participants info (if available)
        participants = getattr(group_call, "participants", [])
        for participant in participants:
            try:
                # Check multiple possible IP fields
                for attr in ["ip", "address", "connection_ip", "relay_ip"]:
                    peer_ip = getattr(participant, attr, None)
                    if peer_ip:
                        ip_str = str(peer_ip)
                        if ip_str not in [x.ip for x in extracted_ips]:
                            add_ip(VCConnectionInfo(
                                ip=ip_str, port=0, type="participant", 
                                region="unknown", raw_endpoint=ip_str,
                                source="participant"
                            ))
            except Exception:
                pass

        # Resolve hostnames if present (run in executor to avoid blocking)
        final_ips: List[VCConnectionInfo] = []
        for ip_info in extracted_ips:
            if ip_info.ip and not self._is_valid_ip(ip_info.ip):
                # Try to resolve hostname
                try:
                    loop = asyncio.get_event_loop()
                    resolved = await loop.run_in_executor(
                        None, socket.gethostbyname, ip_info.ip
                    )
                    if resolved:
                        final_ips.append(VCConnectionInfo(
                            ip=resolved,
                            port=ip_info.port,
                            type=ip_info.type,
                            region=ip_info.region,
                            raw_endpoint=ip_info.raw_endpoint,
                            source=f"{ip_info.source}_resolved"
                        ))
                except Exception:
                    pass
            else:
                final_ips.append(ip_info)

        return {
            "title": record.title,
            "call_id": record.call.id,
            "chat_id": record.chat_id,
            "params": parsed,
            "endpoint_candidates": candidates,
            "extracted_ips": [
                {
                    "ip": x.ip,
                    "port": x.port,
                    "type": x.type,
                    "region": x.region,
                    "source": x.source
                } for x in final_ips
            ],
            "joined": joined,
            "notice": notice,
            "participants_count": len(participants) if participants else 0,
        }

    def _parse_endpoint(self, endpoint: str, source: str = "unknown") -> Optional[VCConnectionInfo]:
        """Parse endpoint string to extract IP and port."""
        if not endpoint:
            return None

        # Pattern 1: IP:PORT (IPv4)
        if ":" in endpoint:
            parts = endpoint.rsplit(":", 1)
            if len(parts) == 2:
                ip, port_str = parts
                try:
                    port = int(port_str)
                    if self._is_valid_ip(ip):
                        return VCConnectionInfo(
                            ip=ip, port=port, type="direct", 
                            region="auto", raw_endpoint=endpoint,
                            source=source
                        )
                except (ValueError, TypeError):
                    pass

        # Pattern 2: [IPv6]:PORT
        if endpoint.startswith("["):
            match = re.match(r'\[([\da-fA-F:]+)\]:(\d+)', endpoint)
            if match:
                ip, port_str = match.groups()
                try:
                    port = int(port_str)
                    if self._is_valid_ipv6(ip):
                        return VCConnectionInfo(
                            ip=ip, port=port, type="direct_ipv6",
                            region="auto", raw_endpoint=endpoint,
                            source=source
                        )
                except (ValueError, TypeError):
                    pass

        # Pattern 3: hostname:port
        try:
            if ":" in endpoint:
                hostname, port_str = endpoint.rsplit(":", 1)
                port = int(port_str)
                return VCConnectionInfo(
                    ip=hostname, port=port, type="hostname",
                    region="unknown", raw_endpoint=endpoint,
                    source=source
                )
        except (ValueError, TypeError):
            pass

        # Pattern 4: Just IP (IPv4)
        if self._is_valid_ip(endpoint):
            return VCConnectionInfo(
                ip=endpoint, port=0, type="ip_only",
                region="unknown", raw_endpoint=endpoint,
                source=source
            )

        # Pattern 5: Just IPv6
        if self._is_valid_ipv6(endpoint):
            return VCConnectionInfo(
                ip=endpoint, port=0, type="ipv6_only",
                region="unknown", raw_endpoint=endpoint,
                source=source
            )

        return None

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is valid IPv4 address."""
        if not ip or not isinstance(ip, str):
            return False
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def _is_valid_ipv6(self, ip: str) -> bool:
        """Check if string is valid IPv6 address."""
        if not ip or not isinstance(ip, str):
            return False
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False

    async def leave_call(self, record: VCRecord) -> None:
        try:
            await self.user_client.invoke(
                functions.phone.LeaveGroupCall(
                    call=types.InputGroupCall(id=record.call.id, access_hash=record.call.access_hash), 
                    source=0
                )
            )
            LOGGER.info("Left VC in %s", record.title)
        except Exception as exc:
            LOGGER.warning("Error leaving call: %s", exc)
