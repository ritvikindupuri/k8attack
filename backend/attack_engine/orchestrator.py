import asyncio
import time
import uuid
from typing import List, Optional

from .engine import AttackEngine, AVAILABLE_ATTACKS


class AttackOrchestrator:
    def __init__(self, attack_engine: AttackEngine):
        self.attack_engine = attack_engine
        self.running = False
        self.results: List[dict] = []
        self.current_attack_index = -1
        self.total_attacks = 0
        self.completed_attacks = 0
        self.failed_attacks = 0
        self.start_time: Optional[float] = None

    async def run_all_attacks(self):
        if self.running:
            return {"status": "already_running"}

        self.running = True
        self.results = []
        self.current_attack_index = -1
        self.total_attacks = len(AVAILABLE_ATTACKS)
        self.completed_attacks = 0
        self.failed_attacks = 0
        self.start_time = time.time()

        ws = self.attack_engine.ws_manager
        attack_ids = list(AVAILABLE_ATTACKS.keys())

        if ws:
            await ws.broadcast({
                "type": "orchestrator_started",
                "total_attacks": self.total_attacks,
                "attack_ids": attack_ids,
                "timestamp": self.start_time,
            })

        for idx, attack_id in enumerate(attack_ids):
            self.current_attack_index = idx
            if not self.running:
                break

            try:
                execution_id = await self.attack_engine.run_attack(attack_id)
                self.results.append({
                    "attack_id": attack_id,
                    "execution_id": execution_id,
                    "status": "launched",
                    "index": idx,
                })
            except Exception as e:
                self.failed_attacks += 1
                self.results.append({
                    "attack_id": attack_id,
                    "execution_id": None,
                    "status": "failed",
                    "error": str(e),
                    "index": idx,
                })

            await asyncio.sleep(2)

        self.running = False
        elapsed = round(time.time() - self.start_time, 2)

        if ws:
            await ws.broadcast({
                "type": "orchestrator_completed",
                "total_attacks": self.total_attacks,
                "completed": self.completed_attacks,
                "failed": self.failed_attacks,
                "elapsed": elapsed,
                "results": self.results,
            })

        return {
            "status": "completed",
            "total": self.total_attacks,
            "completed": self.completed_attacks,
            "failed": self.failed_attacks,
            "elapsed": elapsed,
        }

    def stop(self):
        self.running = False

    def get_status(self) -> dict:
        elapsed = None
        if self.start_time:
            elapsed = round(time.time() - self.start_time, 2)

        return {
            "running": self.running,
            "current_index": self.current_attack_index,
            "total": self.total_attacks,
            "completed": self.completed_attacks,
            "failed": self.failed_attacks,
            "elapsed": elapsed,
            "results": self.results[-10:] if self.results else [],
        }
