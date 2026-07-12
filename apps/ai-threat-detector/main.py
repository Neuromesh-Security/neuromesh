#!/usr/bin/env python3
"""Neuromesh AI Threat Detector — Slow Path entry point."""

from __future__ import annotations

import asyncio
import logging
import signal

from src.inference.anomaly_pipeline import AnomalyPipeline
from src.streaming.kafka_consumer import AsyncTelemetryConsumer

logger = logging.getLogger(__name__)


async def run_service() -> None:
    pipeline = AnomalyPipeline()
    consumer = AsyncTelemetryConsumer.from_env()

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _request_shutdown() -> None:
        logger.info("shutdown signal received")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_shutdown)
        except NotImplementedError:
            # Windows does not support add_signal_handler for SIGTERM.
            pass

    consumer_task = asyncio.create_task(consumer.run(pipeline.handle))

    try:
        await stop_event.wait()
    except asyncio.CancelledError:
        pass
    finally:
        consumer.stop()
        consumer_task.cancel()
        try:
            await consumer_task
        except asyncio.CancelledError:
            pass

    logger.info(
        "ai-threat-detector stopped | behavior=%d critical=%d anomalies=%d",
        pipeline.stats.behavior_alerts,
        pipeline.stats.critical_alerts,
        pipeline.stats.anomalies_detected,
    )


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    logger.info("starting Neuromesh AI Threat Detector (Slow Path)")
    try:
        asyncio.run(run_service())
    except KeyboardInterrupt:
        logger.info("interrupted")


if __name__ == "__main__":
    main()
