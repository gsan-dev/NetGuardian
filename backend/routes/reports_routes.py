"""Endpoint para descargar el informe semanal en PDF (mejora futura integrada)."""
from __future__ import annotations

import time
from datetime import datetime

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse

from auth import get_current_user
from common.config import settings
from common.db import get_repository
from common.reports import generate_weekly_report

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/weekly")
async def weekly_report(user: str = Depends(get_current_user)):
    repo = get_repository()
    until = time.time()
    since = until - 7 * 24 * 3600
    summary = repo.traffic_summary_since(since)

    filename = f"netguardian_weekly_{datetime.fromtimestamp(until):%Y%m%d_%H%M}.pdf"
    output_path = settings.reports_dir_absolute / filename
    generate_weekly_report(summary, since, until, output_path)

    return FileResponse(output_path, media_type="application/pdf", filename=filename)
