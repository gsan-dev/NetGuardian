"""Generación de informes semanales de actividad en PDF.

Mejora futura del README ya integrada desde el principio: tanto el
backend (endpoint bajo demanda) como el sensor (tarea programada) usan
esta misma función para no duplicar el formato del informe.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from fpdf import FPDF


def generate_weekly_report(
    summary: dict[str, Any], since: float, until: float, output_path: Path
) -> Path:
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "NetGuardian - Informe semanal", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 11)
    since_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(since))
    until_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(until))
    pdf.cell(0, 8, f"Periodo: {since_str}  -  {until_str}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Resumen de trafico", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"Ventanas analizadas: {summary.get('num_windows', 0)}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Paquetes totales: {summary.get('total_packets', 0)}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Bytes totales: {summary.get('total_bytes', 0):,}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(
        0, 8, f"Ventanas con anomalias: {summary.get('num_anomalous_windows', 0)}",
        new_x="LMARGIN", new_y="NEXT",
    )
    pdf.cell(0, 8, f"Alertas generadas: {summary.get('num_alerts', 0)}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "IPs con mas anomalias", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    top_ips = summary.get("top_anomalous_ips") or []
    if not top_ips:
        pdf.cell(0, 8, "Sin anomalias registradas en este periodo.", new_x="LMARGIN", new_y="NEXT")
    else:
        for entry in top_ips:
            pdf.cell(
                0, 8,
                f"{entry['src_ip']}: {entry['anomaly_count']} ventanas anomalas",
                new_x="LMARGIN", new_y="NEXT",
            )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))
    return output_path
