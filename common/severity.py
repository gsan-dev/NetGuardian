"""Orden de severidad de alertas, compartido por notificador y bloqueador."""
from __future__ import annotations

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def meets_threshold(severity: str, min_severity: str) -> bool:
    """True si `severity` es igual o superior a `min_severity`."""
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(min_severity, 0)
