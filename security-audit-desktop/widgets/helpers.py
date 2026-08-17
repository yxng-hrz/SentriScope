"""SENTRISCOPE — Shared helpers"""
from typing import List, Dict

def fmt_bytes(bps: float) -> str:
    for u in ("B/s", "KB/s", "MB/s", "GB/s"):
        if bps < 1024:
            return f"{bps:.1f} {u}"
        bps /= 1024
    return f"{bps:.1f} TB/s"

def fmt_size(b: float) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_COLOR = {"critical": "#ef4444", "high": "#f97316", "medium": "#f59e0b", "low": "#22c55e", "info": "#3b82f6"}
SEV_ICON  = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}

def sev_counts(vulns) -> Dict[str, int]:
    c = {"total": len(vulns), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        s = getattr(v, "severity", "info")
        if s in c:
            c[s] += 1
    return c

def risk_score(vulns) -> int:
    w = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
    return min(100, sum(w.get(getattr(v, "severity", "low"), 3) for v in vulns))

def risk_color(score: int) -> str:
    if score < 30: return "#22c55e"
    if score < 60: return "#f59e0b"
    return "#ef4444"

def setup_tree_columns(tree, specs: Dict[str, tuple], anchor: str = "w"):
    """
    Configure les colonnes d'un Treeview.
    specs = {'col_id': ('Label', width), ...}  # 2-tuple (compatibilité existante)
            ou {'col_id': ('Label', width, anchor), ...}  # 3-tuple par-colonne
    Par défaut, stretch=False pour éviter que les colonnes se déforment au resize.
    """
    for col, spec in specs.items():
        if len(spec) == 3:
            label, width, col_anchor = spec
        else:
            label, width = spec
            col_anchor = anchor
        tree.heading(col, text=label, anchor=col_anchor)
        tree.column(col, width=width, anchor=col_anchor, stretch=False, minwidth=40)
