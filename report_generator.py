# report_generator.py
# Converts raw analysis findings into Pandas DataFrames and CSV reports.
# Also provides summary statistics used by both the CLI and GUI.

import os
import datetime
import pandas as pd

from rules import SEVERITY_ORDER

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")


# ---------------------------------------------------------------------------
# DataFrame helpers
# ---------------------------------------------------------------------------

COLUMN_ORDER = [
    "severity",
    "protocol",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "transport",
    "issue",
    "explanation",
    "recommendation",
]

COLUMN_LABELS = {
    "severity":       "Severity",
    "protocol":       "Protocol",
    "src_ip":         "Source IP",
    "dst_ip":         "Destination IP",
    "src_port":       "Src Port",
    "dst_port":       "Dst Port",
    "transport":      "Transport",
    "issue":          "Issue",
    "explanation":    "Explanation",
    "recommendation": "Recommendation",
}


def findings_to_dataframe(findings: list) -> pd.DataFrame:
    """
    Convert a list of finding dicts to a sorted, labeled Pandas DataFrame.
    """
    if not findings:
        return pd.DataFrame(columns=list(COLUMN_LABELS.values()))

    df = pd.DataFrame(findings)

    # Ensure all expected columns exist
    for col in COLUMN_ORDER:
        if col not in df.columns:
            df[col] = "N/A"

    df = df[COLUMN_ORDER]

    # Sort by severity (Critical first)
    df["_sev_order"] = df["severity"].map(lambda s: SEVERITY_ORDER.get(s, 99))
    df = df.sort_values("_sev_order").drop(columns=["_sev_order"])

    df = df.rename(columns=COLUMN_LABELS)
    df = df.reset_index(drop=True)

    return df


def compute_summary(result: dict) -> dict:
    """
    Compute summary statistics from an analysis result dict.

    Returns a dict with keys:
        total_packets, total_findings, critical, high, medium, low, info,
        top_protocols, source, analyzed_at
    """
    findings = result.get("findings", [])
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    protocol_counts: dict[str, int] = {}

    for f in findings:
        sev = f.get("severity", "Low")
        counts[sev] = counts.get(sev, 0) + 1
        proto = f.get("protocol", "Unknown")
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

    top_protocols = sorted(protocol_counts.items(), key=lambda x: -x[1])

    return {
        "total_packets":  result.get("total_packets", 0),
        "total_findings": len(findings),
        "critical":       counts["Critical"],
        "high":           counts["High"],
        "medium":         counts["Medium"],
        "low":            counts["Low"],
        "info":           counts["Info"],
        "top_protocols":  top_protocols,
        "source":         result.get("source", "unknown"),
        "analyzed_at":    result.get("analyzed_at", "N/A"),
    }


# ---------------------------------------------------------------------------
# CSV report generation
# ---------------------------------------------------------------------------

def save_csv_report(result: dict, label: str = "analysis") -> str:
    """
    Save the findings as a CSV file in the reports/ directory.
    Returns the path to the saved file.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{label}_{timestamp}.csv"
    filepath = os.path.join(REPORTS_DIR, filename)

    df = findings_to_dataframe(result.get("findings", []))
    df.to_csv(filepath, index=False)
    return filepath


def dataframe_to_csv_bytes(df: pd.DataFrame) -> bytes:
    """Return a CSV byte string from a DataFrame (for Streamlit download button)."""
    return df.to_csv(index=False).encode("utf-8")


# ---------------------------------------------------------------------------
# Severity breakdown for charts
# ---------------------------------------------------------------------------

def severity_chart_data(result: dict) -> pd.DataFrame:
    """
    Return a small DataFrame suitable for a Plotly bar chart:
        Severity | Count
    """
    summary = compute_summary(result)
    rows = [
        {"Severity": "Critical", "Count": summary["critical"]},
        {"Severity": "High",     "Count": summary["high"]},
        {"Severity": "Medium",   "Count": summary["medium"]},
        {"Severity": "Low",      "Count": summary["low"]},
    ]
    return pd.DataFrame(rows)
