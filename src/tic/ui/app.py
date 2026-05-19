"""Local Streamlit dashboard for `tic sweep`.

Run:
    streamlit run src/tic/ui/app.py --server.address 127.0.0.1 --server.headless true

This page is UI-only. All security-sensitive logic lives in tic.ui.adapter
and the existing core modules. No raw logs, raw provider responses, API keys
or tracebacks are ever rendered to the user.

REDESIGNED: Dark SOC-style dashboard matching IntSights reference.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import plotly.graph_objects as go
import streamlit as st

from tic.security.ansi_strip import strip_terminal_controls
from tic.ui import adapter

_PAGE_TITLE = "Threat Intel Correlator"
_FEED_FORMATS: tuple[str, ...] = ("csv", "ndjson", "misp-json", "stix")
_OUTPUT_MODES: tuple[str, ...] = ("analyst", "summary", "hash")
_FAIL_ON: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

# =============================================================================
# DARK THEME CSS
# =============================================================================
_DARK_THEME_CSS = """
<style>
    /* === ROOT & BODY === */
    .stApp {
        background-color: #0d1b2a;
    }

    /* === MAIN CONTENT AREA === */
    .main .block-container {
        background-color: #1b2838;
        padding: 1rem 2rem 2rem 2rem;
        max-width: 100%;
    }

    /* === SIDEBAR === */
    [data-testid="stSidebar"] {
        background-color: #0d1b2a;
        border-right: 1px solid #2d4a6f;
    }

    [data-testid="stSidebar"] .stMarkdown,
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] .stRadio label,
    [data-testid="stSidebar"] .stCheckbox label,
    [data-testid="stSidebar"] span {
        color: #8ba3c7 !important;
    }

    [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3 {
        color: #ffffff !important;
    }

    [data-testid="stSidebar"] hr {
        border-color: #2d4a6f;
    }

    /* === TYPOGRAPHY === */
    h1, h2, h3, h4, h5, h6 {
        color: #ffffff !important;
        font-weight: 600;
    }

    p, span, label, .stMarkdown {
        color: #a8c5e2 !important;
    }

    /* === HEADER STATS BAR === */
    .header-stats-bar {
        background: linear-gradient(180deg, #1b2838 0%, #162030 100%);
        border-bottom: 2px solid #2d4a6f;
        padding: 0.75rem 1.5rem;
        margin: -1rem -2rem 1.5rem -2rem;
        display: flex;
        align-items: center;
        gap: 2rem;
    }

    .stat-item {
        display: flex;
        flex-direction: column;
        align-items: center;
        padding: 0 1rem;
        border-right: 1px solid #2d4a6f;
    }

    .stat-item:last-child {
        border-right: none;
    }

    .stat-value {
        font-size: 1.75rem;
        font-weight: 700;
        color: #ffffff;
        line-height: 1.2;
    }

    .stat-value.critical { color: #ff4757; }
    .stat-value.high { color: #ffa502; }
    .stat-value.medium { color: #2ed573; }
    .stat-value.low { color: #70a1ff; }

    .stat-label {
        font-size: 0.7rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #8ba3c7;
        margin-top: 0.25rem;
    }

    /* === METRIC CARDS === */
    [data-testid="stMetric"] {
        background-color: #162030;
        border: 1px solid #2d4a6f;
        border-radius: 8px;
        padding: 1rem;
    }

    [data-testid="stMetricLabel"] {
        color: #8ba3c7 !important;
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    [data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-size: 1.5rem;
        font-weight: 700;
    }

    [data-testid="stMetricDelta"] svg {
        display: none;
    }

    /* === PANEL CARDS === */
    .panel-card {
        background-color: #162030;
        border: 1px solid #2d4a6f;
        border-radius: 8px;
        padding: 1.25rem;
        margin-bottom: 1rem;
    }

    .panel-header {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-bottom: 1rem;
        padding-bottom: 0.75rem;
        border-bottom: 1px solid #2d4a6f;
    }

    .panel-title {
        color: #ffffff;
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin: 0;
    }

    /* === DATA TABLES === */
    [data-testid="stDataFrame"] {
        background-color: #162030;
        border: 1px solid #2d4a6f;
        border-radius: 8px;
    }

    [data-testid="stDataFrame"] th {
        background-color: #1b2838 !important;
        color: #8ba3c7 !important;
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.7rem;
        letter-spacing: 0.05em;
    }

    [data-testid="stDataFrame"] td {
        background-color: #162030 !important;
        color: #a8c5e2 !important;
        border-bottom: 1px solid #2d4a6f !important;
    }

    /* === BUTTONS === */
    .stButton > button {
        background: linear-gradient(180deg, #2d4a6f 0%, #1b3a5c 100%);
        color: #ffffff;
        border: 1px solid #3d6a9f;
        border-radius: 6px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-size: 0.8rem;
        padding: 0.5rem 1rem;
        transition: all 0.2s ease;
    }

    .stButton > button:hover {
        background: linear-gradient(180deg, #3d6a9f 0%, #2d4a6f 100%);
        border-color: #4d8acf;
    }

    .stButton > button[kind="primary"] {
        background: linear-gradient(180deg, #1e88e5 0%, #1565c0 100%);
        border-color: #42a5f5;
    }

    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(180deg, #42a5f5 0%, #1e88e5 100%);
    }

    /* === DOWNLOAD BUTTONS === */
    .stDownloadButton > button {
        background: linear-gradient(180deg, #2d4a6f 0%, #1b3a5c 100%);
        color: #ffffff;
        border: 1px solid #3d6a9f;
        border-radius: 6px;
        font-weight: 500;
        font-size: 0.8rem;
    }

    /* === FORM ELEMENTS === */
    .stSelectbox > div > div,
    .stTextInput > div > div > input,
    .stFileUploader > div {
        background-color: #162030 !important;
        border-color: #2d4a6f !important;
        color: #a8c5e2 !important;
    }

    .stRadio > div {
        background-color: transparent;
    }

    .stRadio > div > label {
        background-color: #162030;
        border: 1px solid #2d4a6f;
        border-radius: 4px;
        padding: 0.5rem 1rem;
        margin-right: 0.5rem;
        color: #8ba3c7 !important;
    }

    .stRadio > div > label[data-checked="true"] {
        background-color: #2d4a6f;
        border-color: #3d6a9f;
        color: #ffffff !important;
    }

    /* === EXPANDER === */
    .streamlit-expanderHeader {
        background-color: #162030;
        border: 1px solid #2d4a6f;
        border-radius: 8px;
        color: #a8c5e2 !important;
    }

    .streamlit-expanderContent {
        background-color: #162030;
        border: 1px solid #2d4a6f;
        border-top: none;
        border-radius: 0 0 8px 8px;
    }

    /* === ALERTS === */
    .stAlert {
        border-radius: 8px;
    }

    [data-testid="stAlert"][data-baseweb="notification"] {
        background-color: #162030;
        border: 1px solid #2d4a6f;
    }

    /* Success */
    .stSuccess {
        background-color: rgba(46, 213, 115, 0.1) !important;
        border-left: 4px solid #2ed573 !important;
    }

    /* Warning */
    .stWarning {
        background-color: rgba(255, 165, 2, 0.1) !important;
        border-left: 4px solid #ffa502 !important;
    }

    /* Error */
    .stError {
        background-color: rgba(255, 71, 87, 0.1) !important;
        border-left: 4px solid #ff4757 !important;
    }

    /* Info */
    .stInfo {
        background-color: rgba(112, 161, 255, 0.1) !important;
        border-left: 4px solid #70a1ff !important;
    }

    /* === CONTAINER BORDERS === */
    [data-testid="stVerticalBlock"] > div:has(> .stContainer) {
        background-color: #162030;
        border: 1px solid #2d4a6f;
        border-radius: 8px;
        padding: 1rem;
    }

    /* === CODE BLOCKS === */
    .stCodeBlock {
        background-color: #0d1b2a !important;
        border: 1px solid #2d4a6f;
        border-radius: 4px;
    }

    code {
        color: #70a1ff !important;
        background-color: #0d1b2a !important;
    }

    /* === SPINNER === */
    .stSpinner > div {
        border-color: #1e88e5 transparent transparent transparent;
    }

    /* === DIVIDERS === */
    hr {
        border-color: #2d4a6f;
    }

    /* === SEVERITY BADGES === */
    .severity-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.03em;
    }

    .severity-critical {
        background-color: rgba(255, 71, 87, 0.2);
        color: #ff4757;
        border: 1px solid #ff4757;
    }

    .severity-high {
        background-color: rgba(255, 165, 2, 0.2);
        color: #ffa502;
        border: 1px solid #ffa502;
    }

    .severity-medium {
        background-color: rgba(46, 213, 115, 0.2);
        color: #2ed573;
        border: 1px solid #2ed573;
    }

    .severity-low {
        background-color: rgba(112, 161, 255, 0.2);
        color: #70a1ff;
        border: 1px solid #70a1ff;
    }

    .severity-info {
        background-color: rgba(168, 197, 226, 0.2);
        color: #a8c5e2;
        border: 1px solid #a8c5e2;
    }

    /* === RISK METER === */
    .risk-meter-container {
        background-color: #0d1b2a;
        border-radius: 4px;
        height: 8px;
        width: 100%;
        overflow: hidden;
    }

    .risk-meter-fill {
        height: 100%;
        border-radius: 4px;
        transition: width 0.5s ease;
    }

    /* === HIDE STREAMLIT BRANDING === */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
</style>
"""


def _inject_css() -> None:
    """Inject the dark theme CSS."""
    st.markdown(_DARK_THEME_CSS, unsafe_allow_html=True)


def _severity_color(severity: str) -> str:
    """Return a hex color for severity levels."""
    mapping = {
        "critical": "#ff4757",
        "high": "#ffa502",
        "medium": "#2ed573",
        "low": "#70a1ff",
        "info": "#a8c5e2",
    }
    return mapping.get(severity.lower(), "#a8c5e2")


def _severity_badge(severity: str) -> str:
    """Return HTML for a severity badge."""
    sev_lower = severity.lower()
    return f'<span class="severity-badge severity-{sev_lower}">{severity}</span>'


def _render_header_stats(result: adapter.SweepResult | None = None) -> None:
    """Render the top header statistics bar."""
    if result is None:
        total, crit, high, med, low = 0, 0, 0, 0, 0
    else:
        severity_counts: dict[str, int] = {}
        for f in result.findings:
            sev = f.severity.lower() if hasattr(f, "severity") else "unknown"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        total = len(result.findings)
        crit = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        med = severity_counts.get("medium", 0)
        low = severity_counts.get("low", 0)

    header_html = f"""
    <div class="header-stats-bar">
        <div style="display: flex; align-items: center; gap: 0.5rem; padding-right: 1.5rem; border-right: 1px solid #2d4a6f;">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#1e88e5" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <span style="color: #ffffff; font-weight: 700; font-size: 1.1rem;">THREAT INTEL CORRELATOR</span>
        </div>
        <div class="stat-item">
            <span class="stat-value">{total}</span>
            <span class="stat-label">Open Findings</span>
        </div>
        <div class="stat-item">
            <span class="stat-value critical">{crit}</span>
            <span class="stat-label">Critical</span>
        </div>
        <div class="stat-item">
            <span class="stat-value high">{high}</span>
            <span class="stat-label">High</span>
        </div>
        <div class="stat-item">
            <span class="stat-value medium">{med}</span>
            <span class="stat-label">Medium</span>
        </div>
        <div class="stat-item" style="border-right: none;">
            <span class="stat-value low">{low}</span>
            <span class="stat-label">Low</span>
        </div>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)


def _render_risk_meter(result: adapter.SweepResult | None = None) -> None:
    """Render a system risk meter based on findings."""
    if result is None or not result.findings:
        risk_pct = 0
    else:
        severity_weights = {"critical": 100, "high": 70, "medium": 40, "low": 20, "info": 5}
        total_weight = 0
        for f in result.findings:
            sev = f.severity.lower() if hasattr(f, "severity") else "info"
            total_weight += severity_weights.get(sev, 5)
        # Normalize to 0-100 (cap at 100)
        risk_pct = min(100, int(total_weight / max(len(result.findings), 1)))

    # Color based on risk level
    if risk_pct >= 75:
        color = "#ff4757"
    elif risk_pct >= 50:
        color = "#ffa502"
    elif risk_pct >= 25:
        color = "#2ed573"
    else:
        color = "#70a1ff"

    st.markdown("##### SYSTEM RISK METER")
    risk_html = f"""
    <div style="display: flex; align-items: center; gap: 1rem;">
        <div class="risk-meter-container" style="flex: 1;">
            <div class="risk-meter-fill" style="width: {risk_pct}%; background: linear-gradient(90deg, #70a1ff, {color});"></div>
        </div>
        <span style="color: {color}; font-weight: 700; font-size: 1rem;">{risk_pct}%</span>
    </div>
    """
    st.markdown(risk_html, unsafe_allow_html=True)


def _create_severity_donut(result: adapter.SweepResult) -> go.Figure:
    """Create a donut chart for severity distribution."""
    severity_counts: dict[str, int] = {}
    for f in result.findings:
        sev = f.severity.lower() if hasattr(f, "severity") else "unknown"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    labels = []
    values = []
    colors = []

    severity_order = ["critical", "high", "medium", "low", "info"]
    color_map = {
        "critical": "#ff4757",
        "high": "#ffa502",
        "medium": "#2ed573",
        "low": "#70a1ff",
        "info": "#a8c5e2",
    }

    for sev in severity_order:
        if sev in severity_counts:
            labels.append(sev.upper())
            values.append(severity_counts[sev])
            colors.append(color_map.get(sev, "#a8c5e2"))

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.65,
                marker=dict(colors=colors, line=dict(color="#162030", width=2)),
                textinfo="none",
                hovertemplate="<b>%{label}</b><br>Count: %{value}<extra></extra>",
            )
        ]
    )

    fig.update_layout(
        showlegend=False,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=10, b=10),
        height=200,
        annotations=[
            dict(
                text=f'<b>{sum(values)}</b><br><span style="font-size:10px">TOTAL</span>',
                x=0.5,
                y=0.5,
                font=dict(size=20, color="#ffffff"),
                showarrow=False,
            )
        ],
    )

    return fig


def _create_type_distribution(result: adapter.SweepResult) -> dict[str, int]:
    """Get IOC type distribution from findings."""
    type_counts: dict[str, int] = {}
    for f in result.findings:
        ioc_type = f.ioc_type if hasattr(f, "ioc_type") else "unknown"
        type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1
    return type_counts


def _security_privacy_box() -> None:
    """Render the security & privacy information panel."""
    with st.expander("SECURITY & PRIVACY", expanded=False):
        st.markdown(
            """
            **Local Processing**
            - Runs entirely on your machine. No data leaves this process except
              outbound calls to providers/AI endpoints already configured in your settings.
            - Uploads are staged inside your configured working directory under
              a per-session UUID folder and deleted at the end of each sweep.

            **Data Protection**
            - Only public-safe fields (PublicFinding) are rendered. Raw log lines,
              raw provider payloads, and API keys are never displayed.
            - Hash mode replaces IOC values with HMAC pseudonyms for sensitive environments.
            """
        )


def _load_settings_or_stop() -> Any:
    """Load settings or display error and stop."""
    try:
        return adapter.get_settings()
    except Exception:  # noqa: BLE001
        st.error(
            "Settings could not be loaded. Configure paths via `TIC_PATHS__*` "
            "environment variables or a YAML config (see `configs/default.yaml`)."
        )
        st.stop()


def _sidebar(settings: Any) -> dict[str, Any] | None:
    """Render the sidebar with sweep configuration form."""
    ai_ok = adapter.ai_supported(settings)

    with st.sidebar:
        # Logo/branding area
        st.markdown(
            """
        <div style="padding: 1rem 0 1.5rem 0; border-bottom: 1px solid #2d4a6f; margin-bottom: 1.5rem;">
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#1e88e5" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                <div>
                    <div style="color: #ffffff; font-weight: 700; font-size: 0.9rem;">TIC</div>
                    <div style="color: #8ba3c7; font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.1em;">Threat Command</div>
                </div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        # Navigation-style header
        st.markdown(
            """
        <div style="color: #8ba3c7; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 1rem;">
            SWEEP CONFIGURATION
        </div>
        """,
            unsafe_allow_html=True,
        )

        with st.form("sweep_form", clear_on_submit=False):
            # Input Files Section
            st.markdown("##### INPUT FILES")

            feed_file = st.file_uploader(
                "IOC Feed File",
                type=["csv", "ndjson", "json", "txt"],
                key="feed_file",
                help="Upload a threat intelligence feed containing IOCs to correlate.",
            )

            feed_format = st.radio(
                "Feed Format",
                _FEED_FORMATS,
                horizontal=True,
                index=0,
                help="Format of the uploaded IOC feed.",
            )

            st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

            # Log File Section
            st.markdown("##### LOG FILE")

            log_file = st.file_uploader(
                "Log File (NDJSON)",
                type=["ndjson", "json", "log", "txt"],
                key="log_file",
                help="Upload NDJSON logs to scan for IOC matches.",
            )

            st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

            # Output Settings Section
            st.markdown("##### OUTPUT SETTINGS")

            output_mode = st.radio(
                "Output Mode",
                _OUTPUT_MODES,
                horizontal=True,
                index=0,
                help=(
                    "**analyst**: full IOC value | "
                    "**summary**: truncated values | "
                    "**hash**: HMAC pseudonym (privacy-preserving)"
                ),
            )

            fail_on = st.selectbox(
                "Fail-on Severity",
                _FAIL_ON,
                index=_FAIL_ON.index("high"),
                help="Minimum severity that causes the sweep to report 'above threshold'.",
            )

            st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

            # AI Options Section
            st.markdown("##### AI OPTIONS")

            with_ai = st.checkbox(
                "Enable AI Narration",
                value=False,
                disabled=not ai_ok,
                help=(
                    "AI narration is available (ai.enabled=true)."
                    if ai_ok
                    else "AI narration is disabled in settings."
                ),
            )

            st.markdown("<div style='height: 1.5rem;'></div>", unsafe_allow_html=True)

            submitted = st.form_submit_button(
                "RUN SWEEP",
                type="primary",
                use_container_width=True,
            )

        if not submitted:
            return None
        if feed_file is None or log_file is None:
            st.error("Both an IOC feed file and a log file are required.")
            return None
        return {
            "feed_file": feed_file,
            "feed_format": feed_format,
            "log_file": log_file,
            "output_mode": output_mode,
            "fail_on": fail_on,
            "with_ai": with_ai,
        }


def _execute_sweep(form: dict[str, Any], settings: Any) -> adapter.SweepResult | None:
    """Execute the sweep operation."""
    working_dir: Path = settings.paths.working_dir
    upload_dir: Path | None = None
    try:
        upload_dir = adapter.make_upload_dir(working_dir)
        feed_path = adapter.stage_upload(
            form["feed_file"].getvalue(),
            upload_dir=upload_dir,
            working_dir=working_dir,
            original_filename=form["feed_file"].name,
        )
        log_path = adapter.stage_upload(
            form["log_file"].getvalue(),
            upload_dir=upload_dir,
            working_dir=working_dir,
            original_filename=form["log_file"].name,
        )
        req = adapter.SweepRequest(
            feed_path=feed_path,
            feed_format=form["feed_format"],
            log_path=log_path,
            output_mode=form["output_mode"],
            fail_on=form["fail_on"],
            with_ai=form["with_ai"],
        )
        with st.spinner("Analyzing threat data..."):
            return adapter.run_sweep(req, settings)
    except adapter.SecurityViolationError:
        st.error("Path security check failed. The upload was rejected.")
        return None
    except RuntimeError as e:
        st.error(str(e))
        return None
    finally:
        if upload_dir is not None:
            adapter.cleanup_upload_dir(upload_dir)


def _render_kpi_cards(result: adapter.SweepResult) -> None:
    """Render KPI metric cards."""
    total = len(result.findings)
    above = result.above_threshold

    severity_counts: dict[str, int] = {}
    for f in result.findings:
        sev = f.severity.lower() if hasattr(f, "severity") else "unknown"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    crit = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    med = severity_counts.get("medium", 0)
    severity_counts.get("low", 0)

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Findings", total)
    col2.metric("Critical", crit)
    col3.metric("High", high)
    col4.metric("Medium", med)
    col5.metric("Threshold Status", "ALERT" if above else "OK")


def _render_status_alerts(result: adapter.SweepResult) -> None:
    """Render status alert messages."""
    if result.partial_scan:
        st.warning(
            "Log file was partially scanned (line limit reached). Results may be incomplete."
        )
    if result.ai_attempted and not result.ai_active:
        st.warning(
            "AI narration was requested but could not be initialised. Sweep completed without AI."
        )
    if result.findings and not result.above_threshold:
        st.success("Sweep completed. Findings detected but none exceed the fail-on threshold.")
    elif result.findings and result.above_threshold:
        st.error("Sweep completed. Findings exceed the configured fail-on threshold.")
    elif not result.findings:
        st.success("Sweep completed. No findings detected.")


def _render_results(result: adapter.SweepResult, mode: str) -> None:
    """Render the main results dashboard."""
    # Risk meter at the top
    _render_risk_meter(result)

    st.markdown("<div style='height: 1.5rem;'></div>", unsafe_allow_html=True)

    # Status alerts
    _render_status_alerts(result)

    st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

    if not result.findings:
        st.info(
            "No findings produced for this sweep. "
            "Try adjusting the IOC feed, log file, or output mode."
        )
        return

    # Main dashboard layout: Types | Severities | Sources
    col_types, col_sev, col_sources = st.columns([1, 1, 1])

    # Types panel
    with col_types:
        st.markdown(
            """
        <div class="panel-card">
            <div class="panel-header">
                <span class="panel-title">TYPES</span>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        type_counts = _create_type_distribution(result)
        for ioc_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            icon = (
                "🌐"
                if "ip" in ioc_type.lower()
                else "🔗"
                if "url" in ioc_type.lower()
                else "📧"
                if "email" in ioc_type.lower()
                else "📄"
            )
            st.markdown(
                f"""
            <div style="display: flex; align-items: center; gap: 0.75rem; padding: 0.5rem 0; border-bottom: 1px solid #2d4a6f;">
                <span style="font-size: 1.25rem;">{icon}</span>
                <span style="color: #ffffff; font-weight: 700; font-size: 1.1rem;">{count}</span>
                <span style="color: #8ba3c7; font-size: 0.75rem; text-transform: uppercase;">{ioc_type}</span>
            </div>
            """,
                unsafe_allow_html=True,
            )

    # Severities donut chart
    with col_sev:
        st.markdown(
            """
        <div class="panel-card">
            <div class="panel-header">
                <span class="panel-title">SEVERITIES</span>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        fig = _create_severity_donut(result)
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        # Legend below chart
        severity_counts: dict[str, int] = {}
        for f in result.findings:
            sev = f.severity.lower() if hasattr(f, "severity") else "unknown"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        legend_cols = st.columns(3)
        sev_items = [
            ("CRITICAL", severity_counts.get("critical", 0), "#ff4757"),
            ("HIGH", severity_counts.get("high", 0), "#ffa502"),
            ("MEDIUM", severity_counts.get("medium", 0), "#2ed573"),
        ]
        for col, (label, count, color) in zip(legend_cols, sev_items, strict=False):
            col.markdown(
                f"""
            <div style="text-align: center;">
                <div style="color: {color}; font-weight: 700;">{count}</div>
                <div style="color: #8ba3c7; font-size: 0.65rem;">{label}</div>
            </div>
            """,
                unsafe_allow_html=True,
            )

    # Sources panel (IOC sources)
    with col_sources:
        st.markdown(
            """
        <div class="panel-card">
            <div class="panel-header">
                <span class="panel-title">SOURCES</span>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        source_counts: dict[str, int] = {}
        for f in result.findings:
            source = f.ioc_source if hasattr(f, "ioc_source") else "unknown"
            source_counts[source] = source_counts.get(source, 0) + 1

        total_sources = sum(source_counts.values()) or 1
        for source, count in sorted(source_counts.items(), key=lambda x: -x[1])[:5]:
            pct = int((count / total_sources) * 100)
            st.markdown(
                f"""
            <div style="margin-bottom: 0.75rem;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 0.25rem;">
                    <span style="color: #a8c5e2; font-size: 0.75rem; text-transform: uppercase;">{source[:20]}</span>
                    <span style="color: #70a1ff; font-weight: 600;">{count}</span>
                </div>
                <div class="risk-meter-container">
                    <div class="risk-meter-fill" style="width: {pct}%; background: #70a1ff;"></div>
                </div>
            </div>
            """,
                unsafe_allow_html=True,
            )

    st.markdown("<div style='height: 1.5rem;'></div>", unsafe_allow_html=True)
    st.divider()

    # Findings table
    st.markdown("##### FINDINGS OVERVIEW")

    rows = adapter.public_rows(result.findings, mode, hmac_key=result.hmac_key)
    st.dataframe(rows, use_container_width=True, hide_index=True)

    st.markdown("<div style='height: 1rem;'></div>", unsafe_allow_html=True)

    # Finding inspector
    st.markdown("##### INSPECT FINDING")

    options = [r["finding_id"] for r in rows]
    selected = st.selectbox(
        "Select a finding to inspect",
        options=["-- Select a finding --"] + options,
        index=0,
        format_func=lambda v: v if v.startswith("--") else v[:12] + "...",
        label_visibility="collapsed",
    )
    if selected and not selected.startswith("--"):
        _render_detail(result, selected, mode)

    st.divider()

    # Export section
    st.markdown("##### EXPORT RESULTS")

    json_bytes = adapter.to_json_bytes(result.findings, mode, hmac_key=result.hmac_key)
    csv_bytes = adapter.to_csv_bytes(result.findings, mode, hmac_key=result.hmac_key)
    md_bytes = adapter.to_markdown_bytes(result.findings, mode, hmac_key=result.hmac_key)

    c1, c2, c3 = st.columns(3)
    c1.download_button(
        "DOWNLOAD JSON",
        data=json_bytes,
        file_name="findings.json",
        mime="application/json",
        use_container_width=True,
    )
    c2.download_button(
        "DOWNLOAD CSV",
        data=csv_bytes,
        file_name="findings.csv",
        mime="text/csv",
        use_container_width=True,
    )
    c3.download_button(
        "DOWNLOAD MARKDOWN",
        data=md_bytes,
        file_name="findings.md",
        mime="text/markdown",
        use_container_width=True,
    )


def _render_detail(result: adapter.SweepResult, finding_id: str, mode: str) -> None:
    """Render detailed view of a specific finding."""
    out_mode = adapter._OUTPUT_MODES[mode]
    target = next((f for f in result.findings if f.finding_id == finding_id), None)
    if target is None:
        return
    pub = target.to_public(mode=out_mode, hmac_key=result.hmac_key)

    with st.container(border=True):
        # Header with severity badge
        st.markdown(
            f"""
        <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
            <span style="color: #ffffff; font-weight: 700; font-size: 1.1rem;">FINDING DETAIL</span>
            {_severity_badge(pub.severity)}
        </div>
        """,
            unsafe_allow_html=True,
        )

        c1, c2, c3 = st.columns(3)
        c1.metric("Severity", pub.severity)
        c2.metric("Score", pub.score)
        c3.metric("Matches", pub.match_count)

        st.divider()

        det1, det2 = st.columns(2)
        with det1:
            st.markdown("**IOC Type**")
            st.code(pub.ioc_type, language=None)
            st.markdown("**IOC Value**")
            st.code(pub.ioc_value, language=None)
        with det2:
            st.markdown("**Source**")
            st.write(pub.ioc_source)
            if pub.ioc_tags:
                st.markdown("**Tags**")
                st.write(", ".join(pub.ioc_tags))

        if pub.enrichments:
            st.divider()
            st.markdown("**ENRICHMENTS**")
            st.dataframe(
                [
                    {
                        "Provider": e.provider,
                        "Reputation": e.reputation_score,
                        "Tags": ", ".join(e.tags),
                    }
                    for e in pub.enrichments
                ],
                use_container_width=True,
                hide_index=True,
            )

        if pub.ai_narrative is not None:
            st.divider()
            ai = pub.ai_narrative
            st.markdown("**AI-GENERATED ADVISORY** *(review required)*")
            st.info(strip_terminal_controls(ai.summary))

            meta1, meta2, meta3 = st.columns(3)
            meta1.metric("FP Likelihood", ai.false_positive_likelihood)
            meta2.metric("AI Confidence", ai.confidence)
            meta3.metric("Model", strip_terminal_controls(ai.model))

            if ai.suggested_actions:
                st.markdown("**Suggested Actions**")
                for action in ai.suggested_actions:
                    st.write("- " + strip_terminal_controls(action))

        st.divider()
        with st.expander("RAW PUBLIC DTO (JSON)", expanded=False):
            st.json(pub.model_dump(mode="json"))


def _render_welcome_state() -> None:
    """Render the welcome/empty state when no sweep has been run."""
    st.markdown(
        """
    <div style="text-align: center; padding: 3rem 2rem;">
        <svg width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="#2d4a6f" stroke-width="1.5" style="margin-bottom: 1.5rem;">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <h3 style="color: #ffffff; margin-bottom: 0.5rem;">Ready to Analyze</h3>
        <p style="color: #8ba3c7; max-width: 400px; margin: 0 auto;">
            Upload an IOC feed and a log file in the sidebar, configure your sweep settings, 
            then click <strong>RUN SWEEP</strong> to begin analysis.
        </p>
    </div>
    """,
        unsafe_allow_html=True,
    )


def main() -> None:
    """Main application entry point."""
    st.set_page_config(
        page_title=_PAGE_TITLE,
        layout="wide",
        page_icon="shield",
        initial_sidebar_state="expanded",
    )

    # Inject dark theme CSS
    _inject_css()

    # Load settings
    settings = _load_settings_or_stop()

    # Render sidebar and get form data
    form = _sidebar(settings)

    # Execute sweep if form submitted
    result = None
    if form is not None:
        result = _execute_sweep(form, settings)

    # Render header stats bar
    _render_header_stats(result)

    # Security & privacy info
    _security_privacy_box()

    # Main content area
    if form is None:
        _render_welcome_state()
    elif result is None:
        st.error("Sweep execution failed. Check the error messages above.")
    else:
        _render_results(result, form["output_mode"])


# Streamlit executes the script top-to-bottom on every interaction.
main()
