#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import re
import sys
import time
import reportlab
from pathlib import Path
from typing import List

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib.units import inch
from xml.sax.saxutils import escape

import pandas as pd

# ============================================================
# Azure OpenAI
# ============================================================

try:
    from openai import AzureOpenAI
except ImportError:
    AzureOpenAI = None

# ============================================================
# Reportlab
# ============================================================

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        PageBreak,
        Table,
        TableStyle,
        KeepTogether,
        HRFlowable,
    )
    from reportlab.lib.styles import getSampleStyleSheet
except ImportError:
    SimpleDocTemplate = None

# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

AZURE_OPENAI_ENDPOINT = os.getenv(
    "AZURE_OPENAI_ENDPOINT",
    ""
).strip()

AZURE_OPENAI_API_KEY = os.getenv(
    "AZURE_OPENAI_API_KEY",
    ""
).strip()

AZURE_OPENAI_MODEL = os.getenv(
    "AZURE_OPENAI_MODEL",
    ""
).strip()

AZURE_OPENAI_API_VERSION = os.getenv(
    "AZURE_OPENAI_API_VERSION",
    "2024-10-21",
).strip()

TEMPERATURE = float(
    os.getenv(
        "AI_TEMPERATURE",
        "0.1"
    )
)

MAX_FINDINGS_PER_SUBSCRIPTION = int(
    os.getenv(
        "MAX_FINDINGS_PER_SUBSCRIPTION",
        "100"
    )
)

REQUEST_INTERVAL_SECONDS = float(
    os.getenv(
        "AI_REQUEST_INTERVAL_SECONDS",
        "4"
    )
)

def calculate_risk_score(
    findings_df: pd.DataFrame,
):

    score = (
        (
            findings_df["SEVERITY"]
            == "Critical"
        ).sum() * 10
        +
        (
            findings_df["SEVERITY"]
            == "High"
        ).sum() * 5
        +
        (
            findings_df["SEVERITY"]
            == "Medium"
        ).sum() * 2
    )

    score = min(
        100,
        int(score),
    )

    if score >= 70:
        risk_level = "RED"

    elif score >= 35:
        risk_level = "ORANGE"

    else:
        risk_level = "GREEN"

    return (
        score,
        risk_level,
    )


def build_resource_group_summary(
    findings_df: pd.DataFrame,
) -> str:

    summary = (
        findings_df
        .pivot_table(
            index="RESOURCE_GROUP",
            columns="SEVERITY",
            values="CHECK_ID",
            aggfunc="count",
            fill_value=0,
        )
        .reset_index()
    )

    for sev in [
        "Critical",
        "High",
        "Medium",
    ]:
        if sev not in summary.columns:
            summary[sev] = 0


    summary["TOTAL"] = (
        summary[
            [
                "Critical",
                "High",
                "Medium",
            ]
        ]
        .sum(axis=1)
    )

    summary = summary.sort_values(
        "TOTAL",
        ascending=False,
    )

    return summary.to_csv(
        index=False
    )

def clean_markdown(text: str) -> str:
    """Normalize markdown without stripping useful inline emphasis."""
    return text.strip()


def markdown_inline_to_reportlab(text: str) -> str:
    """Convert a safe subset of Markdown inline syntax to ReportLab markup."""
    text = escape(str(text))
    # Inline code first so emphasis markers inside code are not interpreted.
    code_parts = []
    def hold_code(match):
        code_parts.append(match.group(1))
        return f"\x00CODE{len(code_parts)-1}\x00"
    text = re.sub(r"`([^`]+)`", hold_code, text)
    text = re.sub(r"\*\*(.+?)\*\*|__(.+?)__", lambda m: f"<b>{m.group(1) or m.group(2)}</b>", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)|(?<!_)_([^_]+)_(?!_)", lambda m: f"<i>{m.group(1) or m.group(2)}</i>", text)
    for i, value in enumerate(code_parts):
        text = text.replace(f"\x00CODE{i}\x00", f'<font name="Courier" size="8">{value}</font>')
    return text


def add_page_number(canvas, doc):
    canvas.saveState()
    page_width, _ = letter
    canvas.setStrokeColor(colors.HexColor("#D9E2F0"))
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, 32, page_width - doc.rightMargin, 32)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.drawString(doc.leftMargin, 20, "ARC  |  CLOUD SECURITY ASSESSMENT")
    canvas.drawRightString(page_width - doc.rightMargin, 20, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


def _is_markdown_table_row(line: str) -> bool:
    return line.strip().startswith("|") and line.strip().endswith("|")


def _parse_markdown_table(lines, styles, available_width):
    rows = []
    for line in lines:
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        # Ignore Markdown alignment separator rows.
        if cells and all(re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) for cell in cells):
            continue
        row_style = styles["ARCTableHeader"] if not rows else styles["ARCTableCell"]
        rows.append([Paragraph(markdown_inline_to_reportlab(cell), row_style) for cell in cells])
    if not rows:
        return None
    col_count = max(len(row) for row in rows)
    for row in rows:
        row.extend([Paragraph("", styles["ARCTableCell"])] * (col_count - len(row)))
    # Equal widths are predictable for variable LLM-generated tables.
    widths = [available_width / col_count] * col_count
    table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123B5D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D7E0EA")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F3F6FA")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def markdown_to_pdf(
    markdown_text: str,
    output_pdf: Path,
    subscription_name: str | None = None,
    findings_df: pd.DataFrame | None = None,
):
    """Render the LLM's Markdown assessment as a styled technical PDF.

    The Markdown file remains the source of truth; this function only changes
    its PDF presentation. Existing two-argument calls remain supported.
    """
    if SimpleDocTemplate is None:
        raise RuntimeError("ReportLab is required to generate PDF reports")

    styles = getSampleStyleSheet()
    navy = colors.HexColor("#123B5D")
    blue = colors.HexColor("#176B9A")
    slate = colors.HexColor("#334155")
    muted = colors.HexColor("#64748B")

    styles.add(ParagraphStyle(name="ARCHeading1", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=19, leading=23, textColor=navy, spaceBefore=8, spaceAfter=12, keepWithNext=True))
    styles.add(ParagraphStyle(name="ARCHeading2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=blue, spaceBefore=13, spaceAfter=7, keepWithNext=True))
    styles.add(ParagraphStyle(name="ARCHeading3", parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=slate, spaceBefore=9, spaceAfter=5, keepWithNext=True))
    styles.add(ParagraphStyle(name="ARCBody", parent=styles["BodyText"], fontName="Helvetica", fontSize=9, leading=13, textColor=slate, spaceAfter=6))
    styles.add(ParagraphStyle(name="ARCBullet", parent=styles["ARCBody"], leftIndent=15, firstLineIndent=-8, bulletIndent=2, spaceAfter=4))
    styles.add(ParagraphStyle(name="ARCTableCell", parent=styles["BodyText"], fontName="Helvetica", fontSize=7.4, leading=9.2, textColor=slate, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="ARCTableHeader", parent=styles["ARCTableCell"], fontName="Helvetica-Bold", textColor=colors.white))
    styles.add(ParagraphStyle(name="ARCCallout", parent=styles["ARCBody"], fontSize=9, leading=13, textColor=navy, backColor=colors.HexColor("#EAF2F8"), borderColor=colors.HexColor("#B7CDE0"), borderWidth=0.6, borderPadding=8, spaceBefore=5, spaceAfter=10))
    # KPI cards use separate paragraph styles so large values cannot collide
    # with their labels or supporting risk text.
    styles.add(ParagraphStyle(name="ARCKpiLabel", parent=styles["ARCBody"], fontName="Helvetica-Bold", fontSize=6.5, leading=8, textColor=muted, spaceAfter=3, alignment=1))
    styles.add(ParagraphStyle(name="ARCKpiValue", parent=styles["ARCBody"], fontName="Helvetica-Bold", fontSize=16, leading=19, textColor=navy, spaceAfter=1, alignment=1))
    styles.add(ParagraphStyle(name="ARCKpiSub", parent=styles["ARCBody"], fontName="Helvetica-Bold", fontSize=6.5, leading=8, textColor=blue, alignment=1))

    doc = SimpleDocTemplate(
        str(output_pdf), pagesize=letter,
        topMargin=0.62 * inch, bottomMargin=0.58 * inch,
        leftMargin=0.62 * inch, rightMargin=0.62 * inch,
        title=f"Cloud Security Assessment - {subscription_name or 'Subscription'}",
        author="ARC Cloud Security Assessment",
    )
    elements = []
    generated = time.strftime("%B %d, %Y")
    title = subscription_name or "Azure Subscription Security Assessment"

    # Report masthead and compact posture summary, using only calculated inputs.
    elements.append(Paragraph("ARC  /  CLOUD SECURITY", ParagraphStyle("ARCMasthead", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8, textColor=blue, spaceAfter=7)))
    elements.append(Paragraph(markdown_inline_to_reportlab(title), styles["ARCHeading1"]))
    elements.append(Paragraph(f"Technical Security Assessment  &nbsp;|&nbsp;  Generated {escape(generated)}", ParagraphStyle("ARCMeta", parent=styles["ARCBody"], fontSize=8, textColor=muted, spaceAfter=12)))

    if findings_df is not None:
        severity = findings_df.get("SEVERITY", pd.Series(dtype=str)).value_counts()
        score, level = calculate_risk_score(findings_df)
        rg_count = findings_df.get("RESOURCE_GROUP", pd.Series(dtype=str)).replace("", pd.NA).nunique()
        kpi_data = [[
            [
                Paragraph("SUBSCRIPTION RISK SCORE", styles["ARCKpiLabel"]),
                Paragraph(f"{score}/100", styles["ARCKpiValue"]),
                Paragraph(f"{level} RISK", styles["ARCKpiSub"]),
            ],
            [
                Paragraph("CRITICAL", styles["ARCKpiLabel"]),
                Paragraph(str(int(severity.get("Critical", 0))), styles["ARCKpiValue"]),
            ],
            [
                Paragraph("HIGH", styles["ARCKpiLabel"]),
                Paragraph(str(int(severity.get("High", 0))), styles["ARCKpiValue"]),
            ],
            [
                Paragraph("MEDIUM", styles["ARCKpiLabel"]),
                Paragraph(str(int(severity.get("Medium", 0))), styles["ARCKpiValue"]),
            ],
            [
                Paragraph("RESOURCE GROUPS", styles["ARCKpiLabel"]),
                Paragraph(str(int(rg_count)), styles["ARCKpiValue"]),
            ],
        ]]
        kpi = Table(kpi_data, colWidths=[1.55*inch, 1.08*inch, 1.08*inch, 1.08*inch, 1.25*inch])
        kpi.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
            ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#D7E0EA")),
            ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D7E0EA")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ]))
        elements.extend([kpi, Spacer(1, 14)])
        elements.append(Paragraph(f"Assessment scope: failed Critical, High, and Medium checks, limited to the first {MAX_FINDINGS_PER_SUBSCRIPTION} findings per subscription by the configured report cap. The score is capped at 100 using the existing severity weights and thresholds.", styles["ARCCallout"]))

    lines = markdown_text.splitlines()
    first_line = True
    i = 0
    while i < len(lines):
        raw = lines[i].strip()
        line = clean_markdown(raw)
        if first_line and line and "assessment report" in line.lower() and not line.startswith("#"):
            first_line = False
            i += 1
            continue
        first_line = False

        if not line:
            elements.append(Spacer(1, 4))
            i += 1
            continue
        if line in {"---", "----", "-----"}:
            elements.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#CBD5E1"), spaceBefore=5, spaceAfter=8))
            i += 1
            continue
        if _is_markdown_table_row(line):
            table_lines = []
            while i < len(lines) and _is_markdown_table_row(lines[i].strip()):
                table_lines.append(lines[i].strip())
                i += 1
            table = _parse_markdown_table(table_lines, styles, doc.width)
            if table is not None:
                elements.extend([table, Spacer(1, 9)])
            continue
        if line.startswith("### "):
            elements.append(Paragraph(markdown_inline_to_reportlab(line[4:]), styles["ARCHeading3"]))
        elif line.startswith("## "):
            elements.append(Paragraph(markdown_inline_to_reportlab(line[3:]), styles["ARCHeading2"]))
        elif line.startswith("# "):
            elements.append(Paragraph(markdown_inline_to_reportlab(line[2:]), styles["ARCHeading1"]))
        elif line.startswith(("- ", "* ")):
            elements.append(Paragraph("• &nbsp;" + markdown_inline_to_reportlab(line[2:]), styles["ARCBullet"]))
        elif re.match(r"^\d+[.)]\s+", line):
            number, content = re.match(r"^(\d+[.)])\s+(.*)$", line).groups()
            elements.append(Paragraph(f"<b>{escape(number)}</b> &nbsp;" + markdown_inline_to_reportlab(content), styles["ARCBullet"]))
        elif line.startswith("> "):
            elements.append(Paragraph(markdown_inline_to_reportlab(line[2:]), styles["ARCCallout"]))
        else:
            elements.append(Paragraph(markdown_inline_to_reportlab(line), styles["ARCBody"]))
        i += 1

    doc.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)


# ============================================================
# LOGGING
# ============================================================

def log(message: str) -> None:
    print(
        f"[02-cloud-ai] {message}",
        flush=True,
    )

def fail(message: str) -> None:
    print(
        f"[02-cloud-ai][ERROR] {message}",
        file=sys.stderr,
    )
    sys.exit(1)

# ============================================================
# OPENAI
# ============================================================

def validate_openai_config():

    missing = []

    if not AZURE_OPENAI_ENDPOINT:
        missing.append(
            "AZURE_OPENAI_ENDPOINT"
        )

    if not AZURE_OPENAI_API_KEY:
        missing.append(
            "AZURE_OPENAI_API_KEY"
        )

    if not AZURE_OPENAI_MODEL:
        missing.append(
            "AZURE_OPENAI_MODEL"
        )

    if missing:
        fail(
            "Missing Azure OpenAI configuration: "
            + ", ".join(missing)
        )

    if AzureOpenAI is None:
        fail(
            "openai library not installed"
        )

def create_openai_client():

    validate_openai_config()

    return AzureOpenAI(
        api_key=AZURE_OPENAI_API_KEY,
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        api_version=AZURE_OPENAI_API_VERSION,
    )

# ============================================================
# PROMPT
# ============================================================

def load_prompt(
    prompt_file: Path,
) -> str:

    if not prompt_file.exists():

        fail(
            f"Prompt file not found: "
            f"{prompt_file}"
        )

    return prompt_file.read_text(
        encoding="utf-8"
    )

# ============================================================
# SUBSCRIPTION FILTERING
# ============================================================

def prepare_subscription_df(
    df: pd.DataFrame,
) -> pd.DataFrame:

    severity_order = {
        "Critical": 1,
        "High": 2,
        "Medium": 3,
    }

    df = df.copy()

    # Keep only failed findings
    df = df[
        (
            df["STATUS"]
            .str.upper()
            == "FAIL"
        )
        &
        (
            df["SEVERITY"].isin(
                [
                    "Critical",
                    "High",
                    "Medium",
                ]
            )
        )
    ]

    df["SORT_ORDER"] = (
        df["SEVERITY"]
        .map(severity_order)
        .fillna(99)
    )

    df = df.sort_values(
        [
            "SORT_ORDER",
            "CATEGORY",
        ]
    )

  #  sub_df = sub_df[
  #      sub_df["STATUS"]
  #      .str.upper()
  #      == "FAIL"
  #  ]

    return df.head(
        MAX_FINDINGS_PER_SUBSCRIPTION
    )

# ============================================================
# LLM
# ============================================================

def build_prompt_data(
    subscription_name: str,
    findings_df: pd.DataFrame,
) -> str:

    resource_group_summary = (
        build_resource_group_summary(
            findings_df
        )
    )

    cols = [
        "STATUS",
        "RESOURCE_GROUP",
        "RESOURCE_TYPE",
        "RESOURCE_NAME",
        "CHECK_ID",
        "CHECK_TITLE",
        "SEVERITY",
        "CATEGORY",
        "DESCRIPTION",
        "RISK",
        "REMEDIATION",
    ]

 #   return (
 #       f"SUBSCRIPTION: "
 #       f"{subscription_name}\n\n"
 #       f"FAILED_FINDINGS:\n"
 #       + findings_df[cols].to_csv(index=False)
 #   )

    return (
        f"SUBSCRIPTION: "
        f"{subscription_name}\n\n"
        f"RESOURCE_GROUP_SUMMARY:\n"
        f"{resource_group_summary}\n\n"
        f"FAILED_FINDINGS:\n"
        + findings_df[cols].to_csv(index=False)
    )

def analyze_subscription(
    client,
    prompt_template: str,
    subscription_name: str,
    findings_df: pd.DataFrame,
) -> str:

    findings_payload = (
        build_prompt_data(
            subscription_name,
            findings_df,
        )
    )

    risk_score, risk_level = (
        calculate_risk_score(
            findings_df
        )
    )

    findings_payload = (
        f"RISK_SCORE: "
        f"{risk_score}\n"
        f"RISK_LEVEL: "
        f"{risk_level}\n\n"
        + findings_payload
    )

    response = (
        client.chat.completions.create(
            model=AZURE_OPENAI_MODEL,
            temperature=TEMPERATURE,
            messages=[
                {
                    "role": "system",
                    "content":
                        prompt_template,
                },
                {
                    "role": "user",
                    "content":
                        findings_payload,
                },
            ]
        )
    )

    return (
        response
        .choices[0]
        .message
        .content
    )

# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        required=True,
    )

    parser.add_argument(
        "--output",
        required=True,
    )

    parser.add_argument(
        "--prompt",
        default="cloudsec_analysis_prompt.md",
    )

    args = parser.parse_args()

    input_csv = Path(
        args.input
    )

    output_dir = Path(
        args.output
    )

    prompt_file = Path(
        args.prompt
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    subscriptions_dir = (
        output_dir
        / "subscriptions"
    )

    subscriptions_dir.mkdir(
        exist_ok=True
    )

    log(
        f"Loading inventory: "
        f"{input_csv}"
    )

    df = pd.read_csv(
        input_csv,
        dtype=str,
        keep_default_na=False,
    )

#    print("\nCSV COLUMNS:")
#    print(df.columns.tolist())
#    print()

#    manual_df = df[
#        df["STATUS"]
#        .str.upper()
#        == "MANUAL"
#    ].copy()

#    log(
#        f"Manual findings: {len(manual_df)}"
#    )

#    manual_findings = manual_df[
#        [
#            "CHECK_ID",
#            "CHECK_TITLE",
#        ]
#    ].to_csv(index=False)

    prompt_template = (
        load_prompt(
            prompt_file
        )
    )

    client = (
        create_openai_client()
    )

    results = []

    subscriptions = sorted(
        df[
            "SUBSCRIPTION_NAME"
        ]
        .dropna()
        .unique()
    )

    log(
        f"Found "
        f"{len(subscriptions)} "
        f"subscriptions"
    )

    for subscription_name in subscriptions:

        log(
            f"Analyzing subscription: "
            f"{subscription_name}"
        )

        sub_df = df[
            df["SUBSCRIPTION_NAME"]
            == subscription_name
        ].copy()

        sub_df = prepare_subscription_df(
            sub_df
        )

        if sub_df.empty:

            log(
                f"Skipping "
                f"{subscription_name} "
                f"(no Critical/High/Medium failed findings)"
            )

            continue

        try:

            report = analyze_subscription(
                client=client,
                prompt_template=prompt_template,
                subscription_name=subscription_name,
                findings_df=sub_df,
            )

#            safe_name = re.sub(
#                r"[^A-Za-z0-9_.-]",
#                "_",
#                subscription_name,
#            )

            safe_name = re.sub(
                r"[^A-Za-z0-9_.-]",
                "_",
                subscription_name,
            )

            if "unknown_tenant_domain" in safe_name.lower():
                safe_name = "tenant"

            report_dir = (
                subscriptions_dir
                / safe_name
            )

            report_dir.mkdir(
                parents=True,
                exist_ok=True,
            )

            md_report = (
                report_dir
                / "security_report.md"
            )

            pdf_report = (
                report_dir
                / "security_report.pdf"
            )

            md_report.write_text(
                report,
                encoding="utf-8",
            )

            markdown_to_pdf(
                report,
                pdf_report,
                subscription_name=subscription_name,
                findings_df=sub_df,
            )

            results.append(
                {
                    "SUBSCRIPTION_NAME":
                        subscription_name,
                    "TOTAL_FINDINGS":
                        len(sub_df),
                    "STATUS":
                        "SUCCESS",
                    "MARKDOWN_REPORT":
                        str(md_report),
                    "PDF_REPORT":
                        str(pdf_report),
                    "ERROR":
                        "",
                }
            )

            log(
                f"Created reports: "
                f"{md_report}, {pdf_report}"
            )

        except Exception as exc:

            log(
                f"FAILED: "
                f"{subscription_name}"
            )

            log(
                str(exc)
            )

            results.append(
                {
                    "SUBSCRIPTION_NAME":
                        subscription_name,
                    "TOTAL_FINDINGS":
                        len(sub_df),
                    "STATUS":
                        "FAILED",
                    "REPORT_FILE":
                        "",
                    "ERROR":
                        str(exc),
                }
            )

        time.sleep(
            REQUEST_INTERVAL_SECONDS
        )

    # ========================================================
    # SUMMARY CSV
    # ========================================================

    summary_df = pd.DataFrame(
        results
    )

    summary_csv = (
        output_dir
        / "cloud_llm_analysis.csv"
    )

    summary_df.to_csv(
        summary_csv,
        index=False,
    )

    successful = len(
        summary_df[
            summary_df["STATUS"]
            == "SUCCESS"
        ]
    )

    failed = len(
        summary_df[
            summary_df["STATUS"]
            == "FAILED"
        ]
    )

    total_findings = 0

    if not summary_df.empty:
        total_findings = (
            summary_df[
                "TOTAL_FINDINGS"
            ]
            .fillna(0)
            .astype(int)
            .sum()
        )

    report_count = len(
        list(
            subscriptions_dir.rglob(
                "security_report.pdf"
            )
        )
    )

    print()
    print(
        "=" * 60
    )

    print(
        "Cloud ARC AI Analysis Complete"
    )

    print(
        "=" * 60
    )

    print()

    print(
        f"Subscriptions Processed: "
        f"{len(subscriptions)}"
    )

    print(
        f"Successful Reports: "
        f"{successful}"
    )

    print(
        f"Failed Reports: "
        f"{failed}"
    )

    print(
        f"Findings Analyzed: "
        f"{total_findings}"
    )

    print(
        f"Reports Generated: "
        f"{report_count}"
    )

    print()

    print(
        f"Summary CSV:"
    )

    print(
        f"  {summary_csv}"
    )

    print()

    print(
        f"Subscription Reports:"
    )

    for report_file in sorted(
        subscriptions_dir.rglob(
            "security_report.pdf"
        )
    ):
        print(
            f"  {report_file}"
        )

    print()

    print(
        "=" * 60
    )

    # --------------------------------------------------------
    # Exit Code
    # --------------------------------------------------------

    if successful == 0:

        fail(
            "No subscription reports were generated."
        )

    if failed > 0:

        log(
            f"{failed} subscriptions failed "
            f"during AI analysis."
        )

    return


if __name__ == "__main__":
    main()
