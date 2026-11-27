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

    text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
    text = re.sub(r"\*(.*?)\*", r"\1", text)
    text = re.sub(r"__(.*?)__", r"\1", text)
    text = re.sub(r"`(.*?)`", r"\1", text)

    return text

def add_page_number(canvas, doc):
    canvas.saveState()

    canvas.setFont(
        "Helvetica",
        9,
    )

    canvas.drawRightString(
        550,
        20,
        f"Page {canvas.getPageNumber()}"
    )

    canvas.restoreState()

def markdown_to_pdf(
    markdown_text: str,
    output_pdf: Path,
):

    if SimpleDocTemplate is None:
        return

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="ARCHeading1",
            parent=styles["Heading1"],
            textColor=colors.HexColor("#003366"),
            spaceAfter=12,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ARCHeading2",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#005A9E"),
            spaceBefore=10,
            spaceAfter=6,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ARCBullet",
            parent=styles["BodyText"],
            leftIndent=20,
            bulletIndent=10,
        )
    )

    doc = SimpleDocTemplate(
        str(output_pdf),
        pagesize=letter,
        topMargin=40,
        bottomMargin=40,
        leftMargin=40,
        rightMargin=40,
    )

    elements = []

 #   elements.append(
 #       Paragraph(
 #           "ARC Cloud Security Assessment Report",
 #           styles["Title"],
 #       )
 #   )

 #   elements.append(
 #       Spacer(1, 30)
 #   )

 #   elements.append(
 #       Paragraph(
 #           time.strftime(
 #               "Generated: %Y-%m-%d"
 #           ),
 #           styles["BodyText"],
 #       )
 #   )

 #   elements.append(PageBreak())

    first_line = True

    for line in markdown_text.splitlines():

        line = clean_markdown(line.strip())

        if line.strip() in [
            "---",
            "----",
            "-----",
        ]:
            continue

        if (
            first_line
            and "assessment report"
            in line.lower()
        ):
            first_line = False
            continue

        first_line = False

        if not line:
            elements.append(Spacer(1, 6))
            continue

        if line.startswith("# "):
            elements.append(
                Paragraph(
                    line[2:],
                    styles["ARCHeading1"],
                )
            )
            elements.append(Spacer(1, 10))
            continue

        if line.startswith("## "):
            elements.append(
                Paragraph(
                    line[3:],
                    styles["ARCHeading2"],
                )
            )
            continue

        if line.startswith("### "):
            elements.append(
                Paragraph(
                    line[4:],
                    styles["Heading3"],
                )
            )
            continue

        if line.startswith("- "):
            elements.append(
                Paragraph(
                    f"• {line[2:]}",
                    styles["ARCBullet"],
                )
            )
            continue

        elements.append(
            Paragraph(
                line,
                styles["BodyText"],
            )
        )

 #   doc.build(elements)
    doc.build(
        elements,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number,
    )


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
