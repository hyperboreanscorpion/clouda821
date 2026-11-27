#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

import matplotlib.pyplot as plt
import seaborn as sns

from reportlab.platypus import (
    Image,
)

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate,
    Spacer,
    Paragraph,
    PageBreak,
    Table,
    TableStyle,
)

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.styles import ParagraphStyle

from datetime import datetime

EXPOSURE_KEYWORDS = {

    "Public Exposure": [
        "public",
        "internet",
        "anonymous",
        "external",
        "public network access",
    ],

    "Identity Exposure": [
        "mfa",
        "conditional access",
        "privileged",
        "global administrator",
        "owner",
        "service principal",
        "local accounts",
        "disable local accounts",
    ],

    "Network Exposure": [
        "0.0.0.0/0",
        "any source",
        "network security group",
        "nsg",
        "firewall",
        "restrict network access",
        "network access",
        "public network access",
    ],

    "Data Exposure": [
        "storage",
        "key vault",
        "secret",
        "unencrypted",
        "purge protection",
        "soft delete",
        "encryption",
    ],

    "Security Coverage Gap": [
        "defender",
        "monitoring",
        "logging",
        "diagnostic",
        "activity log",
        "alert",
    ],
}

def wrap_table_dataframe(
    df,
    styles,
    style_name="SmallText",
):
    wrapped = []

    wrapped.append(
        [
            Paragraph(
                str(col),
    #            styles[style_name],
                styles["SmallHeader"]
            )
            for col in df.columns
        ]
    )

    for _, row in df.iterrows():

        wrapped.append(
            [
                Paragraph(
                    str(value),
                    styles[style_name],
                )
                for value in row
            ]
        )

    return wrapped

def build_attention_section(
    inventory,
    scorecards_df,
    resourcegroup_df,
):
    
    items = []

    critical_count = (
        inventory["SEVERITY"]
        == "Critical"
    ).sum()

    high_count = (
        inventory["SEVERITY"]
        == "High"
    ).sum()

    highest_risk_subscription = scorecards_df.iloc[0]["Subscription"] if scorecards_df is not None and not scorecards_df.empty else "N/A"

    highest_risk_rg = resourcegroup_df.iloc[0]["Resource Group"] if resourcegroup_df is not None and not resourcegroup_df.empty else "N/A"

    if critical_count > 0:

        items.append(
            f"{critical_count} Critical cloud finding(s) require immediate remediation. See Critical Exposure(s) table below."
        )

#    if high_count > 100:

#        items.append(
#            f"{high_count} High findings remain open across the environment."
#        )

 #   items.append(
 #       f"Highest risk subscription: "
 #       f"{highest_risk_subscription}."
 #   )

 #   items.append(
 #       f"Highest risk resource group: "
 #       f"{highest_risk_rg}."
 #   )

    return items

def build_exec_summary(
    metrics_df,
    scorecards_df,
    trending_summary=None,
):

    critical_assigned = 0
    critical_unassigned = 0

    critical_assigned = (
        metrics_df[
            metrics_df["Metric"] ==
            "Critical Findings Assigned"
        ]["Value"].iloc[0]
    )

    critical_unassigned = (
        metrics_df[
            metrics_df["Metric"] ==
            "Critical Findings Unassigned"
        ]["Value"].iloc[0]
    )

    overall_risk = (
        metrics_df[
            metrics_df["Metric"]
            == "Overall Risk"
        ]["Value"].iloc[0]
    )

    portfolio_score = (
        metrics_df[
            metrics_df["Metric"]
            == "Portfolio Risk Score"
        ]["Value"].iloc[0]
    )

    top_sub = scorecards_df.iloc[0]["Subscription"] if scorecards_df is not None and not scorecards_df.empty else "N/A"

    top_category = scorecards_df.iloc[0]["Top Category"] if scorecards_df is not None and not scorecards_df.empty and "Top Category" in scorecards_df.columns else "N/A"

    subscription_count = (
        metrics_df[
            metrics_df["Metric"]
            == "Subscriptions"
        ]["Value"].iloc[0]
    )

    trend_text = ""

    if trending_summary is not None:

        try:

            previous = int(
                trending_summary[
                    trending_summary["Metric"]
                    == "Previous Findings"
                ]["Value"].iloc[0]
            )

            current = int(
                trending_summary[
                    trending_summary["Metric"]
                    == "Current Findings"
                ]["Value"].iloc[0]
            )

            resolved = int(
                trending_summary[
                    trending_summary["Metric"]
                    == "Resolved Findings"
                ]["Value"].iloc[0]
            )

            new_findings = int(
                trending_summary[
                    trending_summary["Metric"]
                    == "New Findings"
                ]["Value"].iloc[0]
            )

            if current < previous:
                trend = "Improving"

            elif current > previous:
                trend = "Worsening"

            else:
                trend = "Stable"

            if previous > 0:

                risk_change_pct = round(
                    (
                        (current - previous)
                        / previous
                    ) * 100,
                    1,
                )

            else:

                risk_change_pct = 0

            trend_text = (
                f"Overall trend is {trend}. "
                f"Finding volume changed by "
                f"{risk_change_pct}% since the "
                f"previous assessment. "
            )

        except Exception:
            pass

    return (
        f"The cloud security assessment identified findings "
        f"across {subscription_count} Azure subscriptions."
        f"<br/><br/>"

        f"Overall cloud risk is "
        f"{overall_risk} "
        f"(Portfolio Risk Score: "
        f"{portfolio_score}/100)."
        f"<br/><br/>"

        f"{trend_text}"

        f"The highest risk Azure subscription is "
        f"{top_sub}."
        f"<br/><br/>"

        f"Within the highest-risk subscription, the largest "
        f"finding category is {top_category}. Review the "
        f"subscription scorecard for the wider portfolio distribution."
        f"<br/><br/>"

        f"The assessment identified "
        f"{metrics_df[metrics_df['Metric']=='Criticals']['Value'].iloc[0]} "
        f"Critical-severity finding(s) requiring priority remediation."
        f"<br/><br/>"

        f"{critical_assigned} Critical finding(s) have an "
        f"identified accountable owner; {critical_unassigned} "
        f"Critical finding(s) remain unassigned."
        f"<br/><br/>"

        f"Engineering efforts should prioritize remediation "
        f"of the highest-risk subscriptions and resource groups."
    )

def risk_level(score):

    if score >= 70:
        return "RED"

    if score >= 35:
        return "ORANGE"

    return "GREEN"

def generate_trend_charts(
    output_dir,
    history_file,
):

    charts = {}

    if not history_file.exists():

        return charts

    history_df = pd.read_csv(
        history_file
    )

    history_df[
        "PortfolioRiskScore"
    ] = pd.to_numeric(
        history_df[
            "PortfolioRiskScore"
        ],
        errors="coerce",
    )

    if len(history_df) < 2:

        return charts

    trend_chart = (
        output_dir /
        "portfolio_risk_trend.png"
    )

    history_df[
        "AssessmentDate"
    ] = pd.to_datetime(
        history_df[
            "AssessmentDate"
        ]
    )

    history_df = (
        history_df
        .sort_values(
            "AssessmentDate"
        )
    )

    plt.figure(
        figsize=(8, 4)
    )

    plt.plot(
        history_df[
            "AssessmentDate"
        ],
        history_df[
            "PortfolioRiskScore"
        ],
        marker="o",
        linewidth=2,
        color="#005A9E",
    )

    plt.title(
        "Risk Trend"
    )

    plt.ylabel(
        "Risk Score"
    )

    plt.xlabel(
        "Assessment Date"
    )

    plt.grid(
        True,
        alpha=0.3,
    )

    plt.tight_layout()

    plt.savefig(
        trend_chart
    )

    print(trend_chart)
    print(trend_chart.exists())

    plt.close()

    charts[
        "portfolio_trend"
    ] = trend_chart

    return charts

def generate_charts(
    inventory,
    scorecards_df,
    resourcegroup_df,
    output_dir,
):

    charts = {}

    severity_chart = (
        output_dir /
        "top_resource_groups.png"
    )

 #   top_rgs = (
 #       resourcegroup_df[
 #           resourcegroup_df[
 #               "Resource Group"
 #           ] != "Tenant"
 #       ]
 #       .head(10)
 #   )

    top_rgs = resourcegroup_df.head(10) if not resourcegroup_df.empty else pd.DataFrame(columns=["Resource Group", "Risk Score"])
    if not top_rgs.empty:
        plt.figure(figsize=(10, 6))
        plt.barh(top_rgs["Resource Group"], top_rgs["Risk Score"], color="#0078D4")
        plt.title("Highest Risk Azure Resource Groups")
        plt.xlabel("Risk Score")
        plt.gca().invert_yaxis()
        plt.tight_layout()
        plt.savefig(severity_chart, dpi=180, bbox_inches="tight")
        plt.close()
        charts["resource_groups"] = severity_chart

    # ====================================================
    # Top Risk Resource Groups
    # ====================================================

    top_subs = scorecards_df.head(10) if not scorecards_df.empty else pd.DataFrame(columns=["Subscription", "Risk Score"])

    sub_chart = (
        output_dir /
        "top_risk_subscriptions.png"
    )

    if not top_subs.empty:
        plt.figure(figsize=(8, 5))
        plt.barh(top_subs["Subscription"], top_subs["Risk Score"], color="#0078D4")
        plt.title("Highest Risk Azure Subscriptions")
        plt.xlabel("Risk Score")
        plt.gca().invert_yaxis()
        plt.tight_layout()
        plt.savefig(sub_chart, dpi=180, bbox_inches="tight")
        plt.close()
        charts["subscriptions"] = sub_chart

    # ====================================================
    # Category Breakdown
    # ====================================================

    category_counts = (
        inventory["CATEGORY"]
        .value_counts()
        .head(10)
    )

    category_chart = (
        output_dir /
        "category_breakdown.png"
    )

    plt.figure(figsize=(7, 4))

    category_counts.plot(
        kind="bar",
        color="#005A9E",
    )

    plt.title(
        "Azure Resource Categories"
    )

    plt.ylabel("Findings")

    plt.tight_layout()

    plt.savefig(category_chart)

    plt.close()

    charts["categories"] = category_chart

    # ====================================================
    # Severity Heatmap
    # ====================================================

    heatmap = pd.crosstab(
        inventory["CATEGORY"],
        inventory["SEVERITY"],
    )

    heatmap_chart = (
        output_dir /
        "risk_heatmap.png"
    )

    plt.figure(figsize=(10, 6))

    sns.heatmap(
        heatmap,
        annot=True,
        cmap="Reds",
        fmt="g",
    )

    plt.title(
        "Azure Resource Security Issue Heatmap"
    )

    plt.tight_layout()

    plt.savefig(heatmap_chart)

    plt.close()

    charts["heatmap"] = heatmap_chart

    return charts

# ============================================================
# CONFIG
# ============================================================

risk_reduction_pct = "N/A"

MONITORING_KEYWORDS = [
    "monitor",
    "activity log",
    "alert",
    "diagnostic setting",
    "network watcher",
]

SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 5,
    "Medium": 2,
#    "Low": 1,
}

CATEGORY_WEIGHTS = {

    # Highest Risk
    "Identity & Access": 1.00,
    "Networking": 1.00,
    "Storage": 1.00,
    "Storage Accounts": 1.00,
    "Key Management": 1.00,
    "Threat Protection": 1.00,

    # Moderate Risk
    "Compute": 0.7,
    "Containers": 0.6,
    "Application Services": 0.8,
    "Databases": 1.0,

    # Lower Risk
    "Monitoring": 0.25,
    "Logging": 0.25,
    "Backup & Recovery": 0.40,
    "Data & Analytics": 0.40,
    "API Services": 0.50,
    "AI Services": 0.50,
}

CATEGORY_FRIENDLY_NAMES = {

    # Identity
    "Iam": "Identity Access",
    "Identity": "Identity Access",
    "Entra": "Identity Access",

    # Compute
    "Compute": "Compute",
    "Vm": "Compute",
    "Virtual Machine": "Compute",

    # Networking
    "Network": "Networking",
    "Networking": "Networking",
    "Nsg": "Networking",
    "Firewall": "Networking",

    # Storage
    "Storage": "Storage",

    # Key Management
    "KeyVault": "Key Management",
    "Key Vault": "Key Management",

    # Databases
    "Database": "Databases",
    "Sql": "Databases",
    "Sqlserver": "Databases",
    "Postgresql": "Databases",
    "Mysql": "Databases",
    "Cosmos": "Databases",

    # Containers
    "Container": "Containers",
    "Containers": "Containers",
    "Aks": "Containers",
    "Acr": "Containers",
    "Kubernetes": "Containers",

    # Application Services
    "App Service": "App Services",
    "Appservice": "App Services",
    "Web App": "App Services",
    "Webapp": "App Services",

    # Security & Threat Protection
    "Defender": "Threat Protection",
    "Security": "Threat Protection",

    # Monitoring & Logging
    "Monitor": "Monitoring",
    "Monitoring": "Monitoring",
    "Log Analytics": "Logging",
    "AppInsights": "Monitoring",
    "Application Insights": "Monitoring",

    # Backup & Recovery
    "Backup": "Backup",
    "Recovery": "Recovery",

    # Data & Analytics
    "Synapse": "Data Analytics",
    "Data Factory": "Data Analytics",
    "Data Lake": "Data Analytics",
    "Databricks": "Data Analytics",
    "Analytics": "Data Analytics",

    # API Services
    "Api": "API Services",
    "Apim": "API Services",
    "Api Management": "API Services",

    # AI Services
    "AI": "AI Services",
    "Ai Search": "AI Services",
    "Azure Ai Search": "AI Services",
    "Foundry": "AI Services",

}

def build_exposure_summary(
    inventory,
):

    exposure_rows = []

    critical_exposures = []

    for exposure_type, keywords in (
        EXPOSURE_KEYWORDS.items()
    ):

        matching = inventory[
            inventory["CHECK_TITLE"]
            .astype(str)
            .str.lower()
            .apply(
                lambda x: any(
                    keyword.lower() in x
                    for keyword in keywords
                )
            )
        ].copy()

        critical_matches = matching[
            matching["SEVERITY"]
            == "Critical"
        ]

        if len(critical_matches) > 0:

            top_match = critical_matches.iloc[0]

            exposure_rows.append(
                {
                    "Exposure Type": exposure_type,
                    "Findings": len(critical_matches),
                    "Resource Group": top_match["RESOURCE_GROUP"],
                    "Resource": top_match["RESOURCE_NAME"],
                    "Security Issue": top_match["CHECK_TITLE"],
                }
            )

        critical_matches = matching[
            matching["SEVERITY"]
            == "Critical"
        ]

        if len(critical_matches) > 0:

            top_issues = (
                critical_matches[
                    "CHECK_TITLE"
                ]
                .value_counts()
                .head(3)
                .index.tolist()
            )

            critical_exposures.append(
                {
                    "Exposure Type":
                        exposure_type,
                    "Count":
                        len(
                            critical_matches
                        ),
                    "Top Issues":
                        ", ".join(
                            top_issues
                        ),
                }
            )

    exposure_df = pd.DataFrame(
        exposure_rows
    )

    critical_exposure_df = pd.DataFrame(
        critical_exposures
    )

    if not exposure_df.empty:

        exposure_df = (
            exposure_df
            .sort_values(
                "Findings",
                ascending=False,
            )
        )

    return (
        exposure_df,
        critical_exposure_df,
    )

# ============================================================
# PDF
# ============================================================

def build_pdf(
    metrics_df,
    trend_df,
    trend_charts,
    scorecards_df,
    resourcegroup_df,
    top_findings_df,
    critical_df,
    inventory,
    exposure_df,
    owner_summary_df,
    critical_exposure_df,
    output_pdf,
    charts,
    trending_summary,
):
    """Build a leadership-focused PDF while retaining the existing data outputs."""
    from xml.sax.saxutils import escape
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    from reportlab.lib.units import inch
    from reportlab.platypus import KeepTogether, HRFlowable

    navy = colors.HexColor("#17365D")
    blue = colors.HexColor("#0078D4")
    pale_blue = colors.HexColor("#EAF2F8")
    slate = colors.HexColor("#425466")
    light = colors.HexColor("#F3F6F9")
    border = colors.HexColor("#D7DEE7")
    red = colors.HexColor("#C62828")
    amber = colors.HexColor("#B26A00")
    green = colors.HexColor("#237A4B")

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=23, leading=27, textColor=navy, alignment=TA_LEFT, spaceAfter=5))
    styles.add(ParagraphStyle(name="ReportSubtitle", parent=styles["Normal"], fontSize=9, leading=13, textColor=slate, spaceAfter=14))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=navy, spaceBefore=9, spaceAfter=7, keepWithNext=True))
    styles.add(ParagraphStyle(name="Subsection", parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=slate, spaceBefore=7, spaceAfter=5, keepWithNext=True))
    styles.add(ParagraphStyle(name="BodyReport", parent=styles["BodyText"], fontSize=8.5, leading=12, textColor=colors.HexColor("#263445"), spaceAfter=6))
    styles.add(ParagraphStyle(name="SmallText", parent=styles["BodyText"], fontSize=7, leading=9, textColor=colors.HexColor("#263445"), wordWrap="CJK"))
    styles.add(ParagraphStyle(name="SmallHeader", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=7, leading=8, textColor=colors.white))
    styles.add(ParagraphStyle(name="KpiLabel", parent=styles["Normal"], fontSize=7, leading=9, textColor=slate, alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="KpiValue", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=19, leading=22, textColor=navy, alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="KpiSub", parent=styles["Normal"], fontSize=7, leading=9, textColor=slate, alignment=TA_CENTER))

    def metric(name, default="N/A"):
        if metrics_df is None or metrics_df.empty or "Metric" not in metrics_df or "Value" not in metrics_df:
            return default
        vals = metrics_df.loc[metrics_df["Metric"].astype(str) == name, "Value"]
        return vals.iloc[0] if not vals.empty else default

    def safe(value):
        if pd.isna(value):
            return "—"
        value = str(value).strip()
        return escape(value if value else "—").replace("\n", "<br/>")

    def make_table(df, widths=None, max_rows=None, font=7):
        if df is None or df.empty:
            return Paragraph("No data available for this section.", styles["BodyReport"])
        view = df.head(max_rows).copy() if max_rows else df.copy()
        data = [[Paragraph(safe(c), styles["SmallHeader"]) for c in view.columns]]
        for row in view.itertuples(index=False, name=None):
            data.append([Paragraph(safe(v), styles["SmallText"]) for v in row])
        table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), navy),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, light]),
            ("LINEBELOW", (0, 0), (-1, 0), 0.8, blue),
            ("LINEBELOW", (0, 1), (-1, -1), 0.35, border),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("FONTSIZE", (0, 0), (-1, -1), font),
        ]))
        return table

    def kpi_card(label, value, note="", accent=blue):
        cell = Table([
            [Paragraph(safe(value), styles["KpiValue"])],
            [Paragraph(safe(label).upper(), styles["KpiLabel"])],
            [Paragraph(safe(note), styles["KpiSub"])],
        ], colWidths=[1.82 * inch])
        cell.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), light),
            ("BOX", (0, 0), (-1, -1), 0.6, border),
            ("LINEBEFORE", (0, 0), (0, -1), 3, accent),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        return cell

    def add_chart(story, key, width=7.0 * inch, height=3.6 * inch):
        path = (charts or {}).get(key)
        if path and Path(path).exists():
            story.append(Image(str(path), width=width, height=height, kind="proportional"))

    def page_chrome(canvas, doc):
        canvas.saveState()
        w, h = letter
        canvas.setStrokeColor(border)
        canvas.setLineWidth(0.5)
        canvas.line(0.55 * inch, 0.48 * inch, w - 0.55 * inch, 0.48 * inch)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(slate)
        canvas.drawString(0.58 * inch, 0.31 * inch, "ARC  |  AZURE CLOUD SECURITY  |  SECURITY LEADERSHIP")
        canvas.drawRightString(w - 0.58 * inch, 0.31 * inch, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(str(output_pdf), pagesize=letter, rightMargin=0.58*inch, leftMargin=0.58*inch, topMargin=0.58*inch, bottomMargin=0.68*inch, title="ARC Cloud Security Leadership Report", author="ARC Cloud Security")
    story = []

    story.append(Paragraph("ARC Cloud Security", styles["ReportTitle"]))
    story.append(Paragraph("SECURITY LEADERSHIP ASSESSMENT  |  " + pd.Timestamp.now(tz="UTC").strftime("%B %d, %Y UTC"), styles["ReportSubtitle"]))
    story.append(HRFlowable(width="100%", thickness=1.2, color=blue, spaceAfter=12))
    story.append(Paragraph("Executive posture", styles["Section"]))

    overall = metric("Overall Risk")
    score = metric("Portfolio Risk Score", 0)
    critical = metric("Criticals", 0)
    high = metric("Highs", 0)
    subscriptions = metric("Subscriptions", 0)
    unowned_critical = metric("Unowned Critical Findings", 0)
    coverage = metric("Resource Group Accountability Coverage")
    story.append(Table([[kpi_card("Overall risk", overall, "Portfolio classification", red if str(overall).upper() == "RED" else amber if str(overall).upper() == "ORANGE" else green),
                         kpi_card("Portfolio risk score", score, "0–100 scoring model"),
                         kpi_card("Critical findings", critical, "Priority remediation", red),
                         kpi_card("High findings", high, "Elevated remediation", amber)]], colWidths=[1.82*inch]*4, hAlign="LEFT"))
    story.append(Spacer(1, 9))

    summary = build_exec_summary(metrics_df, scorecards_df, trending_summary)
    # The summary function returns ReportLab-compatible line breaks; escape user-derived values there.
    story.append(Paragraph(summary, styles["BodyReport"]))
    story.append(Paragraph("Leadership signals", styles["Subsection"]))
    signal_rows = [
        [Paragraph("Subscriptions assessed", styles["SmallHeader"]), Paragraph("Unassigned critical findings", styles["SmallHeader"]), Paragraph("RG owner coverage", styles["SmallHeader"]), Paragraph("Highest-risk subscription", styles["SmallHeader"])],
        [Paragraph(safe(subscriptions), styles["BodyReport"]), Paragraph(safe(unowned_critical), styles["BodyReport"]), Paragraph(safe(coverage), styles["BodyReport"]), Paragraph(safe(metric("Highest Risk Subscription")), styles["BodyReport"])],
    ]
    signal_table = Table(signal_rows, colWidths=[1.7*inch, 1.7*inch, 1.7*inch, 2.2*inch])
    signal_table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),slate),("BACKGROUND",(0,1),(-1,1),pale_blue),("BOX",(0,0),(-1,-1),0.5,border),("INNERGRID",(0,0),(-1,-1),0.35,border),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),6),("RIGHTPADDING",(0,0),(-1,-1),6),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)]))
    story.append(signal_table)

    story.append(Paragraph("Priority exposure and accountability", styles["Section"]))
    if exposure_df is not None and not exposure_df.empty:
        story.append(make_table(exposure_df[[c for c in ["Exposure Type", "Findings", "Resource Group", "Resource", "Security Issue"] if c in exposure_df.columns]], widths=[1.0*inch,0.55*inch,1.2*inch,1.25*inch,3.0*inch], max_rows=8))
    else:
        story.append(Paragraph("No critical exposure categories were identified by the configured keyword classification. This does not imply that no exposure exists.", styles["BodyReport"]))
    story.append(Spacer(1, 9))
    story.append(Paragraph("Critical findings requiring owner action", styles["Subsection"]))
    if critical_df is not None and not critical_df.empty:
        crit_cols = [c for c in ["Subscription", "Resource Group", "Category", "Resource", "Security Issue", "AccountabilityOwner"] if c in critical_df.columns]
        story.append(make_table(critical_df[crit_cols], widths=[1.05*inch,1.05*inch,0.8*inch,1.0*inch,2.2*inch,0.9*inch], max_rows=18))
    else:
        story.append(Paragraph("No Critical-severity findings were present in the supplied inventory.", styles["BodyReport"]))

    story.append(PageBreak())
    story.append(Paragraph("Risk movement", styles["Section"]))
    if trend_df is not None and not trend_df.empty:
        story.append(make_table(trend_df, widths=[2.6*inch, 1.5*inch]))
        story.append(Spacer(1, 8))
    else:
        story.append(Paragraph("No prior-assessment trend file was supplied or a usable comparison could not be derived. This report is treated as a baseline for finding-count trends.", styles["BodyReport"]))
    if trend_charts and "portfolio_trend" in trend_charts:
        add_chart(story, "portfolio_trend", width=6.9*inch, height=3.3*inch)
    else:
        story.append(Paragraph("Portfolio risk history will appear here after at least two valid assessment snapshots are recorded.", styles["BodyReport"]))

    story.append(Paragraph("Accountability coverage", styles["Section"]))
    if owner_summary_df is not None and not owner_summary_df.empty:
        story.append(make_table(owner_summary_df, widths=[2.2*inch,2.2*inch,1.4*inch], max_rows=20))
    else:
        story.append(Paragraph("No resource-group ownership summary was available. Provide the optional resource-group owners CSV to report accountability coverage.", styles["BodyReport"]))

    story.append(PageBreak())
    story.append(Paragraph("Azure subscription risk profile", styles["Section"]))
    add_chart(story, "subscriptions", width=6.9*inch, height=3.1*inch)
    sub_cols = [c for c in ["Subscription", "Critical", "High", "Medium", "Risk Score", "Risk Level", "Top Category", "AccountabilityOwner"] if c in scorecards_df.columns]
    story.append(make_table(scorecards_df[sub_cols] if sub_cols else scorecards_df, widths=[1.25*inch,0.48*inch,0.42*inch,0.5*inch,0.62*inch,0.65*inch,1.1*inch,1.1*inch], max_rows=30))

    story.append(Paragraph("Highest-risk resource groups", styles["Section"]))
    add_chart(story, "resource_groups", width=6.9*inch, height=3.0*inch)
    rg_cols = [c for c in ["Subscription", "Resource Group", "Risk Score", "Risk Level", "AccountabilityOwner"] if c in resourcegroup_df.columns]
    story.append(make_table(resourcegroup_df[rg_cols] if rg_cols else resourcegroup_df, widths=[1.55*inch,2.0*inch,0.8*inch,0.9*inch,1.5*inch], max_rows=25))

    story.append(PageBreak())
    story.append(Paragraph("Security control themes", styles["Section"]))
    add_chart(story, "categories", width=6.9*inch, height=3.0*inch)
    add_chart(story, "heatmap", width=6.9*inch, height=3.4*inch)
    story.append(Paragraph("Most common security issues", styles["Section"]))
    story.append(make_table(top_findings_df, widths=[1.55*inch,4.45*inch,0.75*inch], max_rows=20))

    story.append(PageBreak())
    story.append(Paragraph("Methodology and interpretation", styles["Section"]))
    story.append(Paragraph("Portfolio risk score is the arithmetic mean of the per-subscription risk scores produced by this script. Each finding uses its configured severity weight, category weight, and monitoring-check multiplier; the raw score is multiplied by 0.65 and capped at 100. Existing scoring weights and thresholds have been preserved in this revision.", styles["BodyReport"]))
    story.append(Paragraph("Risk bands", styles["Subsection"]))
    story.append(make_table(pd.DataFrame([{"Risk band":"GREEN","Score range":"0–34","Interpretation":"Low risk"},{"Risk band":"ORANGE","Score range":"35–69","Interpretation":"Moderate risk"},{"Risk band":"RED","Score range":"70–100","Interpretation":"High risk"}]), widths=[1.4*inch,1.4*inch,2.5*inch]))
    story.append(Paragraph("Trend terminology", styles["Subsection"]))
    story.append(Paragraph("The supplied trending CSV compares finding counts, not the portfolio risk score. Accordingly, the report describes this as a change in finding volume rather than a measured percentage reduction in risk. Exposure groupings are keyword-based classifications of check titles and may overlap; validate the underlying findings before treating a category label as a definitive exposure determination.", styles["BodyReport"]))
    story.append(Paragraph("Ownership interpretation", styles["Subsection"]))
    story.append(Paragraph("A finding is treated as assigned only when a non-empty accountable owner is available from the resource-group ownership mapping. Missing owner metadata is reported as unassigned; where owner mapping data was not supplied, accountability counts should be interpreted as unavailable rather than as evidence of full coverage.", styles["BodyReport"]))

    doc.build(story, onFirstPage=page_chrome, onLaterPages=page_chrome)

# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--inventory",
        required=True,
    )

    parser.add_argument(
        "--subscription-owners",
        required=False,
    )

    parser.add_argument(
        "--resourcegroup-owners",
        required=False,
    )

    parser.add_argument(
        "--trending",
        required=False,
    )

    parser.add_argument(
        "--llm",
        required=False,
    )

    parser.add_argument(
        "--output",
        required=True,
    )

    args = parser.parse_args()

    output_dir = Path(
        args.output
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    history_file = (
        output_dir
        / "cloud_history.csv"
    )

    subscription_history_file = (
        output_dir
        / "cloud_subscription_history.csv"
    )

    inventory = pd.read_csv(
        args.inventory,
        dtype=str,
        keep_default_na=False,
    )

    required_inventory_columns = [
        "SUBSCRIPTION_ID", "SUBSCRIPTION_NAME", "RESOURCE_GROUP",
        "RESOURCE_UID", "RESOURCE_NAME", "CATEGORY", "SEVERITY", "CHECK_TITLE",
    ]
    missing_columns = [c for c in required_inventory_columns if c not in inventory.columns]
    if missing_columns:
        raise ValueError(
            "Inventory CSV is missing required columns: " + ", ".join(missing_columns)
        )
    if inventory.empty:
        raise ValueError("Inventory CSV contains no findings; report generation stopped.")

    subscription_owners_df = pd.DataFrame()

    if args.subscription_owners:

        owner_file = Path(
            args.subscription_owners
        )

        if owner_file.exists():

            subscription_owners_df = pd.read_csv(
                owner_file,
                dtype=str,
                keep_default_na=False,
            )

    resourcegroup_owners_df = pd.DataFrame()

    if args.resourcegroup_owners:

        owner_file = Path(
            args.resourcegroup_owners
        )

        if owner_file.exists():

            resourcegroup_owners_df = pd.read_csv(
                owner_file,
                dtype=str,
                keep_default_na=False,
            )

    # Normalize optional ownership inputs so missing/partial files do not break reporting.
    for frame, required in [
        (subscription_owners_df, ["SubscriptionName", "AccountabilityOwner"]),
        (resourcegroup_owners_df, ["ResourceGroup", "AccountabilityOwner", "OwnershipSource", "SubscriptionName"]),
    ]:
        for column in required:
            if column not in frame.columns:
                frame[column] = ""
        for column in required:
            frame[column] = frame[column].fillna("").astype(str).str.strip()

    # Prefer subscription-scoped RG ownership where that key is available.
    # If the ownership file only has RG names, do not guess when an RG name is
    # reused in multiple subscriptions: exclude those ambiguous mappings.
    rg_owner_has_subscription = (
        not resourcegroup_owners_df.empty
        and resourcegroup_owners_df["SubscriptionName"].astype(str).str.strip().ne("").any()
    )
    if not resourcegroup_owners_df.empty:
        if rg_owner_has_subscription:
            resourcegroup_owners_df = resourcegroup_owners_df.drop_duplicates(
                subset=["SubscriptionName", "ResourceGroup"], keep="last"
            ).copy()
            rg_owner_left_keys = ["Subscription", "Resource Group"]
            rg_owner_right_keys = ["SubscriptionName", "ResourceGroup"]
        else:
            rg_subscription_counts = inventory.groupby("RESOURCE_GROUP")["SUBSCRIPTION_NAME"].nunique()
            ambiguous_rg_names = set(rg_subscription_counts[rg_subscription_counts > 1].index)
            if ambiguous_rg_names:
                resourcegroup_owners_df = resourcegroup_owners_df.loc[
                    ~resourcegroup_owners_df["ResourceGroup"].isin(ambiguous_rg_names)
                ].copy()
                print(
                    "WARNING: Resource-group owner mappings were skipped for names "
                    "reused across subscriptions. Add SubscriptionName to the owner CSV "
                    "to map these safely: " + ", ".join(sorted(ambiguous_rg_names))
                )
            resourcegroup_owners_df = resourcegroup_owners_df.drop_duplicates(
                subset=["ResourceGroup"], keep="last"
            ).copy()
            rg_owner_left_keys = ["Resource Group"]
            rg_owner_right_keys = ["ResourceGroup"]
    else:
        rg_owner_left_keys = ["Resource Group"]
        rg_owner_right_keys = ["ResourceGroup"]

    owner_summary_df = pd.DataFrame()

    if not resourcegroup_owners_df.empty:

        owner_summary_df = (
            resourcegroup_owners_df.copy()
        )

        owner_summary_df[
            "AccountabilityOwner"
        ] = (
            owner_summary_df[
                "AccountabilityOwner"
            ]
            .astype(str)
            .str.strip()
    #        .str.title()
            .replace("", "Missing")
        )

        owner_summary_df[
            "OwnershipSource"
        ] = (
            owner_summary_df[
                "OwnershipSource"
            ]
            .astype(str)
            .str.strip()
            .str.title()
            .replace("", "Missing")
        )

        owner_summary_df = (
            owner_summary_df
            .groupby(
                [
                    "AccountabilityOwner",
                    "OwnershipSource",
                ],
                dropna=False,
            )
            .size()
            .reset_index(
                name="Resource Groups"
            )
            .sort_values(
                "Resource Groups",
                ascending=False,
            )
        )

    trending_summary = None

    if args.trending:
        trending_file = Path(
            args.trending
        )

        if trending_file.exists():
            trending_summary = pd.read_csv(
                trending_file,
                dtype=str,
                keep_default_na=False,
            )

    trend_df = pd.DataFrame()

    if trending_summary is not None:

        try:

            previous = int(
                trending_summary[
                    trending_summary["Metric"]
                    == "Previous Findings"
                ]["Value"].iloc[0]
            )

            current = int(
                trending_summary[
                    trending_summary["Metric"]
                    == "Current Findings"
                ]["Value"].iloc[0]
            )

            new_findings = int(
                trending_summary[
                    trending_summary["Metric"]
                    == "New Findings"
                ]["Value"].iloc[0]
            )

            resolved = int(
                trending_summary[
                    trending_summary["Metric"]
                    == "Resolved Findings"
                ]["Value"].iloc[0]
            )

            net_change = current - previous

            if current < previous:
                trend = "Improving"
            elif current > previous:
                trend = "Worsening"
            else:
                trend = "Stable"

            trend_df = pd.DataFrame(
                [
                    {
                        "Metric": "Previous Findings",
                        "Value": previous,
                    },
                    {
                        "Metric": "Current Findings",
                        "Value": current,
                    },
                    {
                        "Metric": "New Findings",
                        "Value": new_findings,
                    },
                    {
                        "Metric": "Net Change",
                        "Value": net_change,
                    },
                    {
                        "Metric": "Trend",
                        "Value": trend,
                    },
                    {
                        "Metric": "Resolved Findings",
                        "Value": resolved,
                    },
                ]
            )

        except Exception:
            trend_df = pd.DataFrame()

    inventory["SUBSCRIPTION_NAME"] = (
        inventory["SUBSCRIPTION_NAME"]
        .astype(str)
        .str.replace(
            r".*Unknown tenant domain.*",
            "Tenant",
            regex=True,
        )
    )

    inventory["CATEGORY"] = (
        inventory["CATEGORY"]
        .astype(str)
        .replace(CATEGORY_FRIENDLY_NAMES)
    )



    inventory = inventory[
        ~(
            inventory["SUBSCRIPTION_NAME"]
            .astype(str)
            .str.strip()
            .eq("Tenant")
        )
    ].copy()

    inventory["CHECK_TITLE"] \
        .drop_duplicates() \
        .sort_values() \
        .to_csv(
            output_dir / "check_titles.csv",
            index=False,
        )

 #   tenant_inventory = inventory[
 #       inventory["SUBSCRIPTION_NAME"]
 #       .astype(str)
 #       .str.strip()
 #       .eq("Tenant")
 #   ].copy()

 #   subscription_inventory = inventory[
 #       ~inventory["SUBSCRIPTION_NAME"]
 #       .astype(str)
 #       .str.strip()
 #       .eq("Tenant")
 #   ].copy()

    # -----------------------------------
    # Risk score
    # -----------------------------------

    inventory["WEIGHT"] = (
        inventory["SEVERITY"]
        .map(
            SEVERITY_WEIGHTS
        )
        .fillna(0)
    )

    critical_df = (
        inventory[
            inventory["SEVERITY"]
            == "Critical"
        ]
        [
            [
                "SUBSCRIPTION_NAME",
                "RESOURCE_GROUP",
                "CATEGORY",
                "RESOURCE_NAME",
                "CHECK_TITLE",
            ]
        ]
    ).copy()

    critical_df = critical_df.rename(
        columns={
            "SUBSCRIPTION_NAME": "Subscription",
            "RESOURCE_GROUP": "Resource Group",
            "CATEGORY": "Category",
            "RESOURCE_NAME": "Resource",
            "CHECK_TITLE": "Security Issue",
        }
    )

    if not resourcegroup_owners_df.empty:
        critical_df = critical_df.merge(
            resourcegroup_owners_df[rg_owner_right_keys + ["AccountabilityOwner", "OwnershipSource"]],
            left_on=rg_owner_left_keys, right_on=rg_owner_right_keys, how="left",
        )
        critical_df.drop(columns=rg_owner_right_keys, inplace=True, errors="ignore")
        critical_df["AccountabilityOwner"] = critical_df["AccountabilityOwner"].fillna("").astype(str).str.strip().replace("", "Missing")
        critical_df["OwnershipSource"] = critical_df["OwnershipSource"].fillna("").astype(str).str.strip().replace("", "Missing")
    else:
        critical_df["AccountabilityOwner"] = "Missing"
        critical_df["OwnershipSource"] = "Missing"

    # -----------------------------------
    # Accountability Metrics
    # -----------------------------------
    critical_assigned = int(critical_df["AccountabilityOwner"].ne("Missing").sum())
    critical_unassigned = int(critical_df["AccountabilityOwner"].eq("Missing").sum())

    high_findings_df = inventory.loc[inventory["SEVERITY"] == "High", [
        "SUBSCRIPTION_NAME", "RESOURCE_GROUP", "CATEGORY", "RESOURCE_NAME", "CHECK_TITLE"
    ]].copy()
    high_findings_df = high_findings_df.rename(columns={
        "SUBSCRIPTION_NAME": "Subscription", "RESOURCE_GROUP": "Resource Group",
        "CATEGORY": "Category", "RESOURCE_NAME": "Resource", "CHECK_TITLE": "Security Issue",
    })
    if not resourcegroup_owners_df.empty and not high_findings_df.empty:
        high_findings_df = high_findings_df.merge(
            resourcegroup_owners_df[rg_owner_right_keys + ["AccountabilityOwner", "OwnershipSource"]],
            left_on=rg_owner_left_keys, right_on=rg_owner_right_keys, how="left",
        )
        high_findings_df.drop(columns=rg_owner_right_keys, inplace=True, errors="ignore")
        high_findings_df["AccountabilityOwner"] = high_findings_df["AccountabilityOwner"].fillna("").astype(str).str.strip().replace("", "Missing")
        high_findings_df["OwnershipSource"] = high_findings_df["OwnershipSource"].fillna("").astype(str).str.strip().replace("", "Missing")
    else:
        high_findings_df["AccountabilityOwner"] = "Missing"
        high_findings_df["OwnershipSource"] = "Missing"

    high_assigned = int(high_findings_df["AccountabilityOwner"].ne("Missing").sum())
    high_unassigned = int(high_findings_df["AccountabilityOwner"].eq("Missing").sum())

    unowned_critical_df = critical_df.loc[critical_df["AccountabilityOwner"] == "Missing"].copy()
    unowned_critical_df["Severity"] = "Critical"
    unowned_high_df = high_findings_df.loc[high_findings_df["AccountabilityOwner"] == "Missing"].copy()
    unowned_high_df["Severity"] = "High"
    unowned_findings_df = pd.concat([unowned_critical_df, unowned_high_df], ignore_index=True, sort=False)

    rg_rows = []

    for (
        sub,
        rg
    ), rg_df in inventory.groupby(
        [
            "SUBSCRIPTION_NAME",
            "RESOURCE_GROUP",
        ]
    ):

        rg_df = rg_df.copy()

        rg_df["CATEGORY_WEIGHT"] = (
            rg_df["CATEGORY"]
            .map(CATEGORY_WEIGHTS)
            .fillna(1.0)
        )

        rg_df["CHECK_WEIGHT"] = 1.0

        monitor_mask = (
            rg_df["CHECK_TITLE"]
            .astype(str)
            .str.lower()
            .apply(
                lambda x: any(
                    k in x
                    for k in MONITORING_KEYWORDS
                )
            )
        )

        rg_df.loc[
            monitor_mask,
            "CHECK_WEIGHT"
        ] = 0.50

        raw_score = (
            (
                rg_df["WEIGHT"]
                .astype(float)
            )
            *
            (
                rg_df["CATEGORY_WEIGHT"]
                .astype(float)
            )
            *
            (
                rg_df["CHECK_WEIGHT"]
                .astype(float)
            )
        ).sum()

        score = min(
            100,
            round(raw_score * 0.65)
        )

        rg_rows.append(
            {
                "Subscription": sub,
    #            "SubscriptionId": sub_id,
                "Resource Group": rg,
                "Risk Score": score,
                "Risk Level": risk_level(score),
            }
        )

    resourcegroup_df = pd.DataFrame(
        rg_rows
    ).sort_values(
        "Risk Score",
        ascending=False,
    )

    if not resourcegroup_owners_df.empty:

        resourcegroup_df = resourcegroup_df.merge(
            resourcegroup_owners_df[rg_owner_right_keys + ["AccountabilityOwner"]],
            left_on=rg_owner_left_keys,
            right_on=rg_owner_right_keys,
            how="left",
        )

        resourcegroup_df.drop(columns=rg_owner_right_keys, inplace=True, errors="ignore")

        resourcegroup_df.drop(
            columns=["OwnershipSource"],
            inplace=True,
            errors="ignore",
        )

    EXEC_RG_EXCLUSIONS = [
        "tenant",
        "Tenant",
        "Subscription-Level",
    ]

    exec_resourcegroup_df = (
        resourcegroup_df[
            ~resourcegroup_df[
                "Resource Group"
            ].isin(
                EXEC_RG_EXCLUSIONS
            )
        ]
    ).copy()

    exec_resourcegroup_df = (
        exec_resourcegroup_df.sort_values(
            "Risk Score",
            ascending=False,
        )
    )

    # -----------------------------------
    # Subscription scorecards
    # -----------------------------------

    rows = []

    subscriptions = sorted(
        inventory[
            "SUBSCRIPTION_NAME"
        ].unique()
    )

    for sub in subscriptions:

        sub_df = inventory[
            inventory[
                "SUBSCRIPTION_NAME"
            ]
            == sub
        ].copy()

        critical = (
            sub_df["SEVERITY"]
            == "Critical"
        ).sum()

        high = (
            sub_df["SEVERITY"]
            == "High"
        ).sum()

        medium = (
            sub_df["SEVERITY"]
            == "Medium"
        ).sum()

        sub_df["CATEGORY_WEIGHT"] = (
            sub_df["CATEGORY"]
            .map(CATEGORY_WEIGHTS)
            .fillna(1.0)
        )

        sub_df["CHECK_WEIGHT"] = 1.0

        monitor_mask = (
            sub_df["CHECK_TITLE"]
            .astype(str)
            .str.lower()
            .apply(
                lambda x: any(
                    k in x
                    for k in MONITORING_KEYWORDS
                )
            )
        )

        sub_df.loc[
            monitor_mask,
            "CHECK_WEIGHT"
        ] = 0.50

        raw_score = (
            (
                sub_df["WEIGHT"]
                .astype(float)
            )
            *
            (
                sub_df["CATEGORY_WEIGHT"]
                .astype(float)
            )
            *
            (
                sub_df["CHECK_WEIGHT"]
                .astype(float)
            )
        ).sum()

        score = min(
            100,
            round(raw_score * 0.65)
        )

        level = risk_level(score)

        top_category = (
            sub_df["CATEGORY"]
            .value_counts()
            .index[0]
            if len(sub_df)
            else "None"
        )

        rows.append(
            {
                "Subscription": sub,
                "Critical": critical,
                "High": high,
                "Medium": medium,
                "Risk Score": round(score),
                "Risk Level": level,
                "Top Category": top_category,
            }
        )

    scorecards_df = pd.DataFrame(
        rows
    ).sort_values(
        "Risk Score",
        ascending=False,
    )

    if not subscription_owners_df.empty:

        scorecards_df = (
            scorecards_df.merge(
                subscription_owners_df[
                    [
                        "SubscriptionName",
                        "AccountabilityOwner",
        #                "OwnershipSource",
                    ]
                ],
                left_on="Subscription",
                right_on="SubscriptionName",
                how="left",
            )
        )

        scorecards_df.drop(
            columns=["SubscriptionName"],
            inplace=True,
            errors="ignore",
        )

        scorecards_df[
            "AccountabilityOwner"
        ] = (
            scorecards_df[
                "AccountabilityOwner"
            ]
            .fillna("Missing")
        )

    #    scorecards_df[
    #        "OwnershipSource"
    #    ] = (
    #        scorecards_df[
    #            "OwnershipSource"
    #        ]
    #        .fillna("Missing")
    #    )

    highest_risk_subscription = "N/A"

    if not scorecards_df.empty:

        highest_risk_subscription = (
            scorecards_df.iloc[0]
            ["Subscription"]
        )

    highest_risk_rg = "N/A"

    if not exec_resourcegroup_df.empty:

        highest_risk_rg = (
            exec_resourcegroup_df.iloc[0]
            ["Resource Group"]
        )

    subscription_snapshot_df = (
        scorecards_df.copy()
    )

    subscription_snapshot_df[
        "AssessmentDate"
    ] = pd.Timestamp.utcnow().strftime(
        "%Y-%m-%d"
    )

    if subscription_history_file.exists():

        existing_subscription_df = (
            pd.read_csv(
                subscription_history_file
            )
        )

        subscription_snapshot_df = pd.concat(
            [
                existing_subscription_df,
                subscription_snapshot_df,
            ],
            ignore_index=True,
        )

    subscription_snapshot_df = (
        subscription_snapshot_df
        .drop_duplicates()
    )

    subscription_snapshot_df.to_csv(
        subscription_history_file,
        index=False,
    )
    
    risk_reduction_pct = "N/A"

    if not trend_df.empty:

        if previous > 0:

            risk_reduction_pct = round(
                (
                    (current - previous)
                    / previous
                ) * 100,
                1,
            )

    portfolio_risk_score = 0

    if not scorecards_df.empty:

        portfolio_risk_score = round(
            scorecards_df[
                "Risk Score"
            ]
            .astype(float)
            .mean()
        )

    overall_risk_level = risk_level(
        portfolio_risk_score
    )

    subscription_accountability_coverage = "N/A"

    if not subscription_owners_df.empty:

        subscription_accountability_coverage = round(
            (
                subscription_owners_df["AccountabilityOwner"]
                .fillna("")
                .astype(str)
                .str.strip()
                .ne("")
                .sum()
                /
                len(subscription_owners_df)
            ) * 100,
            1,
        )

    resourcegroup_owner_coverage = "N/A"

    if not resourcegroup_owners_df.empty:

        resourcegroup_owner_coverage = round(
            (
                resourcegroup_owners_df["AccountabilityOwner"]
                .fillna("")
                .astype(str)
                .str.strip()
                .ne("")
                .sum()
                /
                len(resourcegroup_owners_df)
            ) * 100,
            1,
        )

    # -----------------------------------
    # Portfolio metrics
    # -----------------------------------

    metrics = [
        {
            "Metric":
                "Overall Risk",
            "Value":
                overall_risk_level,
        },
        {
            "Metric":
                "Portfolio Risk Score",
            "Value":
                portfolio_risk_score,
        },
        {
            "Metric":
                "Subscriptions",
            "Value":
                inventory[
                    "SUBSCRIPTION_ID"
                ].nunique(),
        },
        {
            "Metric":
                "Resource Groups",
            "Value":
                inventory.loc[
                    ~inventory["RESOURCE_GROUP"].isin(["Tenant", "Subscription-Level"]),
                    ["SUBSCRIPTION_NAME", "RESOURCE_GROUP"],
                ].drop_duplicates().shape[0],
        },
        {
            "Metric":
                "Security Findings",
            "Value":
                len(inventory),
        },
        {
            "Metric":
                "Resources Total",
            "Value":
                inventory[
                    "RESOURCE_UID"
                ].nunique(),
        },
        {
            "Metric":
                "Criticals",
            "Value":
                (
                    inventory["SEVERITY"]
                    == "Critical"
                ).sum(),
        },
        {
            "Metric":
                "Highs",
            "Value":
                (
                    inventory["SEVERITY"]
                    == "High"
                ).sum(),
        },
        {
            "Metric":
                "Mediums",
            "Value":
                (
                    inventory["SEVERITY"]
                    == "Medium"
                ).sum(),
        },
        {
            "Metric":
                "Critical Findings Assigned",
            "Value":
                critical_assigned,
        },
        {
            "Metric":
                "Critical Findings Unassigned",
            "Value":
                critical_unassigned,
        },
        {
            "Metric":
                "High Findings Assigned",
            "Value":
                high_assigned,
        },
        {
            "Metric":
                "High Findings Unassigned",
            "Value":
                high_unassigned,
        },
        {
            "Metric":
                "Highest Risk Subscription",
            "Value":
                highest_risk_subscription,
        },
        {
            "Metric":
                "Highest Risk Resource Group",
            "Value":
                highest_risk_rg,
        },
        {
            "Metric":
                "Finding Count Change %",
            "Value":
                f"{risk_reduction_pct}%",
        },
        {
            "Metric":
                "Trend",
            "Value":
                trend if not trend_df.empty else "Baseline",
        },
        {
            "Metric":
                "Subscription Accountability Coverage",
            "Value":
                f"{subscription_accountability_coverage}%",
        },
        {
            "Metric":
                "Resource Group Accountability Coverage",
            "Value":
                f"{resourcegroup_owner_coverage}%",
        },
        {
            "Metric":
                "Unowned Critical Findings",
            "Value":
                len(unowned_critical_df),
        },
        {
            "Metric":
                "Unowned High Findings",
            "Value":
                len(unowned_high_df),
        },
    ]

   # critical_assigned = 0
   # critical_unassigned = 0
   # high_assigned = 0
   # high_unassigned = 0

    metrics_df = pd.DataFrame(
        metrics
    )

    history_row = {
        "AssessmentDate":
            pd.Timestamp.utcnow().strftime(
                "%Y-%m-%d"
            ),

        "PortfolioRiskScore":
            portfolio_risk_score,

        "OverallRisk":
            overall_risk_level,

        "CriticalCount":
            (
                inventory["SEVERITY"]
                == "Critical"
            ).sum(),

        "HighCount":
            (
                inventory["SEVERITY"]
                == "High"
            ).sum(),

        "MediumCount":
            (
                inventory["SEVERITY"]
                == "Medium"
            ).sum(),

        "Subscriptions":
            inventory[
                "SUBSCRIPTION_NAME"
            ].nunique(),

        "ResourceGroups":
            inventory[
                "RESOURCE_GROUP"
            ].nunique(),
    }

    history_snapshot_df = pd.DataFrame(
        [history_row]
    )

    if history_file.exists():

        existing_history_df = pd.read_csv(
            history_file
        )

        history_snapshot_df = pd.concat(
            [
                existing_history_df,
                history_snapshot_df,
            ],
            ignore_index=True,
        )

    # Keep one portfolio snapshot per UTC assessment date. Scheduled or manual
    # reruns on the same day replace that day's snapshot instead of inflating trends.
    history_snapshot_df = history_snapshot_df.drop_duplicates(
        subset=["AssessmentDate"], keep="last"
    )

    history_snapshot_df.to_csv(
        history_file,
        index=False,
    )

    findings_inventory = (
        inventory[
            ~inventory[
                "RESOURCE_GROUP"
            ].isin(
                EXEC_RG_EXCLUSIONS
            )
        ]
    ).copy()

    top_findings_df = (
        findings_inventory
        .groupby(
            [
                "RESOURCE_GROUP",
                "CHECK_TITLE",
            ]
        )
        .size()
        .reset_index(
            name="COUNT"
        )
        .sort_values(
            "COUNT",
            ascending=False,
        )
        .head(25)
    )

    top_findings_df = (
        top_findings_df.rename(
            columns={
                "RESOURCE_GROUP":
                    "Resource Group",

                "CHECK_TITLE":
                    "Security Issue",

                "COUNT":
                    "Findings",
            }
        )
    )

    (
        exposure_df,
        critical_exposure_df,
    ) = build_exposure_summary(
        inventory
    )

    charts = generate_charts(
        inventory,
        scorecards_df,
        exec_resourcegroup_df,
        output_dir,
    )

    trend_charts = (
        generate_trend_charts(
            output_dir,
            history_file,
        )
    )

    # -----------------------------------
    # Export CSVs
    # -----------------------------------

    owner_summary_path = (
        output_dir
        / "cloud_owner_summary.csv"
    )

    if not owner_summary_df.empty:

        owner_summary_df.to_csv(
            owner_summary_path,
            index=False,
        )

        print(owner_summary_path)

    metrics_path = (
        output_dir
        / "cloud_metrics.csv"
    )

    scorecards_path = (
        output_dir
        / "cloud_subscription_scorecards.csv"
    )

    resourcegroup_path = (
        output_dir
        / "cloud_resourcegroup_scorecards.csv"
    )

    findings_path = (
        output_dir
        / "cloud_top_findings.csv"
    )

    pdf_path = (
        output_dir
        / "cloud_executive_report.pdf"
    )

    metrics_df.to_csv(
        metrics_path,
        index=False,
    )

    scorecards_df.to_csv(
        scorecards_path,
        index=False,
    )

    exec_resourcegroup_df.to_csv(
        resourcegroup_path,
        index=False,
    )

    top_findings_df.to_csv(
        findings_path,
        index=False,
    )

    exposure_df.to_csv(
        output_dir / "cloud_exposures.csv",
        index=False,
    )

    unowned_findings_path = (
        output_dir
        / "cloud_unowned_findings.csv"
    )

    unowned_findings_df.to_csv(
        unowned_findings_path,
        index=False,
    )
    print(unowned_findings_path)

    build_pdf(
        metrics_df,
        trend_df,
        trend_charts,
        scorecards_df,
        exec_resourcegroup_df,
        top_findings_df,
        critical_df,
        inventory,
        exposure_df,
        owner_summary_df,
        critical_exposure_df,
        pdf_path,
        charts,
        trending_summary,
    )

    print(scorecards_df.columns.tolist())
    print(output_dir / "check_titles.csv")
    print(metrics_path)
    print(scorecards_path)
    print(resourcegroup_path)
    print(findings_path)
    print(pdf_path)

    print(history_file)

    print(
        subscription_history_file
    )

if __name__ == "__main__":
    main()
