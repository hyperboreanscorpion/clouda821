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

    highest_risk_subscription = (
        scorecards_df.iloc[0]
        ["Subscription"]
    )

    highest_risk_rg = (
        resourcegroup_df.iloc[0]
        ["Resource Group"]
    )

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

    top_sub = (
        scorecards_df.iloc[0]
        ["Subscription"]
    )

    top_category = (
        scorecards_df.iloc[0]
        ["Top Category"]
    )

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
                        abs(
                            current - previous
                        )
                        / previous
                    ) * 100,
                    1,
                )

            else:

                risk_change_pct = 0

            trend_text = (
                f"Overall trend is {trend}. "
                f"Findings changed by "
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

        f"The highest concentration of findings is within "
        f"the {top_category} category, making it the "
        f"primary contributor to portfolio risk."
        f"<br/><br/>"

        f"The assessment identified "
        f"{metrics_df[metrics_df['Metric']=='Criticals']['Value'].iloc[0]} "
        f"critical findings requiring priority remediation."
        f"<br/><br/>"

        f"{critical_assigned} critical findings have an "
        f"identified accountable owner, while "
        f"{critical_unassigned} remain unassigned."
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

    top_rgs = (
        resourcegroup_df
        .head(10)
    )

    plt.figure(figsize=(10, 6))

    plt.barh(
        top_rgs["Resource Group"],
        top_rgs["Risk Score"],
        color="#d62728",
    )

    plt.title(
        "Highest Risk Azure Resource Groups"
    )

    plt.xlabel(
        "Risk Score"
    )

    plt.tight_layout()

    plt.savefig(
        severity_chart
    )

    plt.close()

    charts["resource_groups"] = severity_chart

    # ====================================================
    # Top Risk Resource Groups
    # ====================================================

    top_subs = (
        scorecards_df
        .head(10)
    )

    sub_chart = (
        output_dir /
        "top_risk_subscriptions.png"
    )

    plt.figure(figsize=(8, 5))

    plt.barh(
        top_subs["Subscription"],
        top_subs["Risk Score"],
        color="#d62728",
    )

    plt.title(
        "Highest Risk Azure Subscriptions"
    )

    plt.tight_layout()

    plt.savefig(sub_chart)

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

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="SmallText",
            parent=styles["BodyText"],
            fontSize=7,
            leading=8,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SmallHeader",
            parent=styles["SmallText"],
            textColor=colors.white,
        )
    )

    doc = SimpleDocTemplate(
        str(output_pdf),
        pagesize=letter,
        leftMargin=72,
        rightMargin=72,
    )

    elements = []

    elements.append(
        Paragraph(
            "ARC Cloud Security Executive Report",
            styles["Title"],
        )
    )

    elements.append(
        Paragraph(
            pd.Timestamp.utcnow().strftime(
                "%B %d, %Y"
            ),
            styles["BodyText"],
        )
    )

    elements.append(
        Spacer(1, 5)
    )

    # ====================================================
    # EXECUTIVE Summary
    # ====================================================

    elements.append(
        Paragraph(
            "Executive Summary",
            styles["Heading2"],
        )
    )

    exec_summary = build_exec_summary(
        metrics_df,
        scorecards_df,
        trending_summary,
    )

    elements.append(
        Paragraph(
            exec_summary,
            styles["BodyText"],
        )
    )

    elements.append(
        Spacer(1, 10)
    )

    elements.append(
        Paragraph(
            "Summary Cloud Security Metrics",
            styles["Heading2"],
        )
    )

 #   metrics_table = Table(
 #       [
 #           list(metrics_df.columns)
 #       ]
 #       + metrics_df.values.tolist(),
 #       colWidths=[
 #           220,
 #           180,
 #       ],
 #   )

    metrics_table = Table(
        wrap_table_dataframe(
            metrics_df,
            styles,
        ),
        colWidths=[
            200,
            200,
        ],
    )

    metrics_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.darkblue,
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    1,
                    colors.black,
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "LEADING",
                    (0, 0),
                    (-1, -1),
                    12,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "WORDWRAP",
                    (0, 0),
                    (-1, -1),
                    True,
                ),
            ]
        )
    )

    elements.append(metrics_table)

  #  elements.append(
  #      Spacer(1, 10)
  #  )

    elements.append(
        PageBreak()
    )


    elements.append(
        Paragraph(
            "Cloud Ownership Accountability Overview",
            styles["Heading2"],
        )
    )

    owner_table = Table(
        wrap_table_dataframe(
            owner_summary_df.head(15),
            styles,
        ),
        colWidths=[
            180,
            100,
            80,
        ]
    )

    owner_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND",(0,0),(-1,0),colors.darkblue),
                ("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("GRID",(0,0),(-1,-1),1,colors.black),
                ("VALIGN",(0,0),(-1,-1),"TOP"),
                ("FONTSIZE",(0,0),(-1,-1),8),
            ]
        )
    )

    elements.append(owner_table)

    elements.append(
        Spacer(1, 10)
    )

 #   elements.append(
 #       Paragraph(
 #           "Leadership Attention Required",
 #           styles["Heading2"],
 #       )
 #   )

 #   elements.append(
 #       PageBreak()
 #   )

 #   elements.append(
 #       Spacer(1, 20)
 #   )

    if not exposure_df.empty:

        elements.append(
            Paragraph(
                "Critical Cloud Exposures Requiring Action",
                styles["Heading2"],
            )
        )

        wrapped_exposures = []

    #    wrapped_exposures.append(
    #        list(exposure_df.columns)
    #    )

        wrapped_exposures.append(
            [
                Paragraph("Exposure Type", styles["SmallHeader"]),
                Paragraph("Findings", styles["SmallHeader"]),
                Paragraph("Resource Group", styles["SmallHeader"]),
                Paragraph("Resource", styles["SmallHeader"]),
                Paragraph("Security Issue", styles["SmallHeader"]),
            ]
        )

        for _, row in exposure_df.head(5).iterrows():

            wrapped_exposures.append(
                [
                    Paragraph(
                        str(row["Exposure Type"]),
                        styles["SmallText"],
                    ),
                    Paragraph(
                        str(row["Findings"]),
                        styles["SmallText"],
                    ),
                    Paragraph(
                        str(row["Resource Group"]),
                        styles["SmallText"],
                    ),
                    Paragraph(
                        str(row["Resource"]),
                        styles["SmallText"],
                    ),
                    Paragraph(
                        str(row["Security Issue"]),
                        styles["SmallText"],
                    ),
                ]
            )

        exposure_table = Table(
            wrapped_exposures,
            colWidths=[
                75,
                30,
                90,
                115,
                125,
            ],
            hAlign="CENTER",
        )

        exposure_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.darkblue,
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        1,
                        colors.black,
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        3,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        3,
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        9,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                ]
            )
        )

        elements.append(
            exposure_table
        )

        elements.append(
            Spacer(1, 10)
        )

        for _, row in (
            exposure_df.head(5)
            .iterrows()
        ):

            elements.append(
                Paragraph(
                    f"{row['Exposure Type']}: "
                    f"{row['Findings']} critical findings identified.",
                    styles["BodyText"],
                )
            )
    
    else:

        elements.append(
            Paragraph(
                "Leadership Attention Required",
                styles["Heading2"],
            )
        )

    #    elements.append(
    #        Paragraph(
    #            "No immediate issues identified for leadership attention.",
    #            styles["BodyText"],
    #        )
    #    )

    elements.append(
        Spacer(1, 1)
    )
        
    attention_items = (
        build_attention_section(
            inventory,
            scorecards_df,
            resourcegroup_df,
        )
    )
    
    if len(attention_items) == 0:

        elements.append(
            Paragraph(
                "No immediate leadership attention items identified.",
                styles["BodyText"],
            )
        )

    else:

        for item in attention_items:

            elements.append(
                Paragraph(
                    f"• {item}",
                    styles["BodyText"],
                )
            )

    elements.append(
        Spacer(1, 10)
    )

    if len(critical_df) > 0:

        elements.append(
            Paragraph(
    #            "Critical Exposures Requiring Action",
    #            "Critical Cloud Exposure Categories",
                "Critical Security Findings and Assigned Owners",
                styles["Heading2"],
            )
        )

        wrapped_criticals = []

    #    wrapped_criticals.append(
    #        list(critical_df.columns)
    #    )

        wrapped_criticals.append(
            [
                Paragraph(
                    str(col),
        #            styles["SmallText"],
                    styles["SmallHeader"]
                )
                for col in critical_df.columns
            ]
        )

        for _, row in critical_df.iterrows():

            wrapped_criticals.append(
                [
                    Paragraph(
                        str(row["Subscription"]),
                        styles["SmallText"],
                    ),
                    Paragraph(
                        str(row["Resource Group"]),
                        styles["SmallText"],
                    ),
                    Paragraph(
                        str(row["Category"]),
                        styles["SmallText"],
                    ),
                    Paragraph(
                        str(row["Resource"]),
                        styles["SmallText"],
                    ),
                     Paragraph(
                        str(row["Security Issue"]),
                        styles["SmallText"],
                    ),
                    Paragraph(
                        str(row["AccountabilityOwner"]),
                        styles["SmallText"],
                    ),
                ]
            )

        critical_table = Table(
            wrapped_criticals,
            colWidths=[
                80,
                80,
                60,
                70,
                90,
                80,
            ]
        )

        critical_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.darkblue,
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        1,
                        colors.black,
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                    (
                        "LEADING",
                        (0, 0),
                        (-1, -1),
                        9,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "WORDWRAP",
                        (0, 0),
                        (-1, -1),
                        True,
                    ),
                ]
            )
        )

        elements.append(
            critical_table
        )

    if not critical_exposure_df.empty:

        elements.append(
            Spacer(1, 10)
        )

        elements.append(
            Paragraph(
    #            "Critical Exposures Requiring Action",
                "Critical Cloud Exposure Summary",
    #            "Critical Findings and Assigned Owners",
                styles["Heading2"],
            )
        )

        for _, row in (
            critical_exposure_df
            .iterrows()
        ):

            elements.append(
                Paragraph(
                    f"• "
                    f"{row['Count']} critical findings "
                    f"related to "
                    f"{row['Exposure Type']}. "
                    f"Examples: "
                    f"{row['Top Issues']}.",
                    styles["BodyText"],
                )
            )
    
    if not trend_df.empty:

        elements.append(
            Spacer(1, 10)
        )

        elements.append(
            Paragraph(
                "Cloud Risk Movement Since Previous Security Assessment",
                styles["Heading2"],
            )
        )

    #    trend_table = Table(
    #        [
    #            list(trend_df.columns)
    #        ]
    #        + trend_df.values.tolist(),
        trend_table = Table(
            wrap_table_dataframe(
                trend_df,
                styles,
            ),
            colWidths=[
                200,
                140,
            ]
        )

        trend_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.darkblue,
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        1,
                        colors.black,
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        10,
                    ),
                ]
            )
        )

        elements.append(trend_table)

  #  elements.append(
  #      Spacer(1, 20)
  #  )

        print(trend_charts)

        if (
            "portfolio_trend"
            in trend_charts
        ):

        #    elements.append(
        #        Spacer(1, 10)
        #    )

            elements.append(
                PageBreak()
            )

            elements.append(
                Paragraph(
                    "Cloud Security Risk Trend Summary",
                    styles["Heading2"],
                )
            )

            elements.append(
                Image(
                    str(
                        trend_charts[
                            "portfolio_trend"
                        ]
                    ),
                    width=450,
                    height=220,
                )
            )

  #  elements.append(
  #      PageBreak()
  #  )

    elements.append(
        Spacer(1, 10)
    )

    elements.append(
        Paragraph(
            "Most Common Azure Cloud Security Issues",
            styles["Heading2"],
        )
    )

    wrapped_findings = []

 #   wrapped_findings.append(
 #       list(top_findings_df.head(10).columns)
 #   )

    wrapped_findings.append(
        [
            Paragraph(
                str(col),
    #            styles["SmallText"],
                styles["SmallHeader"]
            )
            for col in top_findings_df.head(10).columns
        ]
    )

    for _, row in top_findings_df.head(10).iterrows():

        wrapped_findings.append(
            [
                Paragraph(
                    str(row["Resource Group"]),
                    styles["SmallText"],
                ),

                Paragraph(
                    str(row["Security Issue"]),
                    styles["SmallText"],
                ),

                Paragraph(
                    str(row["Findings"]),
                    styles["SmallText"],
                ),
            ]
        )

    findings_table = Table(
        wrapped_findings,
        colWidths=[
            140,  # Resource Group
            320,  # Check Title
            40,   # Count
        ]
    )

    findings_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.darkblue,
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    1,
                    colors.black,
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "LEADING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "WORDWRAP",
                    (0, 0),
                    (-1, -1),
                    True,
                ),
            ]
        )
    )

    elements.append(findings_table)

 #   elements.append(
 #       Spacer(1, 20)
 #   )

    elements.append(
        PageBreak()
    )

    elements.append(
        Paragraph(
            "Highest Risk Azure Resource Groups",
            styles["Heading2"],
        )
    )

    elements.append(
        Spacer(1, 10)
    )

    elements.append(
        Image(
            str(charts["resource_groups"]),
            width=500,
            height=300,
        )
    )

    elements.append(
        Paragraph(
    #        "Azure Resource Group Risk Rankings",
            "Azure Resource Group Risk & Ownership Rankings",
            styles["Heading2"],
        )
    )

  #  rg_table = Table(
  #      [
  #          list(
  #              resourcegroup_df.head(10).columns
  #          )
  #      ]
  #      + resourcegroup_df.head(10)
  #          .values.tolist(),
    rg_table = Table(
        wrap_table_dataframe(
            resourcegroup_df.head(10),
            styles,
        ),
        colWidths=[
            120,   # Subscription
            130,  # Resource Group
            45,   # Risk Score
            45,   # Risk Level
            100,  # AccountabilityOwner
        ]
    )

    rg_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.darkblue,
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    1,
                    colors.black,
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "LEADING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "WORDWRAP",
                    (0, 0),
                    (-1, -1),
                    True,
                ),
            ]
        )
    )

    elements.append(rg_table)

 #   elements.append(PageBreak())

 #   elements.append(
 #       Spacer(1, 20)
 #   )

    elements.append(
        PageBreak()
    )

    # ====================================================
    # RISKY SUBSCRIPTIONS
    # ====================================================

    elements.append(
        Paragraph(
            "Highest Risk Azure Subscriptions",
            styles["Heading2"],
        )
    )

    elements.append(
        Image(
            str(charts["subscriptions"]),
            width=500,
            height=300,
        )
    )

    elements.append(
        Paragraph(
            "Azure Subscriptions Risk Rankings",
            styles["Heading2"],
        )
    )

 #   score_table = Table(
 #       [
 #           list(scorecards_df.columns)
 #       ]
 #       + scorecards_df.values.tolist()
 #   )

 #   score_table = Table(
 #       [
 #           list(scorecards_df.columns)
 #       ]
 #       + scorecards_df.values.tolist(),
    score_table = Table(
        wrap_table_dataframe(
            scorecards_df,
            styles,
        ),
        colWidths=[
            120,   # Subscription
            40,   # Critical
            30,   # High
            30,   # Medium
            40,   # Risk Score
            40,   # Risk Level
            65,   # Top Category
            100,  # AccountabilityOwner
        ]
    )

    score_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.darkblue,
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    1,
                    colors.black,
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "LEADING",
                    (0, 0),
                    (-1, -1),
                    9,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "WORDWRAP",
                    (0, 0),
                    (-1, -1),
                    True,
                ),
            ]
        )
    )

    elements.append(score_table)

    elements.append(PageBreak())
  #  elements.append(
  #      Spacer(1, 20)
  #  )

    # ====================================================
    # CATEGORY ANALYSIS
    # ====================================================

    elements.append(
        Paragraph(
            "Azure Resource Security Breakdown Summary",
            styles["Heading2"],
        )
    )

    elements.append(
        Image(
            str(charts["categories"]),
            width=450,
            height=250,
        )
    )

    elements.append(PageBreak())
  #  elements.append(
  #      Spacer(1, 20)
  #  )

    # ====================================================
    # HEATMAP
    # ====================================================

    elements.append(
        Paragraph(
            "Azure Resource Security Issue Heatmap Overview",
            styles["Heading2"],
        )
    )

    elements.append(
        Image(
            str(charts["heatmap"]),
            width=500,
            height=350,
        )
    )

  #  elements.append(
  #      Spacer(1, 20)
  #  )

    elements.append(PageBreak())

    elements.append(
        Paragraph(
            "Appendix Information",
            styles["Heading2"],
        )
    )

    elements.append(
        Spacer(1, 10)
    )

    elements.append(
        Paragraph(
            """
            Metrics Risk Score Reference:<br/>
            Green = 0-34 (Low Risk)<br/>
            Orange = 35-69 (Moderate Risk)<br/>
            Red = 70-100 (High Risk)
            """,
            styles["BodyText"]
        )
    )

    elements.append(
        Spacer(1, 10)
    )

    elements.append(
        Paragraph(
            """
            Azure Services Category Reference:<br/>
            Identity &amp; Access = Microsoft Entra ID, Users, Groups, Service Principals, RBAC/Role Assignments<br/>
            Compute = Virtual Machines, VM Disks, Managed Disks, Compute Workloads<br/>
            Networking = Virtual Networks, Network Security Groups (NSGs), Public IPs, Firewalls, Connectivity<br/>
            Storage = Storage Accounts, Blob Storage, Azure Files, Data Storage Services<br/>
            Key Management = Azure Key Vault, Keys, Secrets, Certificates<br/>
            Databases = Azure SQL, PostgreSQL, MySQL, Cosmos DB<br/>
            Containers = Azure Kubernetes Service (AKS), Azure Container Registry (ACR), Kubernetes<br/>
            Application Services = App Services, Web Apps, Application Hosting Platforms<br/>
            Security &amp; Threat Protection = Microsoft Defender for Cloud and Security Controls<br/>
            Monitoring &amp; Logging = Azure Monitor, Log Analytics, Application Insights, Alerting/Visibility<br/>
            Backup &amp; Recovery = Recovery Services Vaults, Backup Configurations, Disaster Recovery<br/>
            Data &amp; Analytics = Synapse, Data Factory, Data Lake, Databricks, Analytics Services<br/>
            API Services = Azure API Management (APIM) and API Security Controls<br/>
            AI Services = Azure AI Search and Azure AI Services (Foundry)
            """,
            styles["BodyText"]
        )
    )

    elements.append(
        Spacer(1, 10)
    )

    elements.append(
        Paragraph(
            """
            Ownership & Accountability Summary:<br/>
            Assigned findings have been mapped to an accountable owner, team, division, or department and can be routed for remediation. Unassigned findings indicate resources that currently lack sufficient ownership metadata and represent governance gaps requiring follow-up.<br/><br/>

            Subscription Accountability Coverage and Resource Group Accountability Coverage provide visibility into ownership maturity across the Azure environment. Higher accountability coverage improves remediation effectiveness, reporting accuracy, and risk reduction efforts by ensuring identified security issues can be assigned to responsible stakeholders.
            """,
            styles["BodyText"]
        )
    )

    doc.build(elements)
     
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

        critical_df = (
            critical_df.merge(
                resourcegroup_owners_df[
                    [
                        "ResourceGroup",
                        "AccountabilityOwner",
                        "OwnershipSource",
                    ]
                ],
                left_on="Resource Group",
                right_on="ResourceGroup",
                how="left",
            )
        )

        critical_df.drop(
            columns=["ResourceGroup"],
            inplace=True,
            errors="ignore",
        )

    #    critical_df[
    #        "OwnershipSource"
    #    ] = (
    #        critical_df[
    #            "OwnershipSource"
    #        ]
    #        .fillna("Missing")
    #    )

        critical_df[
            "AccountabilityOwner"
        ] = (
            critical_df[
                "AccountabilityOwner"
            ]
            .fillna("Missing")
        )

        critical_df.drop(
            columns=["OwnershipSource"],
            inplace=True,
            errors="ignore",
        )

    # -----------------------------------
    # Accountability Metrics
    # -----------------------------------

    critical_assigned = 0
    critical_unassigned = 0
    high_assigned = 0
    high_unassigned = 0

    if not critical_df.empty:

        critical_assigned = (
            critical_df[
                critical_df[
                    "OwnershipSource"
                ] != "Missing"
            ]
        ).shape[0]

        critical_unassigned = (
            critical_df[
                critical_df[
                    "OwnershipSource"
                ] == "Missing"
            ]
        ).shape[0]

    high_df = inventory[
        inventory["SEVERITY"]
        == "High"
    ].copy()

    if (
        not high_df.empty
        and
        not resourcegroup_owners_df.empty
    ):

        high_df = (
            high_df.merge(
                resourcegroup_owners_df[
                    [
                        "ResourceGroup",
                        "OwnershipSource",
                    ]
                ],
                left_on="RESOURCE_GROUP",
                right_on="ResourceGroup",
                how="left",
            )
        )

        high_df[
            "OwnershipSource"
        ] = (
            high_df[
                "OwnershipSource"
            ]
            .fillna("Missing")
        )

        high_assigned = (
            high_df[
                high_df[
                    "OwnershipSource"
                ] != "Missing"
            ]
        ).shape[0]

        high_unassigned = (
            high_df[
                high_df[
                    "OwnershipSource"
                ] == "Missing"
            ]
        ).shape[0]


    unowned_findings_df = pd.DataFrame()

    unowned_critical_df = (
        critical_df[
            critical_df[
                "OwnershipSource"
            ] == "Missing"
        ]
    ).copy()

    high_findings_df = (
        inventory[
            inventory["SEVERITY"]
            == "High"
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
        .copy()
    )

    high_findings_df = (
        high_findings_df.rename(
            columns={
                "SUBSCRIPTION_NAME":
                    "Subscription",
                "RESOURCE_GROUP":
                    "Resource Group",
                "CATEGORY":
                    "Category",
                "RESOURCE_NAME":
                    "Resource",
                "CHECK_TITLE":
                    "Security Issue",
            }
        )
    )

    if not resourcegroup_owners_df.empty:

        high_findings_df = (
            high_findings_df.merge(
                resourcegroup_owners_df[
                    [
                        "ResourceGroup",
                        "AccountabilityOwner",
                        "OwnershipSource",
                    ]
                ],
                left_on="Resource Group",
                right_on="ResourceGroup",
                how="left",
            )
        )

        high_findings_df.drop(
            columns=["ResourceGroup"],
            inplace=True,
            errors="ignore",
        )

        high_findings_df[
            "OwnershipSource"
        ] = (
            high_findings_df[
                "OwnershipSource"
            ]
            .fillna("Missing")
        )

        high_findings_df[
            "AccountabilityOwner"
        ] = (
            high_findings_df[
                "AccountabilityOwner"
            ]
            .fillna("Missing")
        )

        unowned_high_df = (
            high_findings_df[
                high_findings_df[
                    "OwnershipSource"
                ] == "Missing"
            ]
        ).copy()

        unowned_critical_df["Severity"] = "Critical"
        unowned_high_df["Severity"] = "High"

        unowned_findings_df = pd.concat(
            [
                unowned_critical_df,
                unowned_high_df,
            ],
            ignore_index=True,
        )

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

        resourcegroup_df = (
            resourcegroup_df.merge(
                resourcegroup_owners_df[
                    [
                        "ResourceGroup",
                        "AccountabilityOwner",
            #            "OwnershipSource",
                    ]
                ],
                left_on="Resource Group",
                right_on="ResourceGroup",
                how="left",
            )
        )

        resourcegroup_df.drop(
            columns=["ResourceGroup"],
            inplace=True,
            errors="ignore",
        )

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
                    (previous - current)
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
                inventory[
                    ~inventory[
                        "RESOURCE_GROUP"
                    ].isin(
                        [
                            "Tenant",
                            "Subscription-Level",
                        ]
                    )
                ]["RESOURCE_GROUP"]
                .nunique(),
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
                "Risk Reduction %",
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

    history_snapshot_df = (
        history_snapshot_df
    #    .drop_duplicates()
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

    if not unowned_findings_df.empty:

        unowned_findings_df.to_csv(
            unowned_findings_path,
            index=False,
        )

        print(
            unowned_findings_path
        )

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
