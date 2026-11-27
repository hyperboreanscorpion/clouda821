#!/usr/bin/env python3
"""Run one Azure Entra assessment, then resource assessments per CSV subscription.

Input CSV columns:
    subscription_name,subscription_id

Authentication environment variables:
    TENANT_ID, CLIENT_ID, CLIENT_SECRET

Prowler exit code 0 = completed without findings; 3 = completed with findings.
Both are treated as completed scans. Other exit codes are failures.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SUBSCRIPTION_ID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
DEFAULT_PROWLER_COMMAND = "prowler"
DEFAULT_MAX_WORKERS = 3
EXIT_SUCCESS = 0
EXIT_FINDINGS = 3


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def log(message: str) -> None:
    timestamp = utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{timestamp}] {message}", flush=True)


def log_error(message: str) -> None:
    timestamp = utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{timestamp}] ERROR: {message}", file=sys.stderr, flush=True)


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable '{name}' is not set.")
    return value


def validate_environment() -> dict[str, str]:
    log("Validating Azure service-principal credentials...")
    tenant_id = required_env("TENANT_ID")
    client_id = required_env("CLIENT_ID")
    client_secret = required_env("CLIENT_SECRET")

    if not SUBSCRIPTION_ID_PATTERN.fullmatch(tenant_id):
        raise RuntimeError("TENANT_ID is not a valid GUID.")
    if not SUBSCRIPTION_ID_PATTERN.fullmatch(client_id):
        raise RuntimeError("CLIENT_ID is not a valid GUID.")

    log("Azure service-principal credentials validated.")
    return {
        "TENANT_ID": tenant_id,
        "CLIENT_ID": client_id,
        "CLIENT_SECRET": client_secret,
    }


def load_subscriptions(subscription_file: Path) -> list[dict[str, str]]:
    if not subscription_file.is_file():
        raise FileNotFoundError(f"Subscription CSV does not exist: {subscription_file}")

    subscriptions: list[dict[str, str]] = []
    seen: set[str] = set()

    with subscription_file.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required_headers = {"subscription_name", "subscription_id"}
        if not reader.fieldnames or not required_headers.issubset(set(reader.fieldnames)):
            raise RuntimeError(
                "Subscription CSV must contain the columns: "
                "subscription_name,subscription_id"
            )

        for line_number, row in enumerate(reader, start=2):
            name = (row.get("subscription_name") or "").strip()
            subscription_id = (row.get("subscription_id") or "").strip()

            if not name:
                raise RuntimeError(f"Missing subscription_name on CSV line {line_number}.")
            if not SUBSCRIPTION_ID_PATTERN.fullmatch(subscription_id):
                raise RuntimeError(f"Invalid subscription_id on CSV line {line_number}.")

            normalized_id = subscription_id.lower()
            if normalized_id in seen:
                log(f"Skipping duplicate subscription ID on CSV line {line_number}: {subscription_id}")
                continue

            seen.add(normalized_id)
            subscriptions.append({"name": name, "id": subscription_id})

    if not subscriptions:
        raise RuntimeError("No valid subscriptions were found in the CSV.")

    return subscriptions


def find_prowler() -> str:
    command = os.environ.get("PROWLER_COMMAND", DEFAULT_PROWLER_COMMAND)
    path = shutil.which(command)
    if not path:
        raise RuntimeError(f"Prowler executable '{command}' was not found in PATH.")
    return path


def get_prowler_version(prowler_path: str) -> str:
    result = subprocess.run(
        [prowler_path, "-v"], capture_output=True, text=True, check=False, timeout=30
    )
    if result.returncode != 0:
        raise RuntimeError("Unable to determine installed Prowler version.")
    version = (result.stdout.strip() or result.stderr.strip()).splitlines()
    version_text = version[0][:200] if version else "Unknown"
    log(f"Prowler version: {version_text}")
    return version_text


def create_run_directory(output_root: Path) -> Path:
    run_id = utc_now().strftime("%Y%m%dT%H%M%S%fZ")
    run_directory = output_root / run_id
    run_directory.mkdir(parents=True, exist_ok=False)
    return run_directory


def safe_directory_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-._")
    return cleaned[:60] or "subscription"


def log_excerpt(log_file: Path, max_lines: int = 18) -> str:
    try:
        with log_file.open("r", encoding="utf-8", errors="replace") as handle:
            lines = deque(handle, maxlen=max_lines)
        return "".join(lines)[-3000:]
    except Exception:
        return "Unable to read the Prowler execution log."


def prowler_environment(authentication: dict[str, str], output_directory: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["AZURE_TENANT_ID"] = authentication["TENANT_ID"]
    environment["AZURE_CLIENT_ID"] = authentication["CLIENT_ID"]
    environment["AZURE_CLIENT_SECRET"] = authentication["CLIENT_SECRET"]
    environment["PROWLER_OUTPUT_DIRECTORY"] = str(output_directory)
    return environment


def execute_scan(
    *,
    prowler_path: str,
    authentication: dict[str, str],
    scan_name: str,
    output_directory: Path,
    command: list[str],
    scan_type: str,
    subscription_id: str = "",
) -> dict[str, Any]:
    """Execute one Prowler process and return a summary record."""
    output_directory.mkdir(parents=True, exist_ok=True)
    execution_log = output_directory / "prowler-execution.log"
    start_time = utc_now()

    log(f"START | {scan_type} | {scan_name}")
    log(f"Output | {output_directory}")

    status = "ERROR"
    exit_code = 1
    error_message = ""

    try:
        with execution_log.open("w", encoding="utf-8") as log_handle:
            log_handle.write("Command: " + " ".join(command) + "\n\n")
            log_handle.flush()
            result = subprocess.run(
                command,
                env=prowler_environment(authentication, output_directory),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )

        exit_code = result.returncode
        if exit_code == EXIT_SUCCESS:
            status = "SUCCESS"
        elif exit_code == EXIT_FINDINGS:
            status = "COMPLETED_WITH_FINDINGS"
        else:
            status = "FAILED"
            error_message = f"Prowler exited with code {exit_code}"

    except Exception as exc:
        status = "ERROR"
        error_message = str(exc)

    end_time = utc_now()
    duration = (end_time - start_time).total_seconds()

    if status in ("FAILED", "ERROR"):
        log_error(f"{status} | {scan_type} | {scan_name} | {error_message}")
        excerpt = log_excerpt(execution_log)
        if excerpt:
            log_error(f"Prowler log excerpt for {scan_name}:\n{excerpt}")
    else:
        log(f"COMPLETE | {scan_type} | {scan_name} | {status} | {duration:.1f}s")

    return {
        "assessment_type": scan_type,
        "subscription_name": scan_name,
        "subscription_id": subscription_id,
        "status": status,
        "exit_code": exit_code,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "duration_seconds": round(duration, 1),
        "output_directory": str(output_directory),
        "execution_log": str(execution_log),
        "error": error_message,
    }


def run_tenant_entra_scan(
    prowler_path: str,
    authentication: dict[str, str],
    bootstrap_subscription_id: str,
    run_directory: Path,
) -> dict[str, Any]:
    """Run Azure provider's Entra service exactly once for this tenant."""
    tenant_directory = run_directory / "tenant-entra"
    command = [
        prowler_path,
        "azure",
        "--sp-env-auth",
        "--subscription-ids",
        bootstrap_subscription_id,
        "--services",
        "entra",
        "--output-directory",
        str(tenant_directory),
        "--output-formats",
        "json-ocsf",
    ]
    log(
        "Starting the single tenant Entra assessment. "
        f"Bootstrap subscription: {bootstrap_subscription_id}"
    )
    return execute_scan(
        prowler_path=prowler_path,
        authentication=authentication,
        scan_name="Tenant Entra",
        output_directory=tenant_directory,
        command=command,
        scan_type="TENANT_ENTRA",
        subscription_id=bootstrap_subscription_id,
    )


def run_subscription_scan(
    prowler_path: str,
    authentication: dict[str, str],
    subscription: dict[str, str],
    run_directory: Path,
) -> dict[str, Any]:
    subscription_directory = (
        run_directory
        / "subscriptions"
        / f"{safe_directory_name(subscription['name'])}_{subscription['id']}"
    )
    command = [
        prowler_path,
        "azure",
        "--sp-env-auth",
        "--subscription-ids",
        subscription["id"],
        "--excluded-services",
        "entra",
        "--output-directory",
        str(subscription_directory),
        "--output-formats",
        "json-ocsf",
    ]
    return execute_scan(
        prowler_path=prowler_path,
        authentication=authentication,
        scan_name=subscription["name"],
        output_directory=subscription_directory,
        command=command,
        scan_type="SUBSCRIPTION",
        subscription_id=subscription["id"],
    )


def write_summary(run_directory: Path, results: list[dict[str, Any]]) -> Path:
    summary_file = run_directory / "prowler-run-summary.csv"
    fieldnames = [
        "assessment_type",
        "subscription_name",
        "subscription_id",
        "status",
        "exit_code",
        "start_time",
        "end_time",
        "duration_seconds",
        "output_directory",
        "execution_log",
        "error",
    ]
    with summary_file.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    return summary_file


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one tenant Entra assessment followed by concurrent Azure subscription assessments."
    )
    parser.add_argument(
        "--subscriptions",
        required=True,
        type=Path,
        help="CSV containing subscription_name,subscription_id.",
    )
    parser.add_argument(
        "--output",
        default="reports",
        type=Path,
        help="Root directory for timestamped Prowler results (default: reports).",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help=f"Maximum concurrent subscription scans (default: {DEFAULT_MAX_WORKERS}).",
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="Return non-zero if the tenant scan or any subscription scan fails.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    log("============================================================")
    log("Prowler Azure Assessment: Tenant Entra + Subscription Scans")
    log("============================================================")

    try:
        if args.max_workers < 1:
            raise RuntimeError("--max-workers must be at least 1.")

        authentication = validate_environment()
        subscriptions = load_subscriptions(args.subscriptions)
        worker_count = min(args.max_workers, len(subscriptions))
        log(f"Subscriptions loaded from CSV: {len(subscriptions)}")
        log(f"Maximum concurrent subscription scans: {worker_count}")

        prowler_path = find_prowler()
        prowler_version = get_prowler_version(prowler_path)
        run_directory = create_run_directory(args.output)
        log(f"Run directory: {run_directory}")

        run_start = utc_now()
        results: list[dict[str, Any]] = []

        # Stage 1: Entra is run once. The first CSV subscription is supplied
        # as the Azure provider's subscription context for authentication.
        tenant_result = run_tenant_entra_scan(
            prowler_path,
            authentication,
            subscriptions[0]["id"],
            run_directory,
        )
        results.append(tenant_result)

        # Stage 2: every unique subscription from the CSV is scanned. The
        # Entra service is excluded; other Azure services remain enabled.
        log("Starting subscription assessments...")
        subscription_results: list[dict[str, Any] | None] = [None] * len(subscriptions)
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_to_index = {
                executor.submit(
                    run_subscription_scan,
                    prowler_path,
                    authentication,
                    subscription,
                    run_directory,
                ): index
                for index, subscription in enumerate(subscriptions)
            }

            for future in as_completed(future_to_index):
                index = future_to_index[future]
                subscription = subscriptions[index]
                try:
                    subscription_results[index] = future.result()
                except Exception as exc:
                    log_error(f"Unexpected worker error for {subscription['id']}: {exc}")
                    subscription_results[index] = {
                        "assessment_type": "SUBSCRIPTION",
                        "subscription_name": subscription["name"],
                        "subscription_id": subscription["id"],
                        "status": "ERROR",
                        "exit_code": 1,
                        "start_time": "",
                        "end_time": "",
                        "duration_seconds": 0,
                        "output_directory": "",
                        "execution_log": "",
                        "error": str(exc),
                    }

        results.extend(result for result in subscription_results if result is not None)
        summary_file = write_summary(run_directory, results)

        successful = sum(1 for item in results if item["status"] == "SUCCESS")
        findings = sum(1 for item in results if item["status"] == "COMPLETED_WITH_FINDINGS")
        failed = sum(1 for item in results if item["status"] in ("FAILED", "ERROR"))
        subscription_count = sum(1 for item in results if item["assessment_type"] == "SUBSCRIPTION")
        total_duration = (utc_now() - run_start).total_seconds()

        log("============================================================")
        log("PROWLER ASSESSMENT COMPLETE")
        log("============================================================")
        log(f"Prowler version: {prowler_version}")
        log(f"Tenant Entra assessment: {tenant_result['status']}")
        log(f"Subscriptions processed: {subscription_count}")
        log(f"Successful scans: {successful}")
        log(f"Completed with findings: {findings}")
        log(f"Failed scans: {failed}")
        log(f"Total execution time: {total_duration:.1f}s")
        log(f"Summary: {summary_file}")
        log(f"Reports: {run_directory}")
        log("============================================================")

        if failed and args.fail_on_error:
            return 1
        return 0

    except Exception as exc:
        log_error(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
