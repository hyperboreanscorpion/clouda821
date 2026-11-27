
#!/usr/bin/env python3

"""
Prowler Azure Security Assessment

Purpose:
    Run Prowler against multiple Azure subscriptions concurrently.

Authentication:
    TENANT_ID
    CLIENT_ID
    CLIENT_SECRET

Input:
    CSV containing:
        subscription_name,subscription_id

Environment variables:
    TENANT_ID
    CLIENT_ID
    CLIENT_SECRET

Optional:
    PROWLER_COMMAND
        Override Prowler executable.

    PROWLER_VERSION
        Informational only.

Features:
    - Concurrent subscription scanning.
    - Default maximum of 3 concurrent scans.
    - Separate output directory per subscription.
    - Separate execution log per subscription.
    - Minimal Azure DevOps pipeline logging.
    - Preserves Prowler assessment reports.
    - Consolidated execution summary.
    - Handles findings separately from execution failures.

Requirements:
    Python 3.10+
    Prowler CLI installed and available in PATH
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys

from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)

from datetime import datetime, timezone
from pathlib import Path
from collections import deque


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUBSCRIPTION_ID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}$"
)

DEFAULT_OUTPUT_DIR = "reports"
DEFAULT_PROWLER_COMMAND = "prowler"
DEFAULT_MAX_WORKERS = 3

# Prowler exit codes
EXIT_SUCCESS = 0
EXIT_FINDINGS = 3


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(message: str) -> None:
    """Print concise timestamped pipeline messages."""

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")

    print(
        f"[{timestamp}] {message}",
        flush=True,
    )


def log_error(message: str) -> None:
    """Print timestamped error messages."""

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")

    print(
        f"[{timestamp}] ERROR: {message}",
        file=sys.stderr,
        flush=True,
    )


# ---------------------------------------------------------------------------
# Environment validation
# ---------------------------------------------------------------------------

def get_required_environment_variable(
    name: str,
) -> str:

    value = os.environ.get(name, "").strip()

    if not value:
        raise RuntimeError(
            f"Required environment variable '{name}' is not set."
        )

    return value


def validate_environment() -> dict[str, str]:

    log("Validating Azure service principal credentials...")

    tenant_id = get_required_environment_variable(
        "TENANT_ID"
    )

    client_id = get_required_environment_variable(
        "CLIENT_ID"
    )

    client_secret = get_required_environment_variable(
        "CLIENT_SECRET"
    )

    if not SUBSCRIPTION_ID_PATTERN.match(tenant_id):
        raise RuntimeError("TENANT_ID is not a valid GUID.")

    if not SUBSCRIPTION_ID_PATTERN.match(client_id):
        raise RuntimeError("CLIENT_ID is not a valid GUID.")

    log("Azure service principal credentials validated.")

    return {
        "TENANT_ID": tenant_id,
        "CLIENT_ID": client_id,
        "CLIENT_SECRET": client_secret,
    }


# ---------------------------------------------------------------------------
# Subscription handling
# ---------------------------------------------------------------------------

def load_subscriptions(
    subscription_file: Path,
) -> list[dict[str, str]]:

    if not subscription_file.exists():
        raise FileNotFoundError(
            f"Subscription file does not exist: {subscription_file}"
        )

    subscriptions = []
    seen = set()

    with subscription_file.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as fh:

        reader = csv.DictReader(fh)

        required_headers = {
            "subscription_name",
            "subscription_id",
        }

        if not reader.fieldnames:
            raise RuntimeError("Subscription CSV is empty.")

        if not required_headers.issubset(
            set(reader.fieldnames)
        ):
            raise RuntimeError(
                "CSV must contain subscription_name "
                "and subscription_id columns."
            )

        for line_number, row in enumerate(reader, start=2):

            subscription_name = (
                row.get("subscription_name") or ""
            ).strip()

            subscription_id = (
                row.get("subscription_id") or ""
            ).strip()

            if not subscription_name:
                raise RuntimeError(
                    f"Missing subscription name on CSV line {line_number}."
                )

            if not SUBSCRIPTION_ID_PATTERN.match(
                subscription_id
            ):
                raise RuntimeError(
                    f"Invalid subscription ID on CSV line {line_number}."
                )

            normalized_id = subscription_id.lower()

            if normalized_id in seen:
                continue

            seen.add(normalized_id)

            subscriptions.append({
                "name": subscription_name,
                "id": subscription_id,
            })

    if not subscriptions:
        raise RuntimeError("No subscriptions found in CSV.")

    return subscriptions


# ---------------------------------------------------------------------------
# Prowler validation
# ---------------------------------------------------------------------------

def find_prowler() -> str:

    prowler_command = os.environ.get(
        "PROWLER_COMMAND",
        DEFAULT_PROWLER_COMMAND,
    )

    prowler_path = shutil.which(prowler_command)

    if not prowler_path:
        raise RuntimeError(
            f"Prowler executable '{prowler_command}' "
            "was not found in PATH."
        )

    return prowler_path


def get_prowler_version(
    prowler_path: str,
) -> str:

    result = subprocess.run(
        [
            prowler_path,
            "-v",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Unable to determine installed Prowler version."
        )

    version = (
        result.stdout.strip()
        or result.stderr.strip()
    )

    # Keep pipeline output short.
    version = version.splitlines()[0][:200] if version else "Unknown"

    log(f"Prowler version: {version}")

    return version


# ---------------------------------------------------------------------------
# Output handling
# ---------------------------------------------------------------------------

def create_run_directory(
    output_dir: Path,
) -> Path:

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%S%fZ")

    run_directory = output_dir / timestamp

    run_directory.mkdir(
        parents=True,
        exist_ok=False,
    )

    return run_directory


def create_subscription_directory(
    run_directory: Path,
    subscription_name: str,
    subscription_id: str,
) -> Path:

    safe_name = re.sub(
        r"[^A-Za-z0-9._-]+",
        "-",
        subscription_name,
    ).strip("-")

    directory_name = (
        f"{safe_name[:60]}_{subscription_id}"
    )

    subscription_directory = (
        run_directory / directory_name
    )

    subscription_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return subscription_directory


# ---------------------------------------------------------------------------
# Execution log handling
# ---------------------------------------------------------------------------

def get_log_excerpt(
    log_file: Path,
    max_lines: int = 15,
) -> str:

    try:
        with log_file.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as fh:

            lines = deque(
                fh,
                maxlen=max_lines,
            )

        return "".join(lines)[-2500:]

    except Exception:
        return "Unable to read execution log."

# ---------------------------------------------------------------------------
# Prowler execution
# ---------------------------------------------------------------------------

def run_prowler_for_subscription(
    prowler_path: str,
    authentication: dict[str, str],
    subscription_name: str,
    subscription_id: str,
    run_directory: Path,
) -> dict[str, object]:

    start_time = datetime.now(timezone.utc)

    subscription_output = create_subscription_directory(
        run_directory,
        subscription_name,
        subscription_id,
    )

    execution_log = (
        subscription_output / "prowler-execution.log"
    )

    environment = os.environ.copy()

    environment["AZURE_TENANT_ID"] = (
        authentication["TENANT_ID"]
    )

    environment["AZURE_CLIENT_ID"] = (
        authentication["CLIENT_ID"]
    )

    environment["AZURE_CLIENT_SECRET"] = (
        authentication["CLIENT_SECRET"]
    )

    environment["PROWLER_OUTPUT_DIRECTORY"] = str(
        subscription_output
    )

    command = [
        prowler_path,
        "azure",
        "--sp-env-auth",
        "--subscription-ids",
        subscription_id,
        "--output-directory",
        str(subscription_output),
        "--output-formats",
#        "csv",
#        "html",
        "json-ocsf",
    ]

    log(
        f"START | {subscription_name} | {subscription_id}"
    )

    try:

        # Redirect all Prowler output to its own log file.
        # Nothing is captured in memory or continuously
        # printed into Azure DevOps pipeline logs.

        with execution_log.open(
            "w",
            encoding="utf-8",
        ) as log_handle:

            result = subprocess.run(
                command,
                env=environment,
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

        if status == "FAILED":

            excerpt = get_log_excerpt(execution_log)

            log_error(
                f"FAILED | {subscription_id} | "
                f"Exit code: {exit_code}"
            )

            if excerpt:
                log_error(
                    f"Last Prowler log entries:\n{excerpt}"
                )

        end_time = datetime.now(timezone.utc)

        duration = (
            end_time - start_time
        ).total_seconds()

        log(
            f"COMPLETE | {subscription_name} | "
            f"{status} | {duration:.1f}s"
        )

        return {
            "subscription_name": subscription_name,
            "subscription_id": subscription_id,
            "status": status,
            "exit_code": exit_code,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": round(duration, 1),
            "output_directory": str(subscription_output),
            "execution_log": str(execution_log),
        }

    except Exception as exc:

        end_time = datetime.now(timezone.utc)

        duration = (
            end_time - start_time
        ).total_seconds()

        log_error(
            f"EXECUTION ERROR | {subscription_id} | {exc}"
        )

        return {
            "subscription_name": subscription_name,
            "subscription_id": subscription_id,
            "status": "ERROR",
            "exit_code": 1,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": round(duration, 1),
            "output_directory": str(subscription_output),
            "execution_log": str(execution_log),
        }


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def write_summary(
    run_directory: Path,
    results: list[dict[str, object]],
) -> Path:

    summary_file = (
        run_directory / "prowler-run-summary.csv"
    )

    fieldnames = [
        "subscription_name",
        "subscription_id",
        "status",
        "exit_code",
        "start_time",
        "end_time",
        "duration_seconds",
        "output_directory",
        "execution_log",
    ]

    with summary_file.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as fh:

        writer = csv.DictWriter(
            fh,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        writer.writerows(results)

    return summary_file


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        description=(
            "Run concurrent Prowler Azure security assessments."
        )
    )

    parser.add_argument(
        "--subscriptions",
        required=True,
        type=Path,
        help="CSV containing subscription_name,subscription_id.",
    )

    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_DIR,
        type=Path,
        help=f"Base output directory. Default: {DEFAULT_OUTPUT_DIR}",
    )

    parser.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help=(
            "Maximum concurrent subscription scans. "
            f"Default: {DEFAULT_MAX_WORKERS}"
        ),
    )

    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help=(
            "Return a non-zero script exit code if "
            "any subscription scan fails."
        ),
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:

    args = parse_arguments()

    log("==================================================")
    log("Prowler Azure Security Assessment")
    log("==================================================")

    try:

        if args.max_workers < 1:
            raise RuntimeError(
                "--max-workers must be at least 1."
            )

        authentication = validate_environment()

        log(
            f"Loading subscriptions: {args.subscriptions}"
        )

        subscriptions = load_subscriptions(
            args.subscriptions
        )

        worker_count = min(
            args.max_workers,
            len(subscriptions),
        )

        log(
            f"Subscriptions found: {len(subscriptions)}"
        )

        log(
            f"Maximum concurrent scans: {worker_count}"
        )

        prowler_path = find_prowler()

        prowler_version = get_prowler_version(
            prowler_path
        )

        run_directory = create_run_directory(
            args.output
        )

        log(
            f"Run directory: {run_directory}"
        )

        run_start = datetime.now(timezone.utc)

        # Preallocate results to preserve original CSV order.
        results: list[dict[str, object] | None] = [
            None
        ] * len(subscriptions)

        # ---------------------------------------------------------------
        # Concurrent subscription scanning
        # ---------------------------------------------------------------

        log("Starting concurrent Prowler assessments...")

        with ThreadPoolExecutor(
            max_workers=worker_count
        ) as executor:

            future_to_index = {}

            for index, subscription in enumerate(
                subscriptions
            ):

                future = executor.submit(
                    run_prowler_for_subscription,
                    prowler_path,
                    authentication,
                    subscription["name"],
                    subscription["id"],
                    run_directory,
                )

                future_to_index[future] = index

            for future in as_completed(future_to_index):

                index = future_to_index[future]

                try:

                    results[index] = future.result()

                except Exception as exc:

                    subscription = subscriptions[index]

                    log_error(
                        f"Unexpected worker error for "
                        f"{subscription['id']}: {exc}"
                    )

                    results[index] = {
                        "subscription_name": subscription["name"],
                        "subscription_id": subscription["id"],
                        "status": "ERROR",
                        "exit_code": 1,
                        "start_time": "",
                        "end_time": "",
                        "duration_seconds": 0,
                        "output_directory": "",
                        "execution_log": "",
                    }

        completed_results = [
            result
            for result in results
            if result is not None
        ]

        # ---------------------------------------------------------------
        # Summary
        # ---------------------------------------------------------------

        summary_file = write_summary(
            run_directory,
            completed_results,
        )

        successful = sum(
            1 for result in completed_results
            if result["status"] == "SUCCESS"
        )

        findings = sum(
            1 for result in completed_results
            if result["status"] == "COMPLETED_WITH_FINDINGS"
        )

        failed = sum(
            1 for result in completed_results
            if result["status"] in ("FAILED", "ERROR")
        )

        total_duration = (
            datetime.now(timezone.utc) - run_start
        ).total_seconds()

        log("==================================================")
        log("PROWLER ASSESSMENT COMPLETE")
        log("==================================================")

        log(f"Prowler version: {prowler_version}")
        log(f"Subscriptions scanned: {len(completed_results)}")
        log(f"Successful: {successful}")
        log(f"Completed with findings: {findings}")
        log(f"Failed: {failed}")
        log(f"Total execution time: {total_duration:.1f}s")
        log(f"Summary: {summary_file}")
        log(f"Reports: {run_directory}")

        log("==================================================")

        if failed > 0 and args.fail_on_error:
            return 1

        return 0

    except Exception as exc:

        log_error(str(exc))

        return 1


if __name__ == "__main__":
    sys.exit(main())
