#!/usr/bin/env python3

"""
Prowler Azure Security Assessment - Proof of Concept

Purpose:
    Run the open-source Prowler CLI against a supplied list of
    Azure subscriptions using an Azure service principal.

Authentication:
    TENANT_ID
    CLIENT_ID
    CLIENT_SECRET

Input:
    Text file containing one Azure subscription ID per line.

Environment variables:
    TENANT_ID
    CLIENT_ID
    CLIENT_SECRET

Optional:
    PROWLER_COMMAND
        Override the Prowler executable. Default: "prowler"

    PROWLER_VERSION
        Informational only. The script does not install Prowler.

Requirements:
    Python 3.10+
    Prowler CLI installed and available in PATH

The script intentionally runs one Prowler assessment per subscription.
This makes Azure DevOps artifacts and troubleshooting easier.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import csv
from datetime import datetime, timezone
from pathlib import Path


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

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(message: str) -> None:
    """Print a timestamped informational message."""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(
        f"[{timestamp}] {message}",
        flush=True,
    )


def log_error(message: str) -> None:
    """Print a timestamped error message."""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(
        f"[{timestamp}] ERROR: {message}",
        file=sys.stderr,
        flush=True,
    )


# ---------------------------------------------------------------------------
# Environment validation
# ---------------------------------------------------------------------------

def get_required_environment_variable(name: str) -> str:
    """
    Retrieve a required environment variable.

    Never prints the value because some variables contain secrets.
    """

    value = os.environ.get(name)

    if not value:
        raise RuntimeError(
            f"Required environment variable '{name}' is not set."
        )

    return value.strip()


def validate_environment() -> dict[str, str]:
    """
    Validate Azure service principal environment variables.

    Returns:
        Dictionary containing authentication environment variables.
    """

    log("Validating Azure authentication environment variables...")

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
        log(
            "WARNING: TENANT_ID does not appear to be "
            "a standard GUID."
        )

    if not SUBSCRIPTION_ID_PATTERN.match(client_id):
        log(
            "WARNING: CLIENT_ID does not appear to be "
            "a standard GUID."
        )

    if not client_secret:
        raise RuntimeError(
            "CLIENT_SECRET is empty."
        )

    log("Azure authentication variables are present.")

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
            f"Subscription file does not exist: "
            f"{subscription_file}"
        )

    subscriptions: list[dict[str, str]] = []

    seen: set[str] = set()

    with subscription_file.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as fh:

        reader = csv.DictReader(fh)

        expected_headers = {
            "subscription_name",
            "subscription_id",
        }

        if not reader.fieldnames:
            raise RuntimeError(
                "Subscription CSV is empty."
            )

        if set(reader.fieldnames) != expected_headers:
            raise RuntimeError(
                "CSV must contain headers: "
                "subscription_name,subscription_id"
            )

        for row in reader:

            subscription_name = (
                row["subscription_name"]
                .strip()
            )

            subscription_id = (
                row["subscription_id"]
                .strip()
            )

            if not SUBSCRIPTION_ID_PATTERN.match(
                subscription_id
            ):
                raise RuntimeError(
                    f"Invalid subscription ID: "
                    f"{subscription_id}"
                )

            normalized_id = (
                subscription_id.lower()
            )

            if normalized_id in seen:
                log(
                    f"Duplicate subscription ignored: "
                    f"{subscription_name}"
                )
                continue

            seen.add(normalized_id)

            subscriptions.append(
                {
                    "name": subscription_name,
                    "id": subscription_id,
                }
            )

    if not subscriptions:
        raise RuntimeError(
            "No subscriptions found in CSV."
        )

    return subscriptions

# ---------------------------------------------------------------------------
# Prowler validation
# ---------------------------------------------------------------------------

def find_prowler() -> str:
    """
    Find the Prowler executable.
    """

    prowler_command = os.environ.get(
        "PROWLER_COMMAND",
        DEFAULT_PROWLER_COMMAND,
    )

    prowler_path = shutil.which(
        prowler_command
    )

    if not prowler_path:
        raise RuntimeError(
            f"Prowler executable '{prowler_command}' "
            "was not found in PATH."
        )

    return prowler_path


def get_prowler_version(
    prowler_path: str,
) -> None:
    """
    Display the installed Prowler version.
    """

    log(
        f"Checking Prowler installation: "
        f"{prowler_path}"
    )

    result = subprocess.run(
        [
            prowler_path,
            "-v",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        log_error(
            "Unable to determine Prowler version."
        )

        if result.stderr:
            log_error(
                result.stderr.strip()
            )

        raise RuntimeError(
            "Prowler version check failed."
        )

    version_output = (
        result.stdout.strip()
        or result.stderr.strip()
    )

    if version_output:
        log(
            f"Prowler version: {version_output}"
        )


# ---------------------------------------------------------------------------
# Output handling
# ---------------------------------------------------------------------------

def create_run_directory(
    output_dir: Path,
) -> Path:
    """
    Create a timestamped Prowler run directory.
    """

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%dT%H%M%SZ"
    )

    run_directory = (
        output_dir / timestamp
    )

    run_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return run_directory


#def create_subscription_directory(
#    run_directory: Path,
#    subscription_id: str,
#) -> Path:
#    """
#    Create an output directory for a subscription.
#    """

#    subscription_directory = (
#        run_directory / subscription_id
#    )

#    subscription_directory.mkdir(
#        parents=True,
#        exist_ok=True,
#    )

#    return subscription_directory


# ---------------------------------------------------------------------------
# Prowler execution
# ---------------------------------------------------------------------------

def run_prowler_for_subscription(
    prowler_path: str,
    tenant_id: str,
    subscription_name: str,
    subscription_id: str,
    output_directory: Path,
) -> int:
    """
    Execute Prowler against one Azure subscription.

    Authentication is provided through environment variables.

    Returns:
        Prowler process exit code.
    """

    log(
        "--------------------------------------------------"
    )

    log(
        f"Starting Prowler assessment"
    )

    log(
        f"Subscription: {subscription_id}"
    )

    log(
        f"Output directory: {output_directory}"
    )

#    subscription_output = (
#        output_directory / subscription_id
#    )

    safe_name = (
        subscription_name
        .replace("/", "-")
        .replace("\\", "-")
        .replace(":", "-")
    )

    subscription_output = (
        output_directory / safe_name
    )

    subscription_output.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Environment inherited from Azure DevOps.
    #
    # The secret is NEVER added to the command line.
    environment = os.environ.copy()

#    environment[
#        "TENANT_ID"
#    ] = tenant_id

    environment["AZURE_TENANT_ID"] = os.environ["TENANT_ID"]
    environment["AZURE_CLIENT_ID"] = os.environ["CLIENT_ID"]
    environment["AZURE_CLIENT_SECRET"] = os.environ["CLIENT_SECRET"]

    log(
        f"AZURE_TENANT_ID={environment.get('AZURE_TENANT_ID','MISSING')}"
    )

    log(
        f"AZURE_CLIENT_ID={environment.get('AZURE_CLIENT_ID','MISSING')}"
    )

    log(
        "AZURE_CLIENT_SECRET="
        + (
            "SET"
            if environment.get("AZURE_CLIENT_SECRET")
            else "MISSING"
        )
    )

    # Explicitly request service-principal environment
    # authentication from Prowler.
    #
    # The actual secret remains in CLIENT_SECRET.
    #
    # We do not print the environment.
    environment[
        "PROWLER_OUTPUT_DIRECTORY"
    ] = str(subscription_output)

    command = [
        prowler_path,
        "azure",
        "--sp-env-auth",
        "--subscription-ids",
        subscription_id,
#        "--output-directory",
#        str(subscription_output),
#        "--output-formats",
#        "csv",
#        "html",
#        "json-ocsf"
    ]

#    command = [
#        prowler_path,
#        "azure",
#        "--sp-env-auth",
#        "--subscription-ids",
#        subscription_id,
#    ]

    # Print a sanitized command for troubleshooting.
    #
    # There is intentionally NO client secret here.
    log(
        "Executing: "
        + " ".join(command)
    )

 #   result = subprocess.run(
 #       command,
 #       env=environment,
 #       check=False,
 #   )

    result = subprocess.run(
        command,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode in (0,3):
        status = "SUCCESS"
        log(
            f"Prowler completed successfully for "
            f"{subscription_id}"
        )
    else:
        status = "FAILED"
        log_error(
            f"Prowler returned exit code "
            f"{result.returncode} for "
            f"{subscription_id}"
        )

    if result.stdout:
        log(result.stdout)

    if result.stderr:
        log_error(result.stderr)
        
    return result.returncode

def cleanup_prowler_outputs(
    subscription_output: Path,
):

    prefixes = [
        "cis",
        "nist",
        "soc2",
        "pci",
        "fedramp",
        "mitre",
        "iso",
        "ens",
        "aws",
        "kubernetes",
    ]

    for file in subscription_output.glob("*"):

        name = file.name.lower()

        if any(
            name.startswith(prefix)
            for prefix in prefixes
        ):
            file.unlink(
                missing_ok=True
            )

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def write_summary(
    run_directory: Path,
    results: list[dict[str, object]],
) -> Path:
    """
    Write a simple machine-readable summary.
    """

    summary_file = (
        run_directory / "prowler-run-summary.csv"
    )

    with summary_file.open(
        "w",
        encoding="utf-8",
    ) as file_handle:

        file_handle.write(
            "subscription_name,subscription_id,status,exit_code\n"
        )

        for result in results:

            subscription_name = str(
                result["subscription_name"]
            )

            subscription_id = str(
                result["subscription_id"]
            )

            status = str(
                result["status"]
            )

            exit_code = str(
                result["exit_code"]
            )

            file_handle.write(
                f"{subscription_name},"
                f"{subscription_id},"
                f"{status},"
                f"{exit_code}\n"
            )

    return summary_file


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Run Prowler Azure assessments using "
            "a service principal."
        )
    )

    parser.add_argument(
        "--subscriptions",
        required=True,
        type=Path,
        help=(
            "Path to CSV file containing"
            "subscription_name,subscription_id"
        ),
    )

    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_DIR,
        type=Path,
        help=(
            "Base output directory. "
            f"Default: {DEFAULT_OUTPUT_DIR}"
        ),
    )

    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help=(
            "Return a non-zero script exit code if "
            "any subscription assessment fails."
        ),
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:

    args = parse_arguments()

    log(
        "=================================================="
    )

    log(
        "Prowler Azure Security Assessment POC"
    )

    log(
        "=================================================="
    )

    try:

        # ---------------------------------------------------------------
        # Validate Azure credentials.
        # ---------------------------------------------------------------

        authentication = (
            validate_environment()
        )

        tenant_id = authentication[
            "TENANT_ID"
        ]

        # ---------------------------------------------------------------
        # Load subscriptions.
        # ---------------------------------------------------------------

        log(
            f"Loading subscriptions from: "
            f"{args.subscriptions}"
        )

        subscriptions = load_subscriptions(
            args.subscriptions
        )

        log(
            f"Found {len(subscriptions)} "
            f"subscription(s)."
        )

        for subscription in subscriptions:
            subscription_name = subscription["name"]
            subscription_id = subscription["id"]

            log(
                f"  - {subscription_id}"
            )

        # ---------------------------------------------------------------
        # Locate Prowler.
        # ---------------------------------------------------------------

        prowler_path = find_prowler()

        get_prowler_version(
            prowler_path
        )

        # ---------------------------------------------------------------
        # Create run directory.
        # ---------------------------------------------------------------

        run_directory = create_run_directory(
            args.output
        )

        log(
            f"Run output directory: "
            f"{run_directory}"
        )

        # ---------------------------------------------------------------
        # Run assessments.
        # ---------------------------------------------------------------

        results: list[
            dict[str, object]
        ] = []

        for subscription in subscriptions:
            subscription_name = subscription["name"]
            subscription_id = subscription["id"]

            start_time = datetime.now(
                timezone.utc
            )

            try:

                exit_code = run_prowler_for_subscription(
                        prowler_path=prowler_path,
                        tenant_id=tenant_id,
                        subscription_name=subscription_name,
                        subscription_id=subscription_id,
                        output_directory=run_directory,
                )

                if exit_code == 0:

                    status = "SUCCESS"

                    safe_name = (
                        subscription_name
                        .replace("/", "-")
                        .replace("\\", "-")
                        .replace(":", "-")
                    )

                    subscription_output = (
                        run_directory / safe_name
                    )

                    cleanup_prowler_outputs(subscription_output)

                else:

                    status = "FAILED"

            except Exception as exc:

                log_error(
                    f"Exception while scanning "
                    f"{subscription_id}: {exc}"
                )

                exit_code = 1
                status = "ERROR"

            end_time = datetime.now(
                timezone.utc
            )

            duration_seconds = (
                end_time - start_time
            ).total_seconds()

            results.append(
#                {
#                    "subscription_id": subscription_id,
#                    "status": status,
#                    "exit_code": exit_code,
#                    "duration_seconds": duration_seconds,
#                }
                {
                    "subscription_name": subscription_name,
                    "subscription_id": subscription_id,
                    "status": status,
                    "exit_code": exit_code,
                }
            )

            log(
                f"Completed {subscription_id} "
                f"with status={status} "
                f"duration={duration_seconds:.1f}s"
            )

        # ---------------------------------------------------------------
        # Write summary.
        # ---------------------------------------------------------------

        summary_file = write_summary(
            run_directory,
            results,
        )

        log(
            f"Summary written to: "
            f"{summary_file}"
        )

        # ---------------------------------------------------------------
        # Print final summary.
        # ---------------------------------------------------------------

        successful = sum(
            1
            for result in results
            if result["status"] == "SUCCESS"
        )

        failed = len(results) - successful

        log(
            "=================================================="
        )

        log(
            "Prowler run complete"
        )

        log(
            f"Subscriptions scanned: {len(results)}"
        )

        log(
            f"Successful: {successful}"
        )

        log(
            f"Failed: {failed}"
        )

        log(
            f"Results: {run_directory}"
        )

        log(
            "=================================================="
        )

        # ---------------------------------------------------------------
        # Pipeline exit behavior.
        # ---------------------------------------------------------------

        if failed > 0 and args.fail_on_error:

            return 1

        return 0

    except Exception as exc:

        log_error(
            str(exc)
        )

        return 1


if __name__ == "__main__":
    sys.exit(
        main()
    )
