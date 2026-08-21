#!/usr/bin/env python3
"""
Unified Security Scanner
========================
All-in-one entry point for the thesis security scanners:
  - HTTPS/TLS Scanner (wraps testssl.sh)
  - HTTP Security Headers Scanner (browser emulation via requests)
  - DNSSEC Scanner (Google DoH API)

Usage:
    python main.py --all                 Run all scanners + analysis
    python main.py --https               Run HTTPS/TLS scanner only
    python main.py --headers             Run Security Headers scanner only
    python main.py --dnssec              Run DNSSEC scanner only
    python main.py --analyze-only        Run analysis/report generation only (skip scanning)
    python main.py --https --dnssec      Run specific combination

Central directory layout (src/):
    src/source/              Place your input CSV files here (once)
    src/results/{scanner}/   Scan result CSVs
    src/charts/{scanner}/    Generated PDF charts
    src/tables/{scanner}/    Generated LaTeX tables
"""

import argparse
import logging
import os
import re
import shutil
import stat
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
CENTRAL_SOURCE = PROJECT_ROOT / "src" / "source"
CENTRAL_RESULTS = PROJECT_ROOT / "src" / "results"
CENTRAL_CHARTS = PROJECT_ROOT / "src" / "charts"
CENTRAL_TABLES = PROJECT_ROOT / "src" / "tables"
TESTSSL_DIR = PROJECT_ROOT / "testssl.sh"

# Shared run stamp used by every scanner launched from this CLI invocation.
# Format: 2026-04-24T08-30-15 (ISO-like with colons replaced, safe for
# filesystem use on Windows/macOS/Linux and still chronologically sortable).
RUN_STAMP = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
os.environ.setdefault("SCAN_RUN_STAMP", RUN_STAMP)

# Use the non-interactive Agg backend so matplotlib never opens display windows.
# Must be set before any scanner module imports pyplot.
os.environ.setdefault("MPLBACKEND", "Agg")


def _ensure_testssl_permissions():
    """Ensure testssl.sh and its bundled OpenSSL binaries are executable.

    Zip archives do not preserve Unix file permissions, so after extraction
    the testssl.sh script and the OpenSSL binaries in bin/ will lack the
    execute bit.  Without it, testssl.sh falls back to the system OpenSSL
    which typically has far fewer ciphers (~96) and causes scan failures.
    """
    testssl_script = TESTSSL_DIR / "testssl.sh"
    if testssl_script.exists():
        testssl_script.chmod(testssl_script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        logging.debug(f"Set execute permission on {testssl_script}")

    bin_dir = TESTSSL_DIR / "bin"
    if bin_dir.exists():
        for f in bin_dir.iterdir():
            if f.is_file() and f.name.startswith("openssl"):
                f.chmod(f.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                logging.debug(f"Set execute permission on {f}")


SCANNER_MAP = {
    "https": {
        "dir": PROJECT_ROOT / "http_scanner",
        "source": "src/data/source",
        "results": "src/data/results",
        "charts": "src/data/reports/charts",
        "tables": "src/data/reports/tables",
        "extra_results": [],
    },
    "headers": {
        "dir": PROJECT_ROOT / "security_headers_scanner",
        "source": "src/data/source",
        "results": "src/data/results",
        "charts": "src/data/results/analysis/charts",
        "tables": "src/data/results/analysis/tables",
        "extra_results": ["src/data/results/analysis"],
    },
    "dnssec": {
        "dir": PROJECT_ROOT / "dnssec_scanner",
        "source": "src/data/source",
        "results": "src/data/results",
        "charts": "src/data/reports/charts",
        "tables": "src/data/reports/tables",
        "extra_results": [],
    },
}


def _prepare_source(scanner_name: str) -> bool:
    """Copy CSV files from central src/source/ into a scanner's internal source directory."""
    info = SCANNER_MAP[scanner_name]
    scanner_source = info["dir"] / info["source"]
    scanner_source.mkdir(parents=True, exist_ok=True)

    csv_files = list(CENTRAL_SOURCE.glob("*.csv"))
    if not csv_files:
        logging.warning(f"No CSV files found in {CENTRAL_SOURCE}")
        return False

    for csv_file in csv_files:
        shutil.copy2(csv_file, scanner_source / csv_file.name)
        logging.debug(f"Copied {csv_file.name} -> {scanner_source}")

    return True


def _stamp_name(filename: str) -> str:
    """Return a filename annotated with the shared RUN_STAMP.

    Already-stamped filenames (containing "__20") are returned unchanged so
    the function is idempotent across retries and multiple --analyze-only runs.
    """
    if "__20" in filename:
        return filename
    stem, ext = os.path.splitext(filename)
    return f"{stem}__{RUN_STAMP}{ext}"


def _inject_run_timestamp(csv_path):
    """Ensure the CSV has a `run_timestamp` column equal to RUN_STAMP.

    This is what the platform's Timeline tab uses to plot trajectories over
    time. Skipped silently on any error, since timestamp injection is a
    nice-to-have and must never block a successful scan.
    """
    try:
        import pandas as pd
        df = pd.read_csv(csv_path)
        df["run_timestamp"] = RUN_STAMP
        df.to_csv(csv_path, index=False, encoding="utf-8")
    except Exception as e:
        logging.debug(f"Skipping timestamp injection for {csv_path}: {e}")


def _count_csv_rows(files) -> int:
    """Count total data rows (excluding header) across a list of CSV files."""
    total = 0
    for f in files:
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                total += max(0, sum(1 for _ in fh) - 1)
        except Exception:
            pass
    return total


def _update_latest(scanner_name: str):
    """Refresh the latest/ snapshot directories for a scanner's outputs.

    For each output category (results, charts, tables), clears the
    <category>/<scanner>/latest/ directory and repopulates it with the files
    just collected for this run, with the __<RUN_STAMP> suffix stripped.
    Subdirectory structure inside the scanner dir is preserved.
    """
    stamp_suffix = f"__{RUN_STAMP}"
    for central_dir in [CENTRAL_RESULTS, CENTRAL_CHARTS, CENTRAL_TABLES]:
        scanner_central = central_dir / scanner_name
        latest_dir = scanner_central / "latest"

        if latest_dir.exists():
            shutil.rmtree(latest_dir)
        latest_dir.mkdir(parents=True, exist_ok=True)

        if not scanner_central.exists():
            continue

        for f in scanner_central.rglob("*"):
            if not f.is_file():
                continue
            try:
                rel_to_scanner = f.relative_to(scanner_central)
            except ValueError:
                continue
            if "latest" in rel_to_scanner.parts:
                continue
            if stamp_suffix not in f.name:
                continue

            clean_name = f.name.replace(stamp_suffix, "")
            rel_parent = f.parent.relative_to(scanner_central)
            dest = latest_dir / rel_parent / clean_name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest)

    logging.info(
        f"[{scanner_name}] latest/ updated -> "
        f"src/results/{scanner_name}/latest/, src/charts/{scanner_name}/latest/, "
        f"src/tables/{scanner_name}/latest/"
    )


def _collect_outputs(scanner_name: str):
    """Collect scanner outputs into the central src/ directories.

    Every copied CSV is renamed with the current RUN_STAMP appended, so
    repeated runs accumulate historical snapshots instead of overwriting.
    After collecting, the latest/ snapshot is refreshed via _update_latest.
    """
    info = SCANNER_MAP[scanner_name]
    scanner_dir = info["dir"]

    results_dir = scanner_dir / info["results"]
    central_results = CENTRAL_RESULTS / scanner_name
    central_results.mkdir(parents=True, exist_ok=True)
    if results_dir.exists():
        for f in results_dir.rglob("*.csv"):
            rel = f.relative_to(results_dir)
            dest = central_results / rel.parent / _stamp_name(rel.name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest)
            _inject_run_timestamp(dest)

    for extra in info["extra_results"]:
        extra_dir = scanner_dir / extra
        if extra_dir.exists():
            for f in extra_dir.rglob("*.csv"):
                rel = f.relative_to(extra_dir)
                dest = central_results / rel.parent / _stamp_name(rel.name)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dest)
                _inject_run_timestamp(dest)

    charts_dir = scanner_dir / info["charts"]
    central_charts = CENTRAL_CHARTS / scanner_name
    central_charts.mkdir(parents=True, exist_ok=True)
    if charts_dir.exists():
        for f in charts_dir.rglob("*.pdf"):
            shutil.copy2(f, central_charts / _stamp_name(f.name))

    tables_dir = scanner_dir / info["tables"]
    central_tables = CENTRAL_TABLES / scanner_name
    central_tables.mkdir(parents=True, exist_ok=True)
    if tables_dir.exists():
        for f in tables_dir.rglob("*.tex"):
            shutil.copy2(f, central_tables / _stamp_name(f.name))

    logging.info(
        f"[{scanner_name}] Outputs collected (stamp={RUN_STAMP}) -> "
        f"src/results/{scanner_name}/, src/charts/{scanner_name}/, src/tables/{scanner_name}/"
    )

    _update_latest(scanner_name)


def _clear_scanner_results(scanner_name: str):
    """Delete existing result CSVs from the scanner's internal results dir.

    Called before a fresh scan so results from previous runs do not accumulate
    in the output file.  Only non-error CSVs are removed; error logs are kept.
    The HTTPS scanner uses its own resume logic and is intentionally excluded.
    """
    if scanner_name == "https":
        return
    info = SCANNER_MAP[scanner_name]
    results_dir = info["dir"] / info["results"]
    if not results_dir.exists():
        return
    for f in results_dir.glob("*.csv"):
        if "_errors_" in f.name:
            continue
        try:
            f.unlink()
            logging.debug(f"[{scanner_name}] Cleared previous result: {f.name}")
        except Exception as e:
            logging.warning(f"[{scanner_name}] Could not clear {f.name}: {e}")


def _clear_scanner_reports(scanner_name: str):
    """Delete existing chart/table files from the scanner's internal report
    dirs before regenerating them.

    Without this, a chart or table that stops being written by a generator
    function (a bug, or code that no longer calls savefig()/save_table() for
    it) leaves its last-successful copy sitting in the scanner's internal
    directory forever. _collect_outputs() blindly copies whatever files
    exist there into the central archive and latest/ on every run,
    re-stamping the filename with the CURRENT run's timestamp -- but
    shutil.copy2 preserves the original file's mtime, so the stale file
    keeps masquerading as part of "the latest run" indefinitely, under an
    ever-more-misleading stamp (this is exactly how the "_by_country" charts
    went stale for months without anyone noticing). Clearing first means a
    generator that silently stops producing a file leaves that file visibly
    missing from latest/, instead of stale-but-disguised as current.
    Runs unconditionally (scan and --analyze-only alike), since report
    generation -- and therefore this staleness risk -- happens in both.
    """
    info = SCANNER_MAP[scanner_name]
    for key, pattern in (("charts", "*.pdf"), ("tables", "*.tex")):
        report_dir = info["dir"] / info[key]
        if not report_dir.exists():
            continue
        for f in report_dir.rglob(pattern):
            try:
                f.unlink()
            except Exception as e:
                logging.warning(f"[{scanner_name}] Could not clear {f}: {e}")


def _run_scanner(scanner_name: str, analyze_only: bool = False):
    """Run a scanner by changing to its directory, importing, and executing."""
    info = SCANNER_MAP[scanner_name]
    scanner_dir = info["dir"]
    logging.info(f"{'Analyzing' if analyze_only else 'Running'} {scanner_name}...")

    original_cwd = os.getcwd()
    original_path = sys.path.copy()

    try:
        os.chdir(scanner_dir)
        sys.path.insert(0, str(scanner_dir))

        _clear_scanner_reports(scanner_name)

        if not analyze_only:
            _clear_scanner_results(scanner_name)

        if scanner_name == "https":
            from src.scanner.http import scan
            from src.analyzer.main import main as run_analysis

            if not analyze_only:
                input_dir = scanner_dir / "src" / "data" / "source"
                https_files = sorted(input_dir.glob("*.csv"))
                logging.info(f"[https] Total: {_count_csv_rows(https_files)} institutions to scan")
                for f in https_files:
                    try:
                        logging.info(f"[https] Scanning file: {f.name}")
                        scan(str(f))
                    except Exception as e:
                        logging.error(f"[https] Error scanning {f.name}: {e}")

            logging.info("[https] Running analysis...")
            try:
                run_analysis()
            except Exception as e:
                logging.error(f"[https] Analysis error: {e}")

        elif scanner_name == "headers":
            from src.scanner.scanner import run_scan
            from src.scanner.utils.utils import check_error_files, reset_error_files
            from src.analyzer.report.main import generate_reports

            if not analyze_only:
                input_dir = scanner_dir / "src" / "data" / "source"
                # reset_error_files() (or an interrupted past run) can leave a
                # "<cc>_errors.csv" sitting in the scanner's own source/ dir
                # for the *next* invocation to pick up as if it were a real
                # dataset — silently re-scanning stale, possibly outdated
                # hosts alongside the current source list and duplicating
                # any institution that's ALSO in it under its current URL.
                # By naming convention that suffix never belongs in source/,
                # so any run starts by clearing it out.
                for stale in input_dir.glob("*_errors.csv"):
                    logging.info(f"[headers] Removing stale leftover from a previous run: {stale.name}")
                    stale.unlink()
                files = [f for f in input_dir.iterdir()
                         if f.suffix == ".csv" and re.match(r'^[a-zA-Z]{2}[-_]', f.name)]
                logging.info(f"[headers] Total: {_count_csv_rows(files)} institutions to scan")
                max_assessments = 10
                assessments = 0

                while True:
                    for f in sorted(files):
                        try:
                            logging.info(f"[headers] Scanning file: {f.name}")
                            run_scan(str(f))
                        except Exception as e:
                            logging.error(f"[headers] Error scanning {f.name}: {e}")

                    assessments += 1
                    if check_error_files():
                        if assessments >= max_assessments:
                            logging.warning(f"[headers] Max attempts reached ({max_assessments}).")
                            break
                        reset_error_files()
                        # `files` still points at the ORIGINAL full source
                        # lists. Without narrowing it, every retry pass
                        # re-scans every institution that already succeeded
                        # too — not just the ones that failed — silently
                        # multiplying their row count by however many retry
                        # passes run (a real ~10x duplication was observed).
                        # reset_error_files() just wrote the retry-worthy
                        # subset into source/<cc>_errors.csv, so only that
                        # needs scanning from here on.
                        files = list(input_dir.glob("*_errors.csv"))
                    else:
                        break

            logging.info("[headers] Generating reports...")
            try:
                generate_reports()
            except Exception as e:
                logging.error(f"[headers] Report generation error: {e}")

        elif scanner_name == "dnssec":
            from src.scanner.dnssec import scan
            from src.analyzer.main import generate_reports

            if not analyze_only:
                input_dir = scanner_dir / "src" / "data" / "source"
                files = [f for f in input_dir.iterdir()
                         if f.suffix == ".csv" and re.match(r'^[a-zA-Z]{2}[-_]', f.name)]
                logging.info(f"[dnssec] Total: {_count_csv_rows(files)} domains to scan")
                for f in sorted(files):
                    try:
                        logging.info(f"[dnssec] Scanning file: {f.name}")
                        scan(str(f))
                    except Exception as e:
                        logging.error(f"[dnssec] Error scanning {f.name}: {e}")

            logging.info("[dnssec] Generating reports...")
            try:
                generate_reports()
            except Exception as e:
                logging.error(f"[dnssec] Report generation error: {e}")

        _collect_outputs(scanner_name)
        logging.info(f"[{scanner_name}] Complete.")

    finally:
        os.chdir(original_cwd)
        sys.path.clear()
        sys.path.extend(original_path)
        mods_to_remove = [m for m in sys.modules if m.startswith("src.") or m == "src"]
        for m in mods_to_remove:
            del sys.modules[m]


def _run_consolidation():
    """Compute the tri-domain final score from the latest scanner outputs."""
    try:
        sys.path.insert(0, str(PROJECT_ROOT))
        from src.consolidation.final_score import run_consolidation
        result = run_consolidation(CENTRAL_RESULTS, RUN_STAMP)
        if result:
            logging.info(f"[consolidation] Final score written -> {result}")
        else:
            logging.warning("[consolidation] Skipped — one or more scanner outputs missing.")
    except Exception as e:
        logging.error(f"[consolidation] Error: {e}", exc_info=True)
    finally:
        if str(PROJECT_ROOT) in sys.path:
            sys.path.remove(str(PROJECT_ROOT))


def main():
    parser = argparse.ArgumentParser(
        description="Unified Security Scanner for Norwegian HEI Thesis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--all", action="store_true", help="Run all scanners + consolidation")
    parser.add_argument("--https", action="store_true", help="Run HTTPS/TLS scanner")
    parser.add_argument("--headers", action="store_true", help="Run Security Headers scanner")
    parser.add_argument("--dnssec", action="store_true", help="Run DNSSEC scanner")
    parser.add_argument("--consolidate", action="store_true",
                        help="Compute consolidated final score from latest scanner outputs")
    parser.add_argument("--analyze-only", action="store_true",
                        help="Skip scanning, run analysis/report generation only")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging level (default: INFO)")

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    run_https   = args.all or args.https
    run_headers = args.all or args.headers
    run_dnssec  = args.all or args.dnssec
    run_consolidate = args.all or args.consolidate

    if not (run_https or run_headers or run_dnssec or run_consolidate):
        parser.print_help()
        print("\nError: specify at least one scanner (--all, --https, --headers, --dnssec, --consolidate)")
        sys.exit(1)

    CENTRAL_SOURCE.mkdir(parents=True, exist_ok=True)
    for sub in ["https", "headers", "dnssec", "consolidated"]:
        (CENTRAL_RESULTS / sub).mkdir(parents=True, exist_ok=True)
    for sub in ["https", "headers", "dnssec"]:
        (CENTRAL_CHARTS / sub).mkdir(parents=True, exist_ok=True)
        (CENTRAL_TABLES / sub).mkdir(parents=True, exist_ok=True)

    scanners_to_run = []
    if run_headers:
        scanners_to_run.append("headers")
    if run_dnssec:
        scanners_to_run.append("dnssec")
    if run_https:
        _ensure_testssl_permissions()
        scanners_to_run.append("https")

    for name in scanners_to_run:
        if not _prepare_source(name):
            logging.error(f"No input data for {name}. Place CSV files in src/source/")
            continue

        try:
            _run_scanner(name, analyze_only=args.analyze_only)
        except Exception as e:
            logging.error(f"Fatal error running {name}: {e}", exc_info=True)

    if run_consolidate:
        logging.info("Running consolidated final score calculation...")
        _run_consolidation()

    logging.info("All requested scans complete.")
    logging.info("Results:  src/results/{https,headers,dnssec,consolidated}/")
    logging.info("Charts:   src/charts/{https,headers,dnssec}/")
    logging.info("Tables:   src/tables/{https,headers,dnssec}/")


if __name__ == "__main__":
    main()
