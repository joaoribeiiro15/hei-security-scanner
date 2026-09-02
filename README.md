# HEI Security Scanner

Security scanning toolkit for the Master's thesis **"An Assessment of Web-Related Security in Norwegian Higher Education Institutions (HEIs)"**, developed at Østfold University College (HiØ), Norway.

Three independent scanners (HTTPS/TLS, HTTP Security Headers, DNSSEC) are unified under a single CLI entry point with a shared `src/` directory for inputs and outputs. A companion LLM risk analysis script synthesises the scan results into per-institution risk reports, using any local or remote language model.

**Author:** João Ribeiro, Østfold University College (HiØ), Norway
**Supervisors:** Pedro Filipe Cruz Pinto (IPVC) · Vikash Katta (HVL)

---

## What was built and why

The HTTPS/TLS, Security Headers, and DNSSEC scanners were originally developed by [Jackson Barreto](https://github.com/jacksonbarreto) as independent tools. This project unifies them into a single repository and CLI, adds a central data directory so the input CSV only needs to be placed once, and extends the toolset with an LLM-powered risk analysis layer that turns raw scanner output into actionable security reports, without any additional active scanning.

---

## Project Structure

```
hei-security-scanner/
├── main.py                      # Unified CLI entry point
├── gui.py                       # Graphical interface (wraps main.py)
├── launch_gui.bat               # Windows double-click launcher
├── launch_gui.sh                # Linux/macOS double-click launcher
├── llm_risk_analysis.py         # LLM risk analysis (reads scanner CSVs)
├── requirements.txt
│
├── src/                         # All inputs and outputs live here (empty in this repo)
│   ├── source/                  # Drop your input CSV here once
│   ├── consolidation/           # Cross-scanner final score
│   ├── results/
│   │   ├── https/
│   │   ├── headers/
│   │   ├── dnssec/
│   │   └── llm_analysis/        # LLM-generated reports
│   ├── charts/
│   │   ├── https/
│   │   ├── headers/
│   │   └── dnssec/
│   └── tables/
│       ├── https/
│       ├── headers/
│       └── dnssec/
│
├── scripts/                     # One-off data repair helpers
├── testssl.sh/                  # Vendored testssl.sh (not shipped, see Setup)
├── http_scanner/
├── security_headers_scanner/
└── dnssec_scanner/
```

---

## Data availability

This repository contains **source code only**. No scan results, consolidated
CSVs, LLM risk reports, error logs or institution datasets are published here.
Every data directory (`src/source/`, `src/results/`, `src/charts/`,
`src/tables/` and each scanner's `src/data/`) ships empty, kept in place by
`.gitkeep` files.

The scan outputs underpinning the thesis are not distributed with the code.
The HEI input lists are published separately in their own dataset
repositories. Place your own input CSV in `src/source/` as described below.

---

## Setup

**Requirements:** Python 3.10+, Linux or macOS (bash required by testssl.sh)

```bash
# 1. Clone
git clone <repository-url> hei-security-scanner
cd hei-security-scanner

# 1b. Vendor testssl.sh (required by the HTTPS/TLS scanner)
git clone --depth 1 https://github.com/testssl/testssl.sh.git testssl.sh

# 2. Virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Dependencies
pip install -r requirements.txt

# 4. Place your institution dataset
cp no-heis-2026.csv src/source/
```

The input CSV is automatically distributed to each scanner at runtime, no further configuration needed.

### Input CSV format

Files should follow the naming pattern `{country_code}-{name}.csv` (e.g. `no-heis-2026.csv`). Required columns:

| Column | Description |
|---|---|
| `ID` | Unique institution identifier |
| `Name` | Institution name |
| `Category` | `Public` or `Private` |
| `url` | Primary institutional website URL |
| `NUTS2` | NUTS2 region code |
| `NUTS2_Label` | NUTS2 region name |

---

## Running the scanners — GUI (recommended)

A graphical interface is available with a modern design (dark/light mode, colour-coded scanners, live log output, animated progress bar) — no terminal commands required.

### Dependencies

The GUI requires `customtkinter`, which is included in `requirements.txt` and installed with:

```bash
pip install -r requirements.txt
```

On Linux, also install the system tkinter package if not already present:

```bash
sudo apt install python3-tk   # Debian / Ubuntu / Kali
```

### Windows

Double-click `launch_gui.bat`.

### Linux (Kali, Ubuntu, Debian, …)

```bash
# Make the launcher executable (one-time)
chmod +x launch_gui.sh

# Run (double-click in the file manager, or in the terminal)
./launch_gui.sh
```

> In most Linux file managers (Thunar, Nautilus, Dolphin) you can double-click `launch_gui.sh` directly once it is executable.

### macOS

```bash
python3 gui.py
```

### What the GUI does

| Section | Description |
|---|---|
| **Input CSV** | Lists all CSV files in `src/source/` as individual checkboxes; tick one or more to scan. Use **Add File…** to import CSVs from elsewhere (copied into `src/source/` automatically). |
| **Scanners** | Colour-coded checkboxes — HTTPS/TLS (blue), Security Headers (orange), DNSSEC (purple) |
| **Options** | Analyze Only (skip scanning, regenerate reports only) and log level selector |
| **Run / Stop** | Green **Run Scan** button starts the scan; turns red **Stop** while running to terminate mid-run |
| **Progress bar** | Indeterminate animated bar under the Run button while any scan is in progress. |
| **Scan Progress panel** | Appears below the action buttons once a scan starts. Shows one labelled, colour-coded progress bar per selected scanner (Security Headers — orange, DNSSEC — purple, HTTPS/TLS — blue). Each bar advances in real time as institutions are scanned, showing `N / Total` and the current file name. Progress is derived from the unique institutions seen in the log stream divided by the total reported by the scanner at start-up. When a scanner finishes its scan phase the bar jumps through analysis (85 %), output collection (92 %), and snapshot (96 %) milestones before reaching 100 % and turning green with a ✓. The whole panel disappears when the run completes or is stopped. |
| **Log Output** | Live stream of scanner output — blue = GUI messages, yellow = WARNING, red = ERROR, green = success |
| **Open Output Folder** | Opens `src/results/` in the system file manager |
| **Dark / Light toggle** | Top-right button switches between dark and light appearance |
| **LLM Analysis tab** | Dedicated tab for running `llm_risk_analysis.py` without leaving the GUI. Configure backend, host, port, model, and input CSVs visually. Outputs are written to `src/results/llm_analysis/` and a live log stream shows progress per institution. |

Only the ticked CSV files are passed to the scanners; unticked files in `src/source/` are temporarily hidden during the run and restored immediately after.

---

## Running the scanners — CLI

```bash
# All scanners
python main.py --all

# Individual scanners
python main.py --https
python main.py --headers
python main.py --dnssec

# Any combination
python main.py --https --dnssec

# Re-run analysis only (skip scanning, use existing results)
python main.py --all --analyze-only

# Re-derive HTTPS certificate columns from stored raw JSON and regenerate reports
# (use this after updating cert validation rules, without a 4-hour re-scan)
python main.py --https --analyze-only

# Verbose output
python main.py --all --log-level DEBUG
```

All results, charts, and LaTeX tables are written to `src/` automatically.

---

## LLM Risk Analysis

`llm_risk_analysis.py` reads the scanner result CSVs, builds a consolidated security profile per institution, and sends it to a language model to produce a risk assessment with mitigation recommendations.

**Output** (written to `src/results/llm_analysis/`):
- `risk_analysis_report_<timestamp>.md`, full per-institution report with findings and recommendations
- `risk_analysis_summary_<timestamp>.csv`, one row per institution with risk level, risk score (0-100), executive summary, NIS2/GDPR notes, and a `Findings_JSON` column

### Findings_JSON column

Each row in the summary CSV contains a `Findings_JSON` column with a JSON
array of per-check findings for that institution:

```json
[
  {
    "test": "Content Security Policy (CSP)",
    "dimension": "HEADERS",
    "score_impact": -25,
    "passed": false,
    "reason": "University of Oslo's website at uio.no has a CSP header that contains 'unsafe-inline' in script-src (csp=Unsafe), negating XSS protection by allowing execution of arbitrary inline scripts.",
    "recommendation": "Remove 'unsafe-inline' from script-src on uio.no; replace with specific trusted origins or use nonce-based CSP; also set object-src 'none' and base-uri 'self'."
  }
]
```

The Thesis Platform reads this column to display institution-specific
**AI Recommendation** blocks on every failing audit card. If the LLM missed a
check, a rule-based fallback derived from the same scanner data fills the gap
automatically.

### Rule-based supplement

After the LLM generates its findings, the script runs an internal rule-based
analysis on the same scanner profile and:

1. Adds any failing checks the LLM omitted entirely.
2. Patches empty `reason` or `recommendation` fields in LLM findings with
   rule-based text, using the institution name and primary domain.

This ensures `Findings_JSON` is always complete regardless of whether the LLM
produced a full response.

### Supported backends

| Backend | When to use | API key |
|---|---|---|
| `lmstudio` | LM Studio running locally or on the network | Not required |
| `ollama` | Ollama running locally | Not required |
| `openai` | OpenAI API | Required |
| `custom` | Any OpenAI-compatible endpoint | Optional |

### LM Studio

Enable the Local Server in LM Studio, load a model, then run:

> **Context Length:** Set the loaded model's context length to at least 8 192
> tokens in LM Studio (recommended: 16 384). The script sends one institution
> per request; at 8 192 the prompt and structured JSON output fit comfortably
> for most profiles. Below 4 096 the response may be truncated.

```bash
# Same machine (default port 1234):
python llm_risk_analysis.py --backend lmstudio \
    --https-csv   src/results/https/no_https_scanner.csv \
    --headers-csv src/results/headers/sh_final_result_with_scores_unique_hei.csv \
    --dnssec-csv  src/results/dnssec/no_dnssec_scanner.csv

# Different machine on the network:
python llm_risk_analysis.py --backend lmstudio \
    --lmstudio-host 192.168.1.100 \
    --https-csv   src/results/https/no_https_scanner.csv \
    --headers-csv src/results/headers/sh_final_result_with_scores_unique_hei.csv \
    --dnssec-csv  src/results/dnssec/no_dnssec_scanner.csv

# See which models are loaded:
python llm_risk_analysis.py --backend lmstudio --lmstudio-host 192.168.1.100 --list-models

# Specify a model explicitly:
python llm_risk_analysis.py --backend lmstudio \
    --model "lmstudio-community/Meta-Llama-3.1-8B-Instruct-GGUF" \
    --https-csv ... --headers-csv ... --dnssec-csv ...
```

If `--model` is omitted the script queries the server and picks the first available model automatically.

### Ollama

```bash
python llm_risk_analysis.py --backend ollama \
    --https-csv   src/results/https/no_https_scanner.csv \
    --headers-csv src/results/headers/sh_final_result_with_scores_unique_hei.csv \
    --dnssec-csv  src/results/dnssec/no_dnssec_scanner.csv
```

Default model: `llama3.1:8b`. Pull it with `ollama pull llama3.1:8b`.

### OpenAI

```bash
python llm_risk_analysis.py --backend openai \
    --api-key sk-... --model gpt-4o \
    --https-csv ... --headers-csv ... --dnssec-csv ...
```

### Custom endpoint

```bash
python llm_risk_analysis.py --backend custom \
    --api-url http://myserver:8080/v1/chat/completions \
    --model my-model \
    --https-csv ... --headers-csv ... --dnssec-csv ...
```

### All options

| Flag | Default | Description |
|---|---|---|
| `--backend` | `lmstudio` | LLM backend to use |
| `--lmstudio-host` | `127.0.0.1` | LM Studio server hostname or IP |
| `--lmstudio-port` | `1234` | LM Studio server port |
| `--model` | auto | Model identifier (auto-selected if omitted) |
| `--list-models` | | List available models and exit |
| `--limit N` | all | Process only first N institutions |
| `--delay SECS` | `1.0` | Pause between LLM calls |
| `--timeout SECS` | `180` | HTTP timeout per request |
| `--retries N` | `3` | Retry attempts on failure |
| `--max-tokens N` | `4096` | Maximum output tokens per LLM call (enforced minimum: 2048) |
| `--output-dir` | `src/results/llm_analysis` | Output directory |

---

## Scanner Details

### HTTPS/TLS (`http_scanner/`)

Wraps [testssl.sh](https://testssl.sh/). Checks protocol versions (SSLv2–TLS 1.3), certificate validity, OCSP stapling, CAA records, Certificate Transparency, and HTTP/2 support.

**Certificate validity** is derived from the testssl.sh `serverDefaults` JSON by `src/scanner/cert_validation.py`. A certificate is valid when all of the following hold:

| Rule | Field | Condition |
|---|---|---|
| 1 | `cert_trust` | finding starts with `"Ok"` |
| 2 | `cert_expirationStatus` | severity is not `CRITICAL` (actually expired); `HIGH` (< 30 days) only fails with `strict_expiration=True` |
| 3 | `cert_commonName_wo_SNI` | severity is not `HIGH` (no name mismatch) |
| 4 | `cert_signatureAlgorithm` | does not contain SHA-1, MD5, or MD2 |
| 5 | `cert_keySize` | RSA >= 2048 bits or EC >= 256 bits |

Results use three certificate categories:

| Category | Condition |
|---|---|
| **Valid** | `valid_certificate=True`, `cert_at_risk=False` |
| **At Risk** | `valid_certificate=True`, `cert_at_risk=True` (expiry within 60 days) |
| **Invalid** | `valid_certificate=False` |

The `cert_at_risk` column is written immediately after `valid_certificate` in every result CSV.

### HTTP Security Headers (`security_headers_scanner/`)

Evaluates `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and `X-XSS-Protection` from both desktop and mobile perspectives.

### DNSSEC (`dnssec_scanner/`)

Queries the Google DNS-over-HTTPS API to check signing status, DNSKEY algorithm compliance, DS digest algorithms, and NSEC vs NSEC3 non-existence proof method.

## Timeline and snapshotting

Every invocation of `python main.py` produces a self-contained snapshot. A single run timestamp (`YYYY-MM-DDTHH-MM-SS`) is computed once and shared across all scanners launched in that invocation, so HTTPS, Headers, and DNSSEC results from the same run are grouped together and can be compared against earlier runs.

For each copied artefact, the timestamp is appended to the filename before the extension:

```
src/results/dnssec/no_dnssec_scanner__2026-04-24T08-30-15.csv
src/charts/dnssec/dnssec_adoption__2026-04-24T08-30-15.pdf
src/tables/dnssec/dnssec_adoption_in_norway_by_nuts2__2026-04-24T08-30-15.tex
```

Additionally, every CSV gets a `run_timestamp` column added at copy time, so the HEI Dashboard can plot trajectories and diff snapshots without reading filenames. This lets you drop any historical collection of result CSVs onto the dashboard and get a coherent timeline view.

Re-running `python main.py --all` never overwrites a previous snapshot; it appends a new one. To free space, delete older files from `src/results/*/` manually.

---

## Tests

```bash
# Certificate validity derivation (34 tests, no extra dependencies)
cd http_scanner
python -m unittest tests.test_cert_validation -v
```

---

## Acknowledgements

- [testssl.sh](https://github.com/drwetter/testssl.sh) by Dirk Wetter
- Original scanner implementations by [Jackson Barreto](https://github.com/jacksonbarreto)
- Barreto et al. (ICISSP 2024) for the assessment methodology
