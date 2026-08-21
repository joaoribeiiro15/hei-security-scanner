"""
Consolidated Final Score
========================
Implements the tri-domain scoring formula from Table I of the paper:

    S_final = HTTPS_domain × 0.80 + DNSSEC × 0.20

where:
    HTTPS_domain = TLS_score × 0.80 + SH_score × 0.20

Simplified weights per institution:
    TLS_score   × 0.64
    SH_score    × 0.16
    DNSSEC_score × 0.20

Grade thresholds (paper Table I):
    A [80–100], B [65–79], C [50–64], D [35–49], E [20–34], F [0–19]

Inputs (from src/results/*/latest/):
    no_https_scanner.csv                      → column: final_score
    sh_final_result_with_scores_unique_hei.csv → column: final_score
    no_dnssec_scanner.csv                     → column: score

Output:
    src/results/consolidated/latest/final_consolidated_result.csv
"""

import logging
import shutil
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)

# ── Column names in each source CSV ──────────────────────────────────────────
_HTTPS_SCORE_COL   = "final_score"
_HEADERS_SCORE_COL = "final_score"
_DNSSEC_SCORE_COL  = "score"

# ── Metadata columns carried through from the source CSVs ────────────────────
_META_COLS = [
    "ID", "country", "Name", "Category", "Institution_Category_Standardized",
    "Member_of_European_University_alliance", "url",
    "NUTS2", "NUTS2_Label", "NUTS3", "NUTS3_Label",
]

# ── Grade thresholds (paper Table I) ─────────────────────────────────────────
_BINS   = [0, 20, 35, 50, 65, 80, 101]
_LABELS = ["F", "E", "D", "C", "B", "A"]


def _normalise_df(df: pd.DataFrame, country: str | None = None) -> pd.DataFrame:
    """Normalise column names across the three source schemas so all DataFrames
    share the same canonical column names before merging.

    Schema differences:
      NO  → ID, url, NUTS2_Label, NUTS3_Label
      DE/FR/IT → ETER_ID, Url, NUTS2_Label_2016/2021, NUTS3_Label_2016/2021
      PL  → Id, Url/url, Region (no NUTS2_Label)
    """
    df = df.copy()
    # Canonical institution ID: prefer ETER_ID > Id > ID.
    # Also fill NaN cells in an existing ID column from ETER_ID/Id — the
    # headers sh file carries an ID column that is populated only for Norway
    # (numeric) while DE/FR/IT rows have NaN there and use ETER_ID instead.
    if "ID" not in df.columns:
        if "ETER_ID" in df.columns:
            df["ID"] = df["ETER_ID"]
        elif "Id" in df.columns:
            df["ID"] = df["Id"]
    else:
        # Patch NaN / empty-string IDs from alternative columns
        nan_mask = df["ID"].isna() | (df["ID"].astype(str).str.strip().isin(["nan", ""]))
        if nan_mask.any():
            for alt in ("ETER_ID", "Id"):
                if alt in df.columns:
                    df.loc[nan_mask, "ID"] = df.loc[nan_mask, alt]
                    nan_mask = df["ID"].isna() | (df["ID"].astype(str).str.strip().isin(["nan", ""]))
                    if not nan_mask.any():
                        break

    # Normalise float-formatted integer IDs produced by pandas when reading
    # CSVs where the Id column is numeric: "1.0" → "1", "347.0" → "347".
    # This ensures PL POLON IDs match across HTTPS, DNSSEC, and headers files.
    if "ID" in df.columns:
        df["ID"] = (
            df["ID"].astype(str)
            .str.strip()
            .str.replace(r"\.0$", "", regex=True)
        )

    # Make numeric institution IDs globally unique by prepending country code.
    # Norway (NO) and Poland (PL) both use plain integer IDs that would collide
    # when data from all countries is concatenated before deduplication.
    # ETER IDs used by DE/FR/IT already embed a country prefix ("D-XXXX", etc.)
    # and are left unchanged.
    if "ID" in df.columns:
        numeric_mask = df["ID"].astype(str).str.match(r"^\d+$", na=False)
        if numeric_mask.any():
            if "country" in df.columns:
                # Multi-country file (e.g. headers sh): apply prefix per row
                df.loc[numeric_mask, "ID"] = (
                    df.loc[numeric_mask, "country"].str.upper().fillna("XX")
                    + "-"
                    + df.loc[numeric_mask, "ID"]
                )
            elif country:
                # Single-country file: apply uniform country prefix
                df.loc[numeric_mask, "ID"] = (
                    country.upper() + "-" + df.loc[numeric_mask, "ID"]
                )
    # url
    if "url" not in df.columns and "Url" in df.columns:
        df["url"] = df["Url"]
    # NUTS2_Label
    if "NUTS2_Label" not in df.columns:
        for alt in ("NUTS2_Label_2016", "NUTS2_Label_2021", "Region"):
            if alt in df.columns:
                df["NUTS2_Label"] = df[alt]
                break
    # NUTS3_Label
    if "NUTS3_Label" not in df.columns:
        for alt in ("NUTS3_Label_2016", "NUTS3_Label_2021"):
            if alt in df.columns:
                df["NUTS3_Label"] = df[alt]
                break
    # country: inject from filename prefix if not already present
    if "country" not in df.columns and country:
        df["country"] = country.upper()
    return df


def _grade(score: float) -> str:
    if pd.isna(score):
        return "N/A"
    if score >= 80:
        return "A"
    if score >= 65:
        return "B"
    if score >= 50:
        return "C"
    if score >= 35:
        return "D"
    if score >= 20:
        return "E"
    return "F"


def _load_latest(results_root: Path, scanner: str, filename: str) -> pd.DataFrame | None:
    """Load a CSV from src/results/<scanner>/latest/<filename> and normalise columns."""
    path = results_root / scanner / "latest" / filename
    if not path.exists():
        logger.warning(f"[consolidation] File not found: {path}")
        return None
    df = pd.read_csv(path, dtype=str)
    logger.info(f"[consolidation] Loaded {len(df)} rows from {path.name}")
    return _normalise_df(df)


def _load_all_scanner_latest(results_root: Path, scanner: str, pattern: str) -> pd.DataFrame | None:
    """Load and concatenate all CSVs matching glob pattern from src/results/<scanner>/latest/.

    Used for per-country scanner outputs (e.g. de_https_scanner.csv, pl_dnssec_scanner.csv)
    so that consolidation works across all countries, not just Norway.
    Country code is inferred from the filename prefix (first two characters).
    """
    latest_dir = results_root / scanner / "latest"
    if not latest_dir.exists():
        logger.warning(f"[consolidation] Directory not found: {latest_dir}")
        return None
    files = sorted(latest_dir.glob(pattern))
    if not files:
        logger.warning(f"[consolidation] No files matching '{pattern}' in {latest_dir}")
        return None
    frames = []
    for f in files:
        try:
            df = pd.read_csv(f, dtype=str)
            # Country from filename prefix: "de_https_scanner.csv" → "DE"
            cc = f.name[:2].upper() if len(f.name) >= 2 else None
            df = _normalise_df(df, country=cc)
            logger.info(f"[consolidation] Loaded {len(df)} rows from {f.name} (country={cc})")
            frames.append(df)
        except Exception as e:
            logger.warning(f"[consolidation] Failed to read {f}: {e}")
    if not frames:
        return None
    combined = pd.concat(frames, ignore_index=True)
    logger.info(f"[consolidation] Combined {len(combined)} rows from {len(frames)} file(s) ({scanner})")
    return combined


def _dedup_scanner_scores(df: pd.DataFrame, score_col: str) -> pd.DataFrame:
    """Keep one row per institution ID for a scanner result DataFrame.

    Prefers rows with a valid (finite) score.  Among equally valid rows,
    keeps the one with the latest assessment_datetime.  This handles cases
    where the scanner was run multiple times without clearing old results,
    producing duplicate rows per institution.
    """
    if df is None or df.empty or "ID" not in df.columns:
        return df
    df = df.copy()
    numeric_score = pd.to_numeric(df[score_col], errors="coerce") if score_col in df.columns else pd.Series(float("nan"), index=df.index)
    df["_valid"] = numeric_score.notna().astype(int)
    df["_dt"] = df["assessment_datetime"] if "assessment_datetime" in df.columns else ""
    df = df.sort_values(["_valid", "_dt"], ascending=[False, False])
    df = df.drop_duplicates(subset=["ID"], keep="first")
    df = df.drop(columns=["_valid", "_dt"])
    return df


def _coerce_score(df: pd.DataFrame, col: str) -> pd.Series:
    return pd.to_numeric(df[col], errors="coerce") if col in df.columns else pd.Series(dtype=float)


def run_consolidation(results_root: Path, run_stamp: str) -> Path | None:
    """
    Read the latest scanner outputs, compute the consolidated final score,
    and write the result CSV.  Returns the path to the output file, or None
    on failure.
    """
    # ── Load source files ─────────────────────────────────────────────────────
    # https + dnssec: one file per country (de_, fr_, it_, no_, pl_, …)
    df_https  = _load_all_scanner_latest(results_root, "https",   "*_https_scanner.csv")
    # headers: single aggregated file produced by score_analyze() across all countries
    df_sh     = _load_latest(results_root, "headers", "sh_final_result_with_scores_unique_hei.csv")
    df_dnssec = _load_all_scanner_latest(results_root, "dnssec",  "*_dnssec_scanner.csv")

    if df_https is None and df_sh is None and df_dnssec is None:
        logger.error("[consolidation] No scanner outputs found — aborting.")
        return None

    # ── Build a master institution list keyed by ID ───────────────────────────
    frames = [df for df in [df_https, df_sh, df_dnssec] if df is not None]
    meta_df = pd.concat(
        [f[[c for c in _META_COLS if c in f.columns]] for f in frames],
        ignore_index=True,
    ).drop_duplicates(subset=["ID"])

    df = meta_df.copy()

    # ── Merge individual scores ───────────────────────────────────────────────
    # Deduplicate each score table before merging to prevent row explosion when
    # the same institution was scanned multiple times (e.g. multiple sessions).
    if df_https is not None:
        https_scores = _dedup_scanner_scores(df_https, _HTTPS_SCORE_COL)[["ID", _HTTPS_SCORE_COL, "grade"]].copy()
        https_scores.rename(columns={_HTTPS_SCORE_COL: "tls_score", "grade": "tls_grade"}, inplace=True)
        df = df.merge(https_scores, on="ID", how="left")
    else:
        df["tls_score"] = pd.NA
        df["tls_grade"] = pd.NA

    if df_sh is not None:
        sh_scores = _dedup_scanner_scores(df_sh, _HEADERS_SCORE_COL)[["ID", _HEADERS_SCORE_COL, "grade"]].copy()
        sh_scores.rename(columns={_HEADERS_SCORE_COL: "sh_score", "grade": "sh_grade"}, inplace=True)
        df = df.merge(sh_scores, on="ID", how="left")
    else:
        df["sh_score"] = pd.NA
        df["sh_grade"] = pd.NA

    if df_dnssec is not None:
        dnssec_scores = _dedup_scanner_scores(df_dnssec, _DNSSEC_SCORE_COL)[["ID", _DNSSEC_SCORE_COL, "grade"]].copy()
        dnssec_scores.rename(columns={_DNSSEC_SCORE_COL: "dnssec_score", "grade": "dnssec_grade"}, inplace=True)
        df = df.merge(dnssec_scores, on="ID", how="left")
    else:
        df["dnssec_score"] = pd.NA
        df["dnssec_grade"] = pd.NA

    # ── Coerce scores to float ────────────────────────────────────────────────
    df["tls_score"]    = pd.to_numeric(df["tls_score"],    errors="coerce")
    df["sh_score"]     = pd.to_numeric(df["sh_score"],     errors="coerce")
    df["dnssec_score"] = pd.to_numeric(df["dnssec_score"], errors="coerce")

    # ── Compute HTTPS domain score (TLS 80% + SH 20%) ────────────────────────
    # Requires BOTH TLS and SH scores to be present. Falling back to whichever
    # one is available at full weight let institutions with a missing domain
    # (e.g. a scan that timed out and never produced a scored row) inherit a
    # misleadingly high score from the one domain that did complete.
    def https_domain(row):
        ht, sh = row["tls_score"], row["sh_score"]
        if pd.notna(ht) and pd.notna(sh):
            return ht * 0.8 + sh * 0.2
        return float("nan")

    df["https_domain_score"] = df.apply(https_domain, axis=1).round(2)

    # ── Compute final consolidated score (HTTPS 80% + DNSSEC 20%) ────────────
    # Same principle: requires the HTTPS domain AND DNSSEC to both be present.
    # An institution missing an entire domain (TLS, Headers, or DNSSEC never
    # produced a scored row) gets no final score/grade — it's an incomplete
    # assessment, not a low or high one.
    def final_score(row):
        hd, ds = row["https_domain_score"], row["dnssec_score"]
        if pd.notna(hd) and pd.notna(ds):
            return hd * 0.8 + ds * 0.2
        return float("nan")

    df["final_score"] = df.apply(final_score, axis=1).round(2)
    df["final_grade"] = df["final_score"].apply(
        lambda s: "Incomplete" if pd.isna(s) else _grade(s)
    )
    df["run_timestamp"] = run_stamp

    # ── Column order ──────────────────────────────────────────────────────────
    ordered_cols = (
        [c for c in _META_COLS if c in df.columns]
        + ["tls_score", "tls_grade", "sh_score", "sh_grade",
           "dnssec_score", "dnssec_grade",
           "https_domain_score", "final_score", "final_grade", "run_timestamp"]
    )
    df = df[[c for c in ordered_cols if c in df.columns]]

    # ── Write output ──────────────────────────────────────────────────────────
    out_dir_stamped = results_root / "consolidated"
    out_dir_latest  = out_dir_stamped / "latest"
    out_dir_latest.mkdir(parents=True, exist_ok=True)
    out_dir_stamped.mkdir(parents=True, exist_ok=True)

    stamped_name = f"final_consolidated_result__{run_stamp}.csv"
    latest_name  = "final_consolidated_result.csv"

    stamped_path = out_dir_stamped / stamped_name
    latest_path  = out_dir_latest  / latest_name

    df.to_csv(stamped_path, index=False, encoding="utf-8")
    shutil.copy2(stamped_path, latest_path)

    n_complete = df[["tls_score", "sh_score", "dnssec_score"]].notna().all(axis=1).sum()
    logger.info(
        f"[consolidation] Done — {len(df)} institutions, {n_complete} with all three scores.\n"
        f"  Stamped : {stamped_path}\n"
        f"  Latest  : {latest_path}"
    )
    return latest_path
