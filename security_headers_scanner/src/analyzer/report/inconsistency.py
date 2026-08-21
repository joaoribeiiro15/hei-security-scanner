import os
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

from src.analyzer.report.header_adoption import get_country
from src.scanner.utils.utils import RESULTS_DIR
from src.config import (
    COL_REDIRECT_INCONSISTENCY_BETWEEN_PLATFORMS,
    COL_HEADER_INCONSISTENCY_BETWEEN_PLATFORMS,
    COL_CRITICAL_HEADER_INCONSISTENCY_BETWEEN_PLATFORMS,
)

# Diretórios coerentes com score_analyzer.py
OUTPUT_DIR = RESULTS_DIR / "analysis"
TABLE_DIRECTORY = OUTPUT_DIR / "tables"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
TABLE_DIRECTORY.mkdir(parents=True, exist_ok=True)

# Ficheiro de entrada vindo do score_analyzer.py
RESULT_FILE_PATH = OUTPUT_DIR / "sh_final_result_with_scores_unique_hei.csv"

# Apenas Noruega
FILTER_COUNTRY = "NO"

inconsistency_columns = [
    COL_CRITICAL_HEADER_INCONSISTENCY_BETWEEN_PLATFORMS,
    COL_HEADER_INCONSISTENCY_BETWEEN_PLATFORMS,
    COL_REDIRECT_INCONSISTENCY_BETWEEN_PLATFORMS,
]


# ---------- Normalização para datasets mínimos (University Name + url) ----------
def _tld_to_country_code(host: str) -> str:
    if not host:
        return "UNK"
    last = host.rsplit(".", 1)[-1].lower()
    mapping = {"no": "NO", "de": "DE", "fr": "FR", "it": "IT"}
    return mapping.get(last, "UNK")


def _extract_host(url: str) -> str:
    if not isinstance(url, str):
        return ""
    u = url.strip()
    if not u:
        return ""
    parsed = urlparse(u if "://" in u else f"http://{u}")
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def normalize_input(df: pd.DataFrame) -> pd.DataFrame:
    """
    Garante colunas necessárias quando só existem 'University Name' e 'url'.
    """
    df = df.copy()

    # ETER_ID
    if "ETER_ID" not in df.columns:
        if "University Name" in df.columns:
            df["ETER_ID"] = df["University Name"]
        else:
            df["ETER_ID"] = df.index.astype(str)

    # country (a partir de final_url ou url)
    if "country" not in df.columns:
        candidate_url_col = "final_url" if "final_url" in df.columns else ("url" if "url" in df.columns else None)
        if candidate_url_col:
            hosts = df[candidate_url_col].apply(_extract_host)
            df["country"] = hosts.apply(_tld_to_country_code)
        else:
            df["country"] = "UNK"

    # NUTS2 + Categoria, se faltarem
    if "NUTS2_Label" not in df.columns:
        df["NUTS2_Label"] = "N/A"
    if "Category" not in df.columns:
        df["Category"] = "unknown"
    else:
        df["Category"] = df["Category"].str.lower()

    # Flags de inconsistência (default 0)
    for col in inconsistency_columns:
        if col not in df.columns:
            df[col] = 0

    return df
# -----------------------------------------------------------------------------


def prepare_inconsistency_stats(dataframe: pd.DataFrame) -> pd.DataFrame:
    dataframe = normalize_input(dataframe)

    # Foco exclusivo na Noruega
    dataframe = dataframe[dataframe["country"] == FILTER_COUNTRY].copy()

    if dataframe.empty:
        # devolve DataFrame com colunas esperadas para evitar quebras a jusante
        cols = [
            "country", "NUTS2_Label", "Category", "ETER_ID",
            *inconsistency_columns
        ]
        return pd.DataFrame(columns=cols)

    _stats_by_nuts = dataframe.groupby(["country", "NUTS2_Label"]).agg(
        total_schools_nuts=("ETER_ID", "count"),
        **{f"{col}_schools_nuts": (col, "sum") for col in inconsistency_columns},
    ).reset_index()

    _stats_by_country = dataframe.groupby("country").agg(
        total_schools_country=("ETER_ID", "count"),
        **{f"{col}_schools_country": (col, "sum") for col in inconsistency_columns},
    ).reset_index()

    _stats_by_nuts_category = dataframe.groupby(["country", "NUTS2_Label", "Category"]).agg(
        total_schools_nuts_category=("ETER_ID", "count"),
        **{f"{col}_schools_nuts_category": (col, "sum") for col in inconsistency_columns},
    ).reset_index()

    consolidated_stats = _stats_by_nuts.merge(_stats_by_country, on="country", how="left")
    consolidated_stats = consolidated_stats.merge(
        _stats_by_nuts_category, on=["country", "NUTS2_Label"], how="left"
    )

    for col in inconsistency_columns:
        consolidated_stats[f"{col}_percent_nuts"] = (
            (consolidated_stats[f"{col}_schools_nuts"] / consolidated_stats["total_schools_nuts"]) * 100
        ).round(2)

        consolidated_stats[f"{col}_percent_country"] = (
            (consolidated_stats[f"{col}_schools_country"] / consolidated_stats["total_schools_country"]) * 100
        ).round(2)

        consolidated_stats[f"{col}_percent_nuts_category"] = (
            (consolidated_stats[f"{col}_schools_nuts_category"] / consolidated_stats["total_schools_nuts_category"])
            * 100
        ).round(2)

    consolidated_stats.rename(columns={"NUTS2_Label": "nuts"}, inplace=True)
    return consolidated_stats


def latex_table(dataframe, level, title, label, country_filter=None, category_filter=None):
    if level == "nuts":
        if country_filter:
            dataframe = dataframe[dataframe["country"] == country_filter]
        columns_to_display = ["nuts"] + [f"{col}_percent_nuts" for col in inconsistency_columns]
        rename_map = {
            "nuts": "NUTS2",
            **{
                f"{col}_percent_nuts": col.replace("_", " ").title().replace(" Between Platforms", "")
                for col in inconsistency_columns
            },
        }
    elif level == "country":
        dataframe = dataframe.drop_duplicates(subset=["country"])
        columns_to_display = ["country"] + [f"{col}_percent_country" for col in inconsistency_columns]
        rename_map = {
            "country": "Country",
            **{
                f"{col}_percent_country": col.replace("_", " ").title().replace(" Between Platforms", "")
                for col in inconsistency_columns
            },
        }
    elif level == "nuts_category":
        if country_filter:
            dataframe = dataframe[dataframe["country"] == country_filter]
        if category_filter:
            dataframe = dataframe[dataframe["Category"] == category_filter]

        columns_to_display = ["nuts", "Category"] + [
            f"{col}_percent_nuts_category" for col in inconsistency_columns
        ]
        rename_map = {
            "nuts": "NUTS2",
            "Category": "Institution Type",
            **{
                f"{col}_percent_nuts_category": col.replace("_", " ").title().replace(" Between Platforms", "")
                for col in inconsistency_columns
            },
        }
    else:
        raise ValueError("Invalid level. Use 'nuts' or 'country'.")

    dataframe = dataframe[columns_to_display].rename(columns=rename_map)
    dataframe = dataframe.sort_values(
        by=[col.replace("_", " ").title().replace(" Between Platforms", "") for col in inconsistency_columns],
        ascending=False,
        kind="mergesort",
    )

    if level in {"nuts", "nuts_category"}:
        dataframe = dataframe.drop_duplicates(subset=["NUTS2"], keep="first")
    if level == "nuts_category":
        dataframe = dataframe.drop(columns=["Institution Type"])

    column_headers = " & ".join(f"\\makecell{{{col.replace(' Inconsistency','')}}}" for col in dataframe.columns)

    table_rows = "\n".join(
        f"            {row[0] if level != 'country' else get_country(row[0])} & "
        + " & ".join(
            "-"
            if pd.isna(value) or value == 0
            else f"{int(value)}"
            if isinstance(value, (float, int)) and value == int(value)
            else f"{value:.2f}"
            if isinstance(value, float)
            else str(value)
            for value in row[1:]
        )
        + " \\\\"
        for row in dataframe.itertuples(index=False, name=None)
    )

    latex_table = f"""
\\begin{{table}}[H]
    \\centering
    \\caption{{{title}}}
    \\label{{tab:{label}}}
    \\rowcolors{{2}}{{white}}{{gray!15}}
    \\begin{{tabularx}}{{\\textwidth}}{{X{'c' * len(dataframe.columns)}}}
        \\toprule
        {column_headers} \\\\
        \\midrule
{table_rows}
        \\bottomrule
    \\end{{tabularx}}
\\end{{table}}
    """
    return latex_table


def generate_latex_table_for_norway(dataframe):
    # Só Noruega
    country = FILTER_COUNTRY

    nuts2_table = latex_table(
        dataframe,
        "nuts",
        f"Security Headers Inconsistencies in {get_country(country)} by NUTS2 (\\%)",
        f"nuts2_inconsistencies_{country}",
        country,
    )
    with open(TABLE_DIRECTORY / f"sh_inconsistencies_in_{country}_by_nuts2.tex", "w", encoding="utf-8") as tex_file:
        tex_file.write(nuts2_table)

    nuts2_table_public = latex_table(
        dataframe,
        "nuts_category",
        f"Security Headers Inconsistencies at Public HEIs in {get_country(country)} by NUTS2 (\\%)",
        f"inconsistencies_in_{country}_by_nuts2_public",
        country,
        "public",
    )
    with open(TABLE_DIRECTORY / f"sh_inconsistencies_in_{country}_by_nuts2_public.tex", "w", encoding="utf-8") as f:
        f.write(nuts2_table_public)

    nuts2_table_private = latex_table(
        dataframe,
        "nuts_category",
        f"Security Headers Inconsistencies at Private HEIs in {get_country(country)} by NUTS2 (\\%)",
        f"inconsistencies_in_{country}_by_nuts2_private",
        country,
        "private",
    )
    with open(TABLE_DIRECTORY / f"sh_inconsistencies_in_{country}_by_nuts2_private.tex", "w", encoding="utf-8") as f:
        f.write(nuts2_table_private)

    country_table = latex_table(
        dataframe, "country", f"Security Headers Inconsistencies in {get_country(country)} (\\%)", "country_inconsistencies"
    )
    with open(TABLE_DIRECTORY / "sh_inconsistencies_by_country.tex", "w", encoding="utf-8") as f:
        f.write(country_table)


def make_inconsistencies():
    df = pd.read_csv(RESULT_FILE_PATH)
    stats = prepare_inconsistency_stats(df)

    # Se, após filtrar, não houver linhas (ex.: só tens outros países), não faz nada
    if stats.empty:
        print("No Norwegian rows to report; skipping inconsistencies tables.")
        return

    generate_latex_table_for_norway(stats)


if __name__ == "__main__":
    pd.set_option("display.max_columns", None)
    pd.set_option("display.width", None)
    make_inconsistencies()
