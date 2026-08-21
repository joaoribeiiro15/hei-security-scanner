import os

from src.analyzer.calculator.calc import calculate_final_scores
from src.analyzer.utils.utils import load_results  # (opcional; remove se não for usado)

from pathlib import Path
import logging
import pandas as pd

# usa os mesmos diretórios do utils
from src.scanner.utils.utils import RESULTS_DIR

# Diretório de saída para a análise (ex.: src/data/results/analysis)
OUTPUT_DIR = RESULTS_DIR / "analysis"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Nome base dos ficheiros de saída
FILENAME_OUTPUT = "sh_final_result_with_scores"


def _load_results_as_dataframe(input_directory: Path) -> pd.DataFrame:
    """
    Lê todos os CSVs de resultados para um único DataFrame.
    Se não houver CSVs, devolve DataFrame vazio (não lista).
    """
    files = list(Path(input_directory).glob("*.csv"))
    if not files:
        logging.warning(
            "No CSV files found in '%s'. Please ensure the files are in the correct directory.",
            input_directory,
        )
        return pd.DataFrame()

    frames = []
    for f in files:
        try:
            df = pd.read_csv(f)
            # POLON files carry a purely-numeric "Id" column. Countries whose
            # files use "ETER_ID" instead don't have that column at all, so
            # once every frame is concatenated below, pandas fills those rows'
            # "Id" with NaN — which silently promotes the WHOLE column to
            # float64, turning e.g. "120" into "120.0" for every institution,
            # not just the ones actually missing a value. Casting to string
            # here, while the column is still float-free, locks in the clean
            # integer text before that promotion can happen.
            for _idcol in ("Id", "ID", "ETER_ID"):
                if _idcol in df.columns:
                    df[_idcol] = df[_idcol].astype(str)
            # Inject country from the result filename (e.g. "PLdesktop.csv" → "PL")
            # so that downstream analysis can group by country regardless of whether
            # the input dataset included a country column.
            if "country" not in df.columns:
                df = df.copy()
                df["country"] = f.stem[:2].upper()
            frames.append(df)
        except Exception as e:
            logging.error("Failed to read %s: %s", f, e)

    if not frames:
        return pd.DataFrame()

    return pd.concat(frames, ignore_index=True)


def score_analyze():
    consolidated_data = _load_results_as_dataframe(RESULTS_DIR)

    if consolidated_data.empty:
        logging.warning("Found 0 result files to analyze. Skipping score analysis.")
        return

    # Normalise institution ID: ETER schema → ETER_ID, NO source → ID, PL/POLON → Id.
    # Convert to object dtype before assignment — ETER_ID may be StringDtype which
    # rejects numeric values from ID/Id columns.
    if "ETER_ID" not in consolidated_data.columns:
        consolidated_data["ETER_ID"] = None
    consolidated_data["ETER_ID"] = consolidated_data["ETER_ID"].astype(object)
    for _alt in ["ID", "Id"]:
        if _alt in consolidated_data.columns:
            # A row only qualifies for this fallback if ETER_ID is still
            # genuinely missing AND _alt actually has a value for it. Without
            # the second condition, rows lacking both columns (e.g. Polish
            # rows during the "ID" pass) get filled with str(NaN) == "nan" —
            # a non-null string — which then blocks the *next* pass ("Id")
            # from ever supplying the real value, since .isna() no longer
            # sees them as needing one.
            _mask = consolidated_data["ETER_ID"].isna() & consolidated_data[_alt].notna()
            if _mask.any():
                consolidated_data.loc[_mask, "ETER_ID"] = consolidated_data.loc[_mask, _alt].astype(str)

    final_scores = calculate_final_scores(consolidated_data)

    # Guardar resultados consolidados
    final_scores.to_csv(OUTPUT_DIR / f"{FILENAME_OUTPUT}.csv", index=False)

    # Um registo por ETER_ID (ex.: o pior score por instituição).
    # groupby(...).idxmin() levanta "'[nan] not in index'" sempre que todas
    # as linhas de uma instituição têm final_score em falta — idxmin() de um
    # grupo totalmente NaN devolve NaN, que o .loc[] depois não consegue
    # resolver. Ordena com os scores válidos primeiro: instituições com pelo
    # menos um score usável mantêm o mais baixo; instituições sem nenhum
    # mantêm à mesma uma linha, em vez de serem descartadas silenciosamente.
    final_scores["_valid"] = final_scores["final_score"].notna().astype(int)
    already_to_analyze = (
        final_scores.sort_values(["_valid", "final_score"], ascending=[False, True])
        .drop_duplicates(subset="ETER_ID", keep="first")
        .drop(columns=["_valid"])
    )
    final_scores.drop(columns=["_valid"], inplace=True)
    already_to_analyze.to_csv(
        OUTPUT_DIR / f"{FILENAME_OUTPUT}_unique_hei.csv",
        index=False,
    )

    print("Final scores saved.")


if __name__ == "__main__":
    score_analyze()
