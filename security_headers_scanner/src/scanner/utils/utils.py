# src/scanner/utils/utils.py

from __future__ import annotations

from pathlib import Path
from typing import List, Union
import logging
from urllib.parse import urlparse

import pandas as pd


# === Diretórios base (ancorados ao próprio módulo) ============================
# __file__ -> .../src/scanner/utils/utils.py
# parents[2] -> .../src
BASE_DIR = Path(__file__).resolve().parents[2]   # .../src
DATA_DIR = BASE_DIR / "data"
ERROR_DIR = DATA_DIR / "errors"
SOURCE_DIR = DATA_DIR / "source"
RESULTS_DIR = DATA_DIR / "results"
DEAD_DIR = DATA_DIR / "dead_hosts"

# Error-message substrings that mean DNS resolution itself failed. A host in
# this state cannot recover within the few minutes a retry cycle takes — DNS
# doesn't come back that fast — so retrying it just re-burns a full
# assessment pass on something guaranteed to fail again.
_DNS_DEAD_MARKERS = (
    "NameResolutionError",
    "Failed to resolve",
    "No address associated with hostname",
    "Name or service not known",
    "Temporary failure in name resolution",
    "getaddrinfo failed",
)


__all__ = [
    "BASE_DIR",
    "DATA_DIR",
    "ERROR_DIR",
    "SOURCE_DIR",
    "RESULTS_DIR",
    "save",
    "check_error_files",
    "reset_error_files",
    "list_error_files",
    "sanitize_url",
    "normalize_domain",
]


# === Normalização de URLs/Domínios ===========================================

def sanitize_url(url: str) -> str:
    """
    Recebe um URL ou domínio e devolve apenas o host limpo
    (sem esquema, path, query e porto), preservando o subdomínio original
    tal como consta no CSV (ex.: 'www.hiof.no' mantém-se 'www.hiof.no').
    Ex.: 'https://www.Example.com:443/path' -> 'www.example.com'
         'https://Example.com/path'         -> 'example.com'
    """
    if not isinstance(url, str):
        return ""
    u = url.strip()
    parsed = urlparse(u if "://" in u else f"http://{u}")
    host = (parsed.hostname or "").strip().lower()
    return host


def normalize_domain(url: str) -> str:
    """
    Extrai o host de um URL para comparação de domínios.
    Mantém o mesmo comportamento que sanitize_url.
    """
    return sanitize_url(url)


# === Helpers =================================================================

def list_error_files() -> List[Path]:
    """
    Lista os CSVs existentes na pasta de erros.
    Não lança exceção se a pasta não existir.
    """
    return list(ERROR_DIR.glob("*.csv")) if ERROR_DIR.exists() else []


# === API utilizada no restante projeto =======================================

def check_error_files() -> bool:
    """
    Devolve True se existirem CSVs na pasta de erros; False caso contrário.
    Resiliente quando a pasta não existe.
    """
    return any(list_error_files())


def reset_error_files() -> bool:
    """
    Prepara nova ronda:
      - Garante que a pasta SOURCE existe.
      - Separa erros por tipo: falhas de DNS (permanentes, não recuperam em
        minutos) vão para DEAD_DIR e nunca mais são re-tentadas; o resto
        (timeouts, 5xx, TLS transitório) volta para SOURCE para nova ronda.
      - Não apaga os CSVs base de SOURCE (ex.: NO-Universities.csv).
      - Cada ficheiro de erro é sempre consumido (nunca fica em ERROR_DIR),
        para não sobreviver a este processo e contaminar runs futuros.
    """
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)

    if not ERROR_DIR.exists():
        return True

    moved_any = False
    for p in list_error_files():
        try:
            df = pd.read_csv(p)
            if "error" in df.columns:
                is_dead = df["error"].astype(str).str.contains(
                    "|".join(_DNS_DEAD_MARKERS), na=False, regex=True,
                )
            else:
                is_dead = pd.Series(False, index=df.index)
            dead_df, retry_df = df[is_dead], df[~is_dead]

            if not dead_df.empty:
                DEAD_DIR.mkdir(parents=True, exist_ok=True)
                dead_target = DEAD_DIR / p.name
                if dead_target.exists():
                    dead_df = pd.concat([pd.read_csv(dead_target), dead_df], ignore_index=True)
                dead_df.to_csv(dead_target, index=False)
                logging.info(
                    "%d host(s) with unrecoverable DNS failures archived to %s (not retried).",
                    len(dead_df), dead_target,
                )

            if not retry_df.empty:
                target = SOURCE_DIR / p.name
                if target.exists():
                    target.unlink()
                retry_df.drop(columns=["error"], errors="ignore").to_csv(target, index=False)
                moved_any = True

            p.unlink()
        except FileNotFoundError:
            pass
        except Exception as e:
            logging.error("Falha ao mover %s para source: %s", p, e)

    if moved_any:
        logging.info("Erros anteriores colocados em %s para nova tentativa.", SOURCE_DIR)

    return True


def save(
    dataframe: Union[pd.DataFrame, list[dict]],
    country_code: str,
    platform: str | None = None,
    error: bool = False,
) -> Path:
    """
    Guarda resultados (ou erros) num CSV agregado por país e, opcionalmente, plataforma.
    - Cria a pasta de destino se necessário.
    - Faz append se o ficheiro já existir (sem header), caso contrário escreve com header.

    Returns:
        Path para o ficheiro escrito/atualizado.
    """
    output_dir = ERROR_DIR if error else RESULTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    suffix_platform = f"_{platform}" if platform else ""
    suffix_error = "_errors" if error else ""
    filename = f"{country_code}{suffix_platform}{suffix_error}.csv"
    output_file = output_dir / filename

    df = dataframe if isinstance(dataframe, pd.DataFrame) else pd.DataFrame(dataframe)

    if df.empty:
        logging.info("Sem linhas para guardar para %s; a ignorar escrita em %s", country_code, output_file)
        return output_file

    if output_file.exists():
        df.to_csv(output_file, mode="a", header=False, index=False)
    else:
        df.to_csv(output_file, index=False)

    return output_file
