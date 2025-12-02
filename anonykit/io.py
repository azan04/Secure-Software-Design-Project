"""I/O helpers for CSV/JSON datasets"""
from typing import Tuple
import pandas as pd

def read_csv(path: str) -> pd.DataFrame:
    return pd.read_csv(path)

def write_csv(df: pd.DataFrame, path: str) -> None:
    df.to_csv(path, index=False)
