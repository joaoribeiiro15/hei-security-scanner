import pandas as pd


def remove_empty_columns(dataframe: pd.DataFrame, ignored_columns=None):
    if ignored_columns is None:
        ignored_columns = ["NUTS2"]
    empty_columns = [c for c in [col for col in dataframe.columns if col not in ignored_columns] if
                     dataframe[c].sum() == 0]
    dataframe.drop(columns=empty_columns, inplace=True)
