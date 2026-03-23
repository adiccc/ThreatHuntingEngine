import pandas as pd


REQUIRED_PROCESS_COLUMNS = {
    "timestamp",
    "host",
    "username",
    "process_name",
    "parent_process",
    "command_line",
}


class ProcessLogParser:
    @staticmethod
    def parse(df: pd.DataFrame) -> list[dict]:
        missing_columns = REQUIRED_PROCESS_COLUMNS - set(df.columns)
        if missing_columns:
            raise ValueError(
                f"Missing required process log columns: {sorted(missing_columns)}"
            )

        records = df.to_dict(orient="records")
        return records