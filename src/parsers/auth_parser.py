import pandas as pd


REQUIRED_AUTH_COLUMNS = {
    "timestamp",
    "username",
    "source_ip",
    "host",
    "event_type",
    "status",
}


class AuthenticationLogParser:
    @staticmethod
    def parse(df: pd.DataFrame) -> list[dict]:
        missing_columns = REQUIRED_AUTH_COLUMNS - set(df.columns)
        if missing_columns:
            raise ValueError(
                f"Missing required auth log columns: {sorted(missing_columns)}"
            )

        records = df.to_dict(orient="records")
        return records