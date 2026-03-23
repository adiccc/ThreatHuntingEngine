import pandas as pd


REQUIRED_NETWORK_COLUMNS = {
    "timestamp",
    "host",
    "source_ip",
    "destination_ip",
    "destination_port",
    "protocol",
}


class NetworkLogParser:
    @staticmethod
    def parse(df: pd.DataFrame) -> list[dict]:
        missing_columns = REQUIRED_NETWORK_COLUMNS - set(df.columns)
        if missing_columns:
            raise ValueError(
                f"Missing required network log columns: {sorted(missing_columns)}"
            )

        records = df.to_dict(orient="records")
        return records