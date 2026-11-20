from dataclasses import dataclass
import os

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    database_url: str = "sqlite:///./z3r0_platform.db"
    api_token: str | None = None
    operator_id: str = "local-operator"
    allow_loopback: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        return cls(
            database_url=os.getenv("Z3R0_DATABASE_URL", "sqlite:///./z3r0_platform.db"),
            api_token=os.getenv("Z3R0_API_TOKEN"),
            operator_id=os.getenv("Z3R0_OPERATOR_ID", "local-operator"),
            allow_loopback=os.getenv("Z3R0_ALLOW_LOOPBACK", "false").lower() in {"1", "true", "yes"},
        )
