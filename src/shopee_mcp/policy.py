from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Policy:
    context: str
    modules: frozenset[str] | None = None
    endpoints: frozenset[str] | None = None
    allow_writes: frozenset[str] = frozenset()

    def __post_init__(self):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.context):
            raise ValueError("Context must be a nonsecret ASCII alias")

    def permits(self, endpoint):
        return (endpoint["review_status"] == "verified"
                and endpoint["implementation"] in {"implemented", "partial"}
                and endpoint["exposure"] in {"enabled", "opt_in"}
                and (self.modules is None or endpoint["module"] in self.modules)
                and (self.endpoints is None or endpoint["api_name"] in self.endpoints)
                and ((endpoint["effects"] == "read" and endpoint["exposure"] == "enabled")
                     or "*" in self.allow_writes or endpoint["api_name"] in self.allow_writes))
