from dataclasses import dataclass

@dataclass
class Attempt:
    """
    Represents one login attempt.
    """
    date: str
    timestamp: int
    username: str
    ip_address: str
    is_successful: bool