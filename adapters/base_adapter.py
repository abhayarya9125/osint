from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class DataPoint:
    source: str
    category: str
    data: dict
    url: str
    timestamp: str = field(
        default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    confidence: float = 1.0


class BaseAdapter(ABC):
    @abstractmethod
    def fetch(self, entity: str) -> list:
        pass
