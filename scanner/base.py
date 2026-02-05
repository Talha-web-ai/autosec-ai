from abc import ABC, abstractmethod
import time

class BaseScanner(ABC):
    name = "base"

    def __init__(self, target: str):
        self.target = target

    def run(self):
        start = time.time()
        findings = self.scan()
        return {
            "scanner": self.name,
            "target": self.target,
            "findings": findings,
            "meta": {
                "execution_time": round(time.time() - start, 2)
            }
        }

    @abstractmethod
    def scan(self) -> list:
        pass
