from __future__ import annotations

from abc import ABC, abstractmethod

class Notifier(ABC):
    @abstractmethod
    def send(self, message: str) -> bool:
        raise NotImplementedError

class EmailNotifier(Notifier):
    def __init__(self, reachable: bool = True) -> None:
        self.reachable = reachable
        self.sent: list[str] = []

    def send(self, message: str) -> bool:
        if not self.reachable:
            return False
        self.sent.append(message)
        return True

class SmsNotifier(Notifier):
    def __init__(self, reachable: bool = True) -> None:
        self.reachable = reachable
        self.sent_chunks: list[str] = []

    def send(self, message: str) -> bool:
        if not self.reachable:
            return False

        chunks = [message[i:i + 160] for i in range(0, len(message), 160)] or [""]
        self.sent_chunks.extend(chunks)
        return True

class WebhookNotifier(Notifier):
    def __init__(self, reachable: bool = True) -> None:
        self.reachable = reachable
        self.sent: list[str] = []

    def send(self, message: str) -> bool:
        if not self.reachable:
            return False
        self.sent.append(message)
        return True
