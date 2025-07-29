from abc import ABC, abstractmethod
from typing import Any, Tuple, Optional

class WhatsAppProvider(ABC):
    @abstractmethod
    def send_message(self, to: str, message: str) -> Any:
        pass

    @abstractmethod
    def get_messages(self) -> list[dict]:
        pass

    @abstractmethod
    def webhook_handler(self, request_data: Any) -> Tuple[str, Optional[str]]:
        pass