from abc import ABC, abstractmethod
from typing import List

from ip_guard.domain.rule import Regra


class RepositorioRegras(ABC):
    @abstractmethod
    def todas(self) -> List[Regra]:
        ...
