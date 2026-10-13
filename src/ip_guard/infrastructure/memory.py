from typing import List

from ip_guard.application.ports import RepositorioRegras
from ip_guard.domain.rule import Regra


class RegrasEmMemoria(RepositorioRegras):
    def __init__(self, regras: List[Regra] = None):
        self._regras = list(regras) if regras else []

    def adicionar(self, regra: Regra):
        self._regras.append(regra)

    def todas(self) -> List[Regra]:
        return list(self._regras)
