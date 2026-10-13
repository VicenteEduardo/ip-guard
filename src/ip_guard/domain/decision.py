from enum import Enum


class Decisao(Enum):
    AUTORIZADO = "AUTORIZADO"
    BLOQUEADO = "BLOQUEADO"

    def __str__(self):
        return self.value
