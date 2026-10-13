from dataclasses import dataclass, field
from typing import List, Optional

from .decision import Decisao
from .ip_address import EnderecoIp
from .rule import Regra


@dataclass
class Avaliacao:
    ip: EnderecoIp
    decisao: Decisao
    regra_aplicada: Optional[str] = None


class PoliticaAutorizacao:
    # deny wins. se empatar ou nao achar nada, bloqueia por padrao.
    def __init__(self, padrao: Decisao = Decisao.BLOQUEADO):
        self.padrao = padrao

    def avaliar(self, ip: EnderecoIp, regras: List[Regra]) -> Avaliacao:
        achou_allow = None

        for r in regras:
            if not r.casa(ip):
                continue
            if r.decisao() == Decisao.BLOQUEADO:
                return Avaliacao(ip=ip, decisao=Decisao.BLOQUEADO, regra_aplicada=r.nome)

            if achou_allow is None:
                achou_allow = r

        if achou_allow:
            return Avaliacao(ip=ip, decisao=Decisao.AUTORIZADO, regra_aplicada=achou_allow.nome)

        return Avaliacao(ip=ip, decisao=self.padrao, regra_aplicada=None)
