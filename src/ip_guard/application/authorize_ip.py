from dataclasses import dataclass
from typing import Optional

from ip_guard.domain.decision import Decisao
from ip_guard.domain.ip_address import EnderecoIp, IpInvalido
from ip_guard.domain.policy import PoliticaAutorizacao

from .ports import RepositorioRegras


@dataclass
class Resultado:
    ip: str
    autorizado: bool
    motivo: Optional[str] = None

    @property
    def decisao(self) -> Decisao:
        return Decisao.AUTORIZADO if self.autorizado else Decisao.BLOQUEADO


class AutorizarIp:
    # caso de uso. depende so da abstracao (DIP), nao de arquivo/memoria.
    def __init__(self, regras: RepositorioRegras, politica: PoliticaAutorizacao = None):
        self.regras = regras
        self.politica = politica or PoliticaAutorizacao()

    def executar(self, ip_str: str) -> Resultado:
        try:
            ip = EnderecoIp(ip_str)
        except IpInvalido as e:
            # ip ruim nunca autoriza
            return Resultado(ip=ip_str, autorizado=False, motivo=str(e))

        lista = self.regras.todas()
        av = self.politica.avaliar(ip, lista)

        if av.decisao == Decisao.AUTORIZADO:
            return Resultado(ip=ip.valor, autorizado=True, motivo=av.regra_aplicada or "whitelist")
        return Resultado(ip=ip.valor, autorizado=False, motivo=av.regra_aplicada or "sem regra (padrao bloquear)")
