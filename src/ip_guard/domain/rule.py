from abc import ABC, abstractmethod
from dataclasses import dataclass

from .decision import Decisao
from .ip_address import EnderecoIp


class Regra(ABC):
    # regra base. cada regra nova herda daqui (aberto p/ extensao)
    nome: str = "regra"

    @abstractmethod
    def casa(self, ip: EnderecoIp) -> bool:
        ...

    @abstractmethod
    def decisao(self) -> Decisao:
        ...


@dataclass
class IpExatoRegra(Regra):
    ip_alvo: str
    acao: Decisao
    nome: str = "ip-exato"

    def casa(self, ip: EnderecoIp) -> bool:
        return ip.valor == self.ip_alvo

    def decisao(self) -> Decisao:
        return self.acao


@dataclass
class FaixaCidrRegra(Regra):
    cidr: str
    acao: Decisao
    nome: str = "cidr"

    def casa(self, ip: EnderecoIp) -> bool:
        return ip.dentro_da_rede(self.cidr)

    def decisao(self) -> Decisao:
        return self.acao
