import json
from pathlib import Path
from typing import List

from ip_guard.application.ports import RepositorioRegras
from ip_guard.domain.decision import Decisao
from ip_guard.domain.rule import FaixaCidrRegra, IpExatoRegra, Regra


class RegrasDoJson(RepositorioRegras):
    # espera um json tipo:
    # {"whitelist": ["1.2.3.4"], "blacklist": ["5.6.7.8"],
    #  "allow_cidr": ["10.0.0.0/8"], "deny_cidr": ["192.168.0.0/16"]}
    def __init__(self, caminho):
        self.caminho = Path(caminho)

    def todas(self) -> List[Regra]:
        if not self.caminho.exists():
            return []

        raw = json.loads(self.caminho.read_text(encoding="utf-8"))

        regras: List[Regra] = []
        for ip in raw.get("whitelist", []):
            regras.append(IpExatoRegra(ip_alvo=ip, acao=Decisao.AUTORIZADO, nome="whitelist"))
        for ip in raw.get("blacklist", []):
            regras.append(IpExatoRegra(ip_alvo=ip, acao=Decisao.BLOQUEADO, nome="blacklist"))
        for cidr in raw.get("allow_cidr", []):
            regras.append(FaixaCidrRegra(cidr=cidr, acao=Decisao.AUTORIZADO, nome="allow-cidr"))
        for cidr in raw.get("deny_cidr", []):
            regras.append(FaixaCidrRegra(cidr=cidr, acao=Decisao.BLOQUEADO, nome="deny-cidr"))

        return regras
