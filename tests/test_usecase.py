from ip_guard.application.authorize_ip import AutorizarIp
from ip_guard.domain.decision import Decisao
from ip_guard.domain.rule import IpExatoRegra
from ip_guard.infrastructure.memory import RegrasEmMemoria


def test_caso_uso_autoriza():
    repo = RegrasEmMemoria([IpExatoRegra("9.9.9.9", Decisao.AUTORIZADO, nome="whitelist")])
    caso = AutorizarIp(repo)
    out = caso.executar("9.9.9.9")
    assert out.autorizado is True
    assert out.ip == "9.9.9.9"


def test_caso_uso_bloqueia_quando_nao_tem_regra():
    caso = AutorizarIp(RegrasEmMemoria([]))
    out = caso.executar("9.9.9.9")
    assert out.autorizado is False


def test_caso_uso_ip_invalido_nao_quebra():
    caso = AutorizarIp(RegrasEmMemoria([]))
    out = caso.executar("nao-e-ip")
    assert out.autorizado is False
    assert "invalido" in out.motivo.lower()
