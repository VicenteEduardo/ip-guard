from ip_guard.domain.decision import Decisao
from ip_guard.domain.ip_address import EnderecoIp
from ip_guard.domain.policy import PoliticaAutorizacao
from ip_guard.domain.rule import FaixaCidrRegra, IpExatoRegra


def test_sem_regra_bloqueia():
    pol = PoliticaAutorizacao()
    r = pol.avaliar(EnderecoIp("8.8.8.8"), [])
    assert r.decisao == Decisao.BLOQUEADO


def test_whitelist_libera():
    pol = PoliticaAutorizacao()
    regras = [IpExatoRegra("8.8.8.8", Decisao.AUTORIZADO, nome="whitelist")]
    r = pol.avaliar(EnderecoIp("8.8.8.8"), regras)
    assert r.decisao == Decisao.AUTORIZADO
    assert r.regra_aplicada == "whitelist"


def test_blacklist_ganha_da_whitelist():
    # se o ip ta nas duas listas, bloqueia. fail-safe.
    pol = PoliticaAutorizacao()
    regras = [
        IpExatoRegra("1.1.1.1", Decisao.AUTORIZADO, nome="whitelist"),
        IpExatoRegra("1.1.1.1", Decisao.BLOQUEADO, nome="blacklist"),
    ]
    r = pol.avaliar(EnderecoIp("1.1.1.1"), regras)
    assert r.decisao == Decisao.BLOQUEADO


def test_cidr_libera_faixa():
    pol = PoliticaAutorizacao()
    regras = [FaixaCidrRegra("10.0.0.0/8", Decisao.AUTORIZADO, nome="allow-cidr")]
    assert pol.avaliar(EnderecoIp("10.5.6.7"), regras).decisao == Decisao.AUTORIZADO
    assert pol.avaliar(EnderecoIp("11.0.0.1"), regras).decisao == Decisao.BLOQUEADO


def test_deny_cidr_ganha():
    pol = PoliticaAutorizacao()
    regras = [
        FaixaCidrRegra("0.0.0.0/0", Decisao.AUTORIZADO, nome="allow-cidr"),
        FaixaCidrRegra("192.168.0.0/16", Decisao.BLOQUEADO, nome="deny-cidr"),
    ]
    r = pol.avaliar(EnderecoIp("192.168.1.1"), regras)
    assert r.decisao == Decisao.BLOQUEADO
