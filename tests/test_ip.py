import pytest

from ip_guard.domain.ip_address import EnderecoIp, IpInvalido


def test_ip_valido():
    ip = EnderecoIp("192.168.1.10")
    assert str(ip) == "192.168.1.10"
    assert ip.versao == 4


def test_ip_com_espaco():
    ip = EnderecoIp("  10.0.0.1  ")
    assert str(ip) == "10.0.0.1"


def test_ip_ruim_levanta_erro():
    with pytest.raises(IpInvalido):
        EnderecoIp("999.1.1.1")

    with pytest.raises(IpInvalido):
        EnderecoIp("abc")


def test_ipv6_funciona():
    ip = EnderecoIp("::1")
    assert ip.versao == 6


def test_dentro_da_rede():
    ip = EnderecoIp("10.1.2.3")
    assert ip.dentro_da_rede("10.0.0.0/8") is True
    assert ip.dentro_da_rede("192.168.0.0/16") is False
