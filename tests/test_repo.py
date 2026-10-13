import json

from ip_guard.application.authorize_ip import AutorizarIp
from ip_guard.infrastructure.json_rules import RegrasDoJson


def test_carrega_json(tmp_path):
    arq = tmp_path / "regras.json"
    arq.write_text(json.dumps({
        "whitelist": ["1.2.3.4"],
        "blacklist": ["5.6.7.8"],
        "allow_cidr": ["10.0.0.0/8"],
        "deny_cidr": []
    }))

    repo = RegrasDoJson(arq)
    regras = repo.todas()
    assert len(regras) == 3

    caso = AutorizarIp(repo)
    assert caso.executar("1.2.3.4").autorizado is True
    assert caso.executar("5.6.7.8").autorizado is False
    assert caso.executar("10.9.9.9").autorizado is True


def test_arquivo_que_nao_existe_retorna_vazio(tmp_path):
    repo = RegrasDoJson(tmp_path / "nao-existe.json")
    assert repo.todas() == []
