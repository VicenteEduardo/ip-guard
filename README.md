# ip-guard

## objectivo

Controlar o acesso à rede decidindo, para cada endereço IP recebido, se deve ser AUTORIZADO ou BLOQUEADO segundo regras configuradas (whitelist, blacklist e faixas CIDR). O sistema serve como mini-firewall avaliador: recebe IPs via CLI ou como biblioteca, aplica a política deny-wins e devolve a decisão com o motivo, para integrar em port monitoring, VPN ou análise de logs.

Recebe um IP e diz se entra ou nao, baseado em whitelist / blacklist / CIDR.

Regra de ouro: **deny wins**. Se cair numa regra de bloqueio, bloqueia mesmo que tenha allow. Sem regra = bloqueia.

## estrutura

```
src/ip_guard/
  domain/          # regra de negocio pura, sem depender de nada
    ip_address.py  # value object EnderecoIp
    rule.py        # Regra (abc) + IpExatoRegra + FaixaCidrRegra
    policy.py      # PoliticaAutorizacao.avaliar()
  application/     # caso de uso
    authorize_ip.py  # AutorizarIp.executar()
    ports.py         # RepositorioRegras (porta)
  infrastructure/  # adapters
    memory.py      # RegrasEmMemoria (pra teste)
    json_rules.py  # RegrasDoJson (le regras.json)
  interface/
    cli.py         # argparse
```

## como rodar

```bash
cd ip-guard
python3 -m pytest -v
PYTHONPATH=src python3 -m ip_guard 187.44.10.5 --regras regras.json
PYTHONPATH=src python3 -m ip_guard 8.8.8.8 --regras regras.json
cat lista.txt | PYTHONPATH=src python3 -m ip_guard --regras regras.json
```

`regras.json`:

```json
{
  "whitelist": ["187.44.10.5"],
  "blacklist": ["45.90.12.7"],
  "allow_cidr": ["10.0.0.0/8"],
  "deny_cidr": ["192.168.0.0/16"]
}
```

## usar como lib

```python
from ip_guard.application.authorize_ip import AutorizarIp
from ip_guard.infrastructure.json_rules import RegrasDoJson

caso = AutorizarIp(RegrasDoJson("regras.json"))
r = caso.executar("10.1.2.3")
print(r.autorizado, r.motivo)
```

## tdd

Fiz na ordem: `EnderecoIp` -> `PoliticaAutorizacao` -> `AutorizarIp` -> `RegrasDoJson` -> CLI.
Cada passo com teste quebrando antes. Roda `python3 -m pytest` que cobre isso.

## solid onde

- S: cada classe faz uma coisa (Ip valida, Policy decide, Repo carrega)
- O: regra nova = herda de `Regra`, nao mexe no resto
- L: `IpExatoRegra` e `FaixaCidrRegra` trocam entre si sem quebrar `avaliar()`
- I: `RepositorioRegras` tem so `todas()`
- D: `AutorizarIp` recebe o repo por parametro, nao importa se e memoria ou json
```

## ddd

Linguagem ubíqua: autorizar/bloquear, whitelist/blacklist, cidr. Dominio sem import de infra.
