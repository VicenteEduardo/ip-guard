import argparse
import sys
from pathlib import Path

from ip_guard.application.authorize_ip import AutorizarIp
from ip_guard.infrastructure.json_rules import RegrasDoJson
from ip_guard.infrastructure.memory import RegrasEmMemoria
from ip_guard.domain.decision import Decisao
from ip_guard.domain.rule import FaixaCidrRegra, IpExatoRegra


def monta_repo(args):
    if args.regras:
        return RegrasDoJson(args.regras)

    # sem arquivo usa um default pequeno pra facilitar teste manual
    repo = RegrasEmMemoria()
    repo.adicionar(IpExatoRegra("127.0.0.1", Decisao.AUTORIZADO, nome="whitelist"))
    repo.adicionar(FaixaCidrRegra("10.0.0.0/8", Decisao.AUTORIZADO, nome="allow-cidr"))
    return repo


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ip-guard", description="diz se um IP pode ou nao passar")
    ap.add_argument("ip", nargs="?", help="IP pra avaliar. se vazio, le do stdin")
    ap.add_argument("--regras", default=None, help="caminho do regras.json")
    ap.add_argument("--quiet", action="store_true", help="so imprime AUTORIZADO/BLOQUEADO")
    args = ap.parse_args(argv)

    repo = monta_repo(args)
    caso = AutorizarIp(repo)

    ips = []
    if args.ip:
        ips = [args.ip]
    else:
        # permite pipe: cat ips.txt | ip-guard
        data = sys.stdin.read().strip().split()
        ips = [x.strip().strip(",") for x in data if x.strip()]

    if not ips:
        ap.print_help()
        return 2

    rc = 0
    for entrada in ips:
        r = caso.executar(entrada)
        if args.quiet:
            print(r.decisao)
        else:
            status = "AUTORIZADO" if r.autorizado else "BLOQUEADO"
            print(f"{r.ip} -> {status} ({r.motivo})")
        if not r.autorizado:
            rc = 1

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
