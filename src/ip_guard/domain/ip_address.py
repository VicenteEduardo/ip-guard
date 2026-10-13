import ipaddress


class IpInvalido(ValueError):
    pass


class EnderecoIp:
    # value object simples, imutavel na pratica
    def __init__(self, valor: str):
        valor = valor.strip()
        try:
            self._ip = ipaddress.ip_address(valor)
        except ValueError:
            raise IpInvalido(f"IP invalido: {valor}")
        self.valor = str(self._ip)

    def __str__(self):
        return self.valor

    def __eq__(self, outro):
        if isinstance(outro, EnderecoIp):
            return self._ip == outro._ip
        return False

    def __hash__(self):
        return hash(self._ip)

    @property
    def versao(self):
        return self._ip.version

    def dentro_da_rede(self, rede: str) -> bool:
        # rede no formato "10.0.0.0/8"
        try:
            net = ipaddress.ip_network(rede, strict=False)
        except ValueError:
            return False
        return self._ip in net
