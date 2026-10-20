"""Port scanner TCP com banner grabbing (uso educacional).

Use APENAS em sistemas seus ou com autorização explícita
(ex.: localhost, uma VM sua, ou scanme.nmap.org).

Exemplos:
    python port_scanner.py localhost
    python port_scanner.py scanme.nmap.org -p 22,80,443
    python port_scanner.py 192.168.56.101 -p 1-1024 -t 0.5
"""
import argparse
import socket
import ssl

PORTAS_PADRAO = [21, 22, 25, 80, 443, 3306, 8080]
PORTAS_HTTP = {80, 8080}
PORTAS_TLS = {443, 8443}

# Para ler o banner não precisamos validar o certificado.
CONTEXTO_TLS = ssl.create_default_context()
CONTEXTO_TLS.check_hostname = False
CONTEXTO_TLS.verify_mode = ssl.CERT_NONE


def interpretar_portas(texto):
    """Converte '22,80,100-110' em uma lista de portas."""
    portas = []
    for parte in texto.split(","):
        if "-" in parte:
            inicio, fim = parte.split("-")
            portas.extend(range(int(inicio), int(fim) + 1))
        else:
            portas.append(int(parte))
    if any(p < 1 or p > 65535 for p in portas):
        raise ValueError("portas devem estar entre 1 e 65535")
    return portas


def ler_banner(sock, host, porta):
    """Tenta obter o banner do serviço. Retorna o texto ou None."""
    conexao = sock
    try:
        if porta in PORTAS_TLS:
            conexao = CONTEXTO_TLS.wrap_socket(sock, server_hostname=host)
        # Servidores web só respondem depois de receber uma requisição.
        if porta in PORTAS_HTTP or porta in PORTAS_TLS:
            requisicao = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
            conexao.sendall(requisicao.encode())
        dados = conexao.recv(1024)
        return dados.decode(errors="ignore").strip() or None
    except (socket.timeout, ssl.SSLError, OSError):
        return None
    finally:
        conexao.close()


def escanear(host, portas, timeout):
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[!] Não foi possível resolver o host: {host}")
        return

    print(f"Iniciando scan em {host} ({ip})")
    for porta in portas:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, porta)) != 0:
                print(f"[-] Porta {porta}: FECHADA")
                continue

            print(f"[+] Porta {porta}: ABERTA")
            banner = ler_banner(s, host, porta)
            if banner is None:
                print("    [!] Não foi possível ler o banner.")
                continue
            linhas = banner.splitlines()
            print(f"    [i] {linhas[0]}")
            for linha in linhas[1:]:
                if linha.lower().startswith("server:"):
                    print(f"    [i] {linha}")


def main():
    parser = argparse.ArgumentParser(
        description="Port scanner TCP com banner grabbing (uso educacional)."
    )
    parser.add_argument("host", help="IP ou hostname (apenas alvos autorizados)")
    parser.add_argument(
        "-p", "--portas",
        default=",".join(map(str, PORTAS_PADRAO)),
        help="portas: '22,80,443' ou '1-1024' (padrão: comuns)",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0,
        help="timeout por porta, em segundos (padrão: 1.0)",
    )
    args = parser.parse_args()

    try:
        portas = interpretar_portas(args.portas)
    except ValueError as erro:
        parser.error(f"portas inválidas: {erro}")

    try:
        escanear(args.host, portas, args.timeout)
    except KeyboardInterrupt:
        print("\n[!] Scan interrompido pelo usuário.")


if __name__ == "__main__":
    main()
