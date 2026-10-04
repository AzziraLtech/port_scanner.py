import socket

alvo = input("Digite o IP ou Hostname: python")
#Lista de portas comuns para testar
portas = [21, 22, 80, 443, 3306]

print(f"Iniciando scan em: {alvo}")

for porta in portas:
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliente.settimeout(1.0) # Espera 1segundo é pela resposta

    resultado = cliente.connect_ex((alvo, porta))

    if resultado == 0:
        print(f"[+] Porta {porta}:ABERTA")
        try:
            # Tenta receber1024 bytes do serviço (o " Banner")
            banner = cliente.recv(1024)
            print(f"    [!] |Serviço: {banner.decode().strip()}")
        except:
            print("     [!] Não foi possível ler o banner.")
    else:
        print(f"[-] Porta {porta}: FECHADA")

    cliente.close()