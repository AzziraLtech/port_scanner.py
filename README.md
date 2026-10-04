Este é um script básico em Python desenvolvido para identificar portas abertas em um host específico. O objetivo deste projeto é demonstrar conhecimentos fundamentais em redes, sockets e automação com Python voltada para segurança ofensiva.

## 🚀 Funcionalidades

- Escaneamento de portas TCP comuns.
- Identificação de status de conexão (Aberta/Fechada).
- Tratamento de exceções (erros de conexão, interrupção do usuário).
- Registro do horário de início do scan.

## 🛠️ Tecnologias Utilizadas

- **Linguagem:** Python 3.x
- **Bibliotecas:** `socket`, `datetime`

## 📋 Como utilizar e Desenvolver

Este projeto permite escanear portas de forma dinâmica. Para rodar:

1. Certifique-se de ter o Python instalado.
2. Execute o script:
   ```bash
   python port_scanner.py
   ```
3. Insira o IP ou hostname do alvo quando o terminal solicitar.

## 📸 Exemplo de Saída (Output)

Ao executar o scanner contra o `google.com`, o resultado esperado é:

```bash
Digite o IP ou Hostname: google.com
Iniciando scan em: google.com
[+] Porta 80: ABERTA
[+] Porta 443: ABERTA
[-] Porta 21: FECHADA
[-] Porta 22: FECHADA
[-] Porta 3306: FECHADA
Scan finalizado!
```

## ⚠️ Aviso Legal

Este script foi desenvolvido exclusivamente para fins educacionais e testes de segurança em ambientes controlados ou autorizados. O uso deste software contra alvos sem permissão explícita é ilegal e antiético. O desenvolvedor não se responsabiliza pelo uso indevido desta ferramenta.
