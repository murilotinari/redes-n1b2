import socket
import struct
import os
from datetime import datetime, timedelta

# Dicionário para armazenar o número de pacotes SYN por IP
syn_count = {}
# Dicionário para armazenar o tempo de bloqueio por IP
blocked_ips = {}
# Intervalo de tempo para verificação de ataque (em segundos)
interval = 5
# Limite de pacotes SYN por IP que caracteriza um ataque
syn_threshold = 10
# Tempo de desbloqueio (em segundos)
unblock_time = 15
# Última verificação de tempo
last_check = datetime.now()

# Função para bloquear IP usando iptables
def block_ip(ip_address):
    os.system(f"iptables -A INPUT -s {ip_address} -j DROP")
    blocked_ips[ip_address] = datetime.now()
    with open("syn_flood_log.txt", "a") as log_file:
        log_file.write(f"[{datetime.now()}] IP {ip_address} bloqueado por exceder o limite de pacotes SYN.\n")
    print(f"IP {ip_address} bloqueado por exceder o limite de pacotes SYN.")

def unblock_ip(ip_address):
    os.system(f"iptables -D INPUT -s {ip_address} -j DROP")
    with open("syn_flood_log.txt", "a") as log_file:
        log_file.write(f"[{datetime.now()}] IP {ip_address} desbloqueado após o tempo de bloqueio.\n")
    print(f"IP {ip_address} desbloqueado após o tempo de bloqueio.")
    del blocked_ips[ip_address]

# Criar um socket raw para capturar pacotes de rede
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    print("Captura de pacotes iniciada...")
except PermissionError:
    print("Erro: é necessário executar o script como superusuário (root).")
    exit()

while True:
    # Captura de pacotes
    packet, addr = s.recvfrom(65565)
    ip_header = packet[:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4

    # Captura o cabeçalho TCP
    tcp_header = packet[iph_length:iph_length + 20]
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
    flags = tcph[5]

    # Verifica se é um pacote SYN (flag SYN está habilitada)
    syn_flag = flags & 0x02  # SYN flag é o bit 1

    if syn_flag:
        source_ip = socket.inet_ntoa(iph[8])
        current_time = datetime.now()

        # Atualiza contagem de pacotes SYN por IP
        if source_ip not in syn_count:
            syn_count[source_ip] = 1
        else:
            syn_count[source_ip] += 1

        # Verifica se o tempo de intervalo foi ultrapassado
        if current_time - last_check > timedelta(seconds=interval):
            for ip, count in list(syn_count.items()):
                if count > syn_threshold:
                    block_ip(ip)
                # Reseta a contagem após verificação
                del syn_count[ip]

            # Atualiza a última verificação de tempo
            last_check = current_time


    # Verifica se algum IP bloqueado pode ser desbloqueado
    for ip, block_time in list(blocked_ips.items()):
        if datetime.now() - block_time > timedelta(seconds=unblock_time):
            unblock_ip(ip)
