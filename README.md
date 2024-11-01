# README: Intrusion Detection System (IDS) para Detecção e Bloqueio de SYN Flood

## Visão Geral
Este projeto é um Intrusion Detection System (IDS) simples, desenvolvido em Python, que detecta ataques de SYN flood em uma rede e bloqueia automaticamente o IP de origem que ultrapassa um limiar de pacotes SYN definido. O sistema também realiza o desbloqueio dos IPs após um período de tempo configurável.

## Funcionalidades
- Captura de pacotes TCP usando sockets raw.
- Detecção de pacotes com flag SYN para identificar potenciais ataques de SYN flood.
- Monitoramento da frequência de pacotes SYN recebidos de cada IP.
- Bloqueio automático de IPs que ultrapassam o limite de pacotes SYN usando `iptables`.
- Desbloqueio automático de IPs após um período de tempo definido.
- Registro das ações de bloqueio e desbloqueio em um arquivo de log.

## Tecnologias Utilizadas
- **Linguagem**: Python
- **Bibliotecas**: `socket`, `struct`, `os`, `datetime`
- **Ferramentas de Sistema**: `iptables`

## Pré-requisitos
- Python 3.x instalado.
- Permissões de superusuário (root) para executar o script e manipular regras do `iptables`.
- Sistema operacional Linux.

## Como Executar o Projeto
1. **Clone o repositório**:
   ```bash
   git clone <URL do repositório>
   cd <diretório do projeto>
   ```

2. **Execute o script com permissões de superusuário**:
   ```bash
   sudo python3 syn_flood_ids.py
   ```

## Configuração de Parâmetros
- **`syn_threshold`**: Define o número de pacotes SYN por segundo que caracteriza um ataque. O padrão é `100`.
- **`interval`**: Intervalo de tempo (em segundos) para verificação de pacotes SYN. O padrão é `5` segundos.
- **`unblock_time`**: Tempo de bloqueio (em segundos) após o qual um IP é desbloqueado automaticamente. O padrão é `60` segundos.

## Estrutura do Código
- **Captura de Pacotes de Rede**: O script utiliza `socket` para criar um socket raw que captura pacotes de rede.
- **Detecção de Ataques**: Os pacotes TCP são filtrados para verificar a flag SYN e a contagem por IP é atualizada.
- **Bloqueio de IP**: Caso o número de pacotes SYN de um IP ultrapasse o limiar, o IP é bloqueado com `iptables`.
- **Desbloqueio Automático**: Após o tempo definido em `unblock_time`, os IPs são desbloqueados automaticamente.
- **Logs**: Todas as ações de bloqueio e desbloqueio são registradas em `syn_flood_log.txt`.

## Exemplo de Uso
Durante a execução do script, ele irá capturar pacotes e, se um IP enviar um número de pacotes SYN maior que o `syn_threshold` em um intervalo de `interval` segundos, o IP será bloqueado. Passado o `unblock_time`, o IP será desbloqueado automaticamente e a ação será registrada no log.

## Melhorias Futuras
- Implementação de uma interface gráfica para monitoramento.
- Integração com sistemas de notificação para alertas em tempo real.
- Suporte para detecção de outros tipos de ataques.

## Observações
- Este projeto é uma demonstração de um sistema de detecção e resposta simples para fins educacionais. Em ambientes de produção, recomenda-se o uso de soluções robustas de segurança.

## Contribuições
Contribuições são bem-vindas! Sinta-se à vontade para abrir issues e pull requests para melhorar o projeto.

## Licença
Este projeto é distribuído sob a licença MIT. Consulte o arquivo `LICENSE` para mais informações.

