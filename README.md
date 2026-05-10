## NOPEN (Advanced Remote Administration)

<p align="center">
  <img src="Screenshot_20.png" width="600"/>
</p>

```console
$ ./nopen_client_v2.py --help

NOPEN Client — Remote Administration Tool

--[ Passive Architecture (Port-knocking + Listen mode)
--[ Traffic Obfuscation (AES-256-GCM frames disguised as DNS/HTTP)
--[ Persistence & Cleanup (utmp/wtmp/lastlog wipe, in-memory exec)

commands & usage (post-connect):

  [ Arquitetura Passiva ]
    -knock <p1,p2,p3> [tcp|udp]    Port-knock para acordar implante
    -listen [porta] [timeout]      Aguarda implante conectar (modo passivo)
    -obfs [raw|dns|http]           Define modo de ofuscação de tráfego

  [ Limpeza de Rastros ]
    -wipelogs [user] [host]        Limpa utmp/wtmp/lastlog/auth.log remotos
    -shred <arquivo>               Destrói arquivo local (3 passes)
    -wipelocal                     Limpa rastros na máquina LOCAL do operador
    -memexec <script.py>           Executa script Python remoto SEM tocar disco
    -memelf <binario>              Executa ELF remoto via memfd_create (RAM)
    -burn                          BURN: wipe + encerra servidor + desconecta

  [ Gerais ]
    -elevate                       Verifica privilégios / SUID / sudo -l
    -getenv                        Variáveis de ambiente remotas
    -gs <padrão> [dir]             Busca arquivo por padrão
    -setenv VAR=valor              Define variável remota
    -shell                         Shell interativo local
    -status                        Status completo da sessão
    -time                          Data/hora UTC remota
    -pid                           PID do processo servidor

  [ Rede Remota ]
    -ifconfig                      Interfaces de rede
    -nslookup <host>               Resolução DNS
    -ping [-u|-t|-i] <host>        Ping avançado
    -trace -r <target> [src]       Traceroute
    -comptine <target> [src]       Traceroute ICMP furtivo
    -scan [args]                   nmap / scanner de portas
    -sentry <args>                 Captura de pacotes (tcpdump)
    -tunnel <porta>                Tunelamento de porta
    -vscan                         Scanner de vulnerabilidades

  [ Redirecionamento ]
    -fixudp <ip> <porta>           Corrige redirecionamento UDP
    -irtun <target> <cb> <port>    Túnel reverso ICMP
    -jackpop <tport> <srcip> <sp>  Port-knocking avançado
    -nrtun <ip> <toip> [toport]    Túnel NAT reverso
    -stun <toip:port>              NAT traversal STUN
    -rawsend tcp <port>            Envio raw TCP
    -rtun <porta> [toip [toport]]  Túnel reverso
    -sutun [-t ttl] <toip> <port>  Túnel simétrico UDP
    -chuli <ip> <porta>            Redireciona conexão

  [ Arquivos Remotos ]
    -cat [-s N] [-m max] <arquivo> Exibe arquivo remoto
    -cksum <arquivo>               md5 + sha256
    -cklist <padrão>               Verifica lista de arquivos
    -get <arquivo>                 Baixa arquivo do servidor
    -grep [-v|-n|-i] <pat> <arq>   Grep remoto
    -lput <local> [dest]           Envia arquivo para servidor
    -strings <arquivo>             Extrai strings
    -tail [+/-n] <arquivo>         Fim de arquivo
    -touch [-t] <arquivo>          Altera timestamps
    -upload <arquivo> <porta>      Upload via porta
    -mailgrep <args>               Busca em e-mails

  [ Diretório Remoto ]
    -ls [-la] [path]               Lista diretório
    -find <args>                   Busca avançada
    -cd <path>                     Muda diretório remoto
    -cdp                           Exibe CWD remoto

  [ Cliente Local ]
    -autopilot <porta> [xml]       Modo autopilot
    -cmdout [arquivo]              Redireciona saída para arquivo
    -exit                          Encerra cliente NOPEN
    -help                          Este menu
    -hist                          Histórico de comandos da sessão
    -readrc [arquivo]              Lê arquivo de comandos
    -remark / -rem <texto>         Comentário no log
    -reset                         Reseta estado da sessão

  [ Ambiente Local ]
    -lcd <dir>                     Muda diretório local
    -lgetenv                       Variáveis locais
    -lpwd                          Diretório local atual
    -lsetenv VAR=valor             Define variável local
    -lsh [-q] <cmd>                Executa comando localmente

notes:
  - NOPEN Strict mode: only RSA-2048 / SHA-256 / AES-256-GCM are negotiated.
  - Trace wiping and memory execution require appropriate OS privileges (Root on Linux).
  - Comandos sem prefixo são enviados direto ao shell remoto.
```

> *This tool is inspired by NOPEN from the Equation Group (National Security Agency).*

<p align="center">
  <img src="Screnshot1jpg.jpg" width="600"/>
</p>
