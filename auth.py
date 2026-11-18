"""
Entrega 2 - Hash e autenticação segura
Núcleo de cadastro/login: senhas protegidas com Argon2id (biblioteca `cryptography`).

Nada de criptografia caseira: a derivação (Argon2id), o salt aleatório e a
comparação em tempo constante são feitos pela biblioteca.
"""
import base64
import os
import sqlite3
import time
import unicodedata

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# ---------------------------------------------------------------- parâmetros
# ASVS 5.0 (11.4.2): Argon2id com m >= 46 MiB (47104 KiB). Usamos t=2 (> t=1 mínimo).
MEMORIA_KIB = 47104      # 46 MiB
ITERACOES = 2
PARALELISMO = 1
TAM_SALT = 16            # 128 bits, aleatório por usuário
TAM_HASH = 32            # 256 bits

# ASVS 6.2.1 / 6.2.5: mínimo 8 (15 recomendado), sem regras de composição
SENHA_MIN = 8
SENHA_RECOMENDADA = 15
SENHA_MAX = 128

# Anti-força-bruta (ISO 27002 8.5: limite de tentativas)
MAX_FALHAS = 5
BLOQUEIO_SEG = 60

# ASVS 6.2.12: base de senhas vazadas. Aqui, amostra didática; em produção usar
# uma base real (ex.: lista Pwned Passwords) consultada localmente ou via k-anonimato.
SENHAS_VAZADAS = {
    "12345678", "123456789", "1234567890", "password", "password1", "qwerty123",
    "qwertyuiop", "iloveyou", "11111111", "abc12345", "senha123", "senha1234",
    "admin123", "letmein1", "welcome1", "123mudar", "brasil123", "corinthians",
    "mudar123", "00000000", "senhasenha", "12345678910",
}


# ---------------------------------------------------------------- hash
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _kdf(salt: bytes, m: int, t: int, p: int) -> Argon2id:
    return Argon2id(salt=salt, length=TAM_HASH, iterations=t, lanes=p, memory_cost=m)


def normalizar(senha: str) -> bytes:
    """Normaliza Unicode (NFKC) para que a mesma senha digitada em teclados
    diferentes gere o mesmo hash, e converte para bytes UTF-8."""
    return unicodedata.normalize("NFKC", senha).encode("utf-8")


def gerar_hash(senha: str) -> str:
    """Retorna string no formato PHC: parâmetros + salt + hash em um só campo."""
    salt = os.urandom(TAM_SALT)
    h = _kdf(salt, MEMORIA_KIB, ITERACOES, PARALELISMO).derive(normalizar(senha))
    return (f"$argon2id$v=19$m={MEMORIA_KIB},t={ITERACOES},p={PARALELISMO}"
            f"${_b64(salt)}${_b64(h)}")


def _ler(armazenado: str):
    _, alg, _ver, params, salt, h = armazenado.split("$")
    if alg != "argon2id":
        raise ValueError("algoritmo inesperado")
    p = dict(x.split("=") for x in params.split(","))
    return int(p["m"]), int(p["t"]), int(p["p"]), _unb64(salt), _unb64(h)


def verificar_hash(senha: str, armazenado: str) -> bool:
    """Comparação em tempo constante feita pela biblioteca (verify)."""
    try:
        m, t, p, salt, esperado = _ler(armazenado)
        _kdf(salt, m, t, p).verify(normalizar(senha), esperado)
        return True
    except (InvalidKey, ValueError, KeyError):
        return False


def precisa_rehash(armazenado: str) -> bool:
    """True se o hash foi gerado com parâmetros mais fracos que os atuais."""
    m, t, p, _, _ = _ler(armazenado)
    return (m, t, p) != (MEMORIA_KIB, ITERACOES, PARALELISMO)


# hash "isca" para igualar o tempo de resposta quando o usuário não existe
_HASH_ISCA = gerar_hash("isca-nao-e-senha-de-ninguem")


# ---------------------------------------------------------------- política
def validar_senha(usuario: str, senha: str):
    """Retorna (ok, mensagem). Sem exigir maiúscula/número/símbolo (ASVS 6.2.5)."""
    s = unicodedata.normalize("NFKC", senha)
    if len(s) < SENHA_MIN:
        return False, f"A senha precisa ter pelo menos {SENHA_MIN} caracteres."
    if len(s) > SENHA_MAX:
        return False, f"A senha pode ter no máximo {SENHA_MAX} caracteres."
    if s.casefold() in SENHAS_VAZADAS:
        return False, "Essa senha é muito comum ou já apareceu em vazamentos. Escolha outra."
    if s.casefold() == usuario.casefold():
        return False, "A senha não pode ser igual ao nome de usuário."
    return True, ""


# ---------------------------------------------------------------- serviço
class ServicoAuth:
    def __init__(self, caminho_db: str = "usuarios.db"):
        self.db = sqlite3.connect(caminho_db)
        self.db.execute("""CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT NOT NULL UNIQUE,
            senha_hash TEXT NOT NULL,
            falhas INTEGER NOT NULL DEFAULT 0,
            bloqueado_ate REAL NOT NULL DEFAULT 0,
            criado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
        self.db.commit()

    @staticmethod
    def _nome(usuario: str) -> str:
        return unicodedata.normalize("NFKC", usuario).strip().casefold()

    def cadastrar(self, usuario: str, senha: str):
        """Retorna (ok, mensagem). Senha em texto puro nunca é gravada."""
        nome = self._nome(usuario)
        if not (3 <= len(nome) <= 32) or not nome.replace("_", "").replace(".", "").isalnum():
            return False, "Usuário: 3 a 32 caracteres (letras, números, _ ou .)."
        ok, msg = validar_senha(nome, senha)
        if not ok:
            return False, msg
        try:
            self.db.execute("INSERT INTO usuarios (usuario, senha_hash) VALUES (?, ?)",
                            (nome, gerar_hash(senha)))   # consulta parametrizada
            self.db.commit()
        except sqlite3.IntegrityError:
            return False, "Não foi possível concluir o cadastro com esses dados."
        aviso = "" if len(senha) >= SENHA_RECOMENDADA else \
            f" (dica: {SENHA_RECOMENDADA}+ caracteres é mais seguro)"
        return True, "Cadastro realizado." + aviso

    def autenticar(self, usuario: str, senha: str, agora=None):
        """Retorna (ok, mensagem). Mensagem de erro é sempre genérica."""
        agora = time.time() if agora is None else agora
        generica = "Usuário ou senha inválidos."
        nome = self._nome(usuario)
        linha = self.db.execute(
            "SELECT senha_hash, falhas, bloqueado_ate FROM usuarios WHERE usuario = ?",
            (nome,)).fetchone()

        if linha is None:
            verificar_hash(senha, _HASH_ISCA)         # gasta o mesmo tempo
            return False, generica
        senha_hash, falhas, bloqueado_ate = linha

        if bloqueado_ate > agora:
            return False, "Muitas tentativas. Aguarde e tente novamente."

        if len(senha) > SENHA_MAX or not verificar_hash(senha, senha_hash):
            falhas += 1
            bloqueio = agora + BLOQUEIO_SEG if falhas >= MAX_FALHAS else 0
            if falhas >= MAX_FALHAS:
                falhas = 0
            self.db.execute("UPDATE usuarios SET falhas=?, bloqueado_ate=? WHERE usuario=?",
                            (falhas, bloqueio, nome))
            self.db.commit()
            return False, generica

        novo = gerar_hash(senha) if precisa_rehash(senha_hash) else senha_hash
        self.db.execute("UPDATE usuarios SET senha_hash=?, falhas=0, bloqueado_ate=0 "
                        "WHERE usuario=?", (novo, nome))
        self.db.commit()
        return True, "Login realizado."
