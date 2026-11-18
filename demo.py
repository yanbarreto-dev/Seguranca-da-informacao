"""
Entrega 2 - Demonstração (gera as evidências).  Executar: python demo.py
Usa um banco temporário: nada de dados reais.
"""
import hashlib
import os
import sqlite3
import tempfile
import time

import auth
from auth import ServicoAuth

SENHA = "cavalo-bateria-grampo-2026"

caminho = os.path.join(tempfile.mkdtemp(), "demo.db")
s = ServicoAuth(caminho)

print("=== 1. Cadastro (a senha nunca é gravada em texto puro) ===")
print("cadastrar('maria', senha forte)      ->", s.cadastrar("maria", SENHA))
print("cadastrar('joao', '12345678')        ->", s.cadastrar("joao", "12345678"))
print("cadastrar('ana', 'abc')              ->", s.cadastrar("ana", "abc"))
print("cadastrar('Maria', senha forte)      ->", s.cadastrar("Maria", SENHA), "(duplicado)")

print("\n=== 2. O que fica no banco de dados ===")
for linha in sqlite3.connect(caminho).execute("SELECT id, usuario, senha_hash FROM usuarios"):
    print(linha)
print("Formato: $argon2id$v=19$m=<memória KiB>,t=<iterações>,p=<paralelismo>$<salt>$<hash>")

print("\n=== 3. Mesma senha, hashes diferentes (salt aleatório) ===")
print(auth.gerar_hash(SENHA))
print(auth.gerar_hash(SENHA))

print("\n=== 4. Login ===")
print("senha correta           ->", s.autenticar("maria", SENHA))
print("senha incorreta         ->", s.autenticar("maria", "senha-errada-123"))
print("usuário inexistente     ->", s.autenticar("ninguem", "senha-errada-123"))
print("injeção SQL no usuário  ->", s.autenticar("maria' OR '1'='1", "x"))

print("\n=== 5. Bloqueio após 5 falhas ===")
t = 5000.0
for i in range(auth.MAX_FALHAS):
    s.autenticar("maria", "errada-errada-1", agora=t)
print("senha CORRETA durante bloqueio ->", s.autenticar("maria", SENHA, agora=t + 1))
print("senha correta após 60 s        ->", s.autenticar("maria", SENHA, agora=t + 61))

print("\n=== 6. Por que SHA-256 isolado NÃO serve para senhas ===")
sha = hashlib.sha256(SENHA.encode()).hexdigest()
print("SHA-256 (1ª vez):", sha)
print("SHA-256 (2ª vez):", hashlib.sha256(SENHA.encode()).hexdigest(), "<- idêntico: sem salt")
N = 200_000
t0 = time.perf_counter()
for i in range(N):
    hashlib.sha256(str(i).encode()).digest()
t_sha = time.perf_counter() - t0
t0 = time.perf_counter()
for i in range(5):
    auth.gerar_hash(str(i))
t_arg = (time.perf_counter() - t0) / 5
print(f"SHA-256: {N:,} tentativas em {t_sha:.2f} s  (~{N / t_sha:,.0f} por segundo)")
print(f"Argon2id: 1 tentativa em {t_arg * 1000:.0f} ms  (~{1 / t_arg:,.0f} por segundo)")
print(f"Atacante testa ~{(N / t_sha) / (1 / t_arg):,.0f}x mais senhas por segundo no SHA-256.")
