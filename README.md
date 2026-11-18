# Entrega 2 — Hash e autenticação segura

**Disciplina:** Segurança da Informação — Profa. Ma. Ana Carla do Nascimento Santos
**Equipe:** Ian Saulo Barros Fioravante, Yan Felizola e Gustavo Oliveira

## 1. Problema e objetivo

Uma aplicação precisa cadastrar usuários **sem armazenar senhas em texto puro**. O projeto implementa cadastro e login com **Argon2id**, testa login correto e incorreto e demonstra por que um hash genérico como o SHA-256 isolado não é adequado para senhas.

## 2. Ambiente e tecnologias

- Python 3.10 ou superior
- `cryptography` 46 ou superior (mesma biblioteca da Entrega 1; usa OpenSSL 3.2+ para o Argon2id). Nenhum algoritmo foi implementado manualmente.
- Flask (interface web) e SQLite (banco, biblioteca padrão do Python)

## 3. Algoritmo e parâmetros

| Item | Escolha | Justificativa |
|---|---|---|
| Algoritmo | **Argon2id** | Recomendado pelo ASVS 5.0 (11.4.2); resiste a GPU/ASIC por usar muita memória |
| Memória | 47104 KiB (46 MiB) | Mínimo do ASVS para Argon2id |
| Iterações / paralelismo | t = 2, p = 1 | Acima do mínimo (t = 1) |
| Salt | 16 bytes aleatórios (`os.urandom`), um por usuário | Dois usuários com a mesma senha têm hashes diferentes |
| Saída | 32 bytes | |
| Armazenamento | uma string PHC: `$argon2id$v=19$m=…,t=…,p=…$salt$hash` | Parâmetros, salt e hash juntos; permite trocar parâmetros no futuro |
| Comparação | `Argon2id.verify` da biblioteca | Tempo constante, sem `==` manual |

## 4. Como executar

### 4.1 Pré-requisitos

- Python 3.10 ou superior (`python --version`; no Windows, se `python` não for reconhecido, use `py`)
- Git (apenas para clonar)

### 4.2 Instalação

```bash
git clone <URL-DO-REPOSITORIO>
cd entrega2-hash-autenticacao-segura
```

Recomendado: ambiente virtual.

```bash
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

Instale as dependências:

```bash
pip install -r requirements.txt
```

> Se o PowerShell bloquear a ativação do ambiente virtual, rode uma vez:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### 4.3 Executar os testes (25 testes)

```bash
python -m unittest -v
```

Resultado esperado: `Ran 25 tests ... OK` (saída de referência em `saida_testes.txt`).

### 4.4 Executar a demonstração em terminal

```bash
python demo.py
```

Usa um banco temporário e imprime: cadastro, o que fica no banco, hashes diferentes para a mesma senha, login correto/incorreto, injeção SQL, bloqueio após 5 falhas e a comparação SHA-256 × Argon2id (saída de referência em `saida_demo.txt`).

### 4.5 Executar a interface web (Flask)

```bash
python app.py
```

Abra http://127.0.0.1:5000 e use as páginas **Cadastro** e **Login**. Para encerrar, `Ctrl+C`.

Observações:

- O banco `usuarios.db` (SQLite) é criado na primeira execução. Para recomeçar do zero, pare o servidor e apague o arquivo.
- O servidor roda com `threaded=False` porque a conexão SQLite do `ServicoAuth` só pode ser usada na thread que a criou. Sem isso, cadastro e login retornam "Erro interno" (HTTP 500).
- Variáveis opcionais: `SECRET_KEY` (segredo da sessão) e `DB_PATH` (caminho do banco).

  ```bash
  # Windows (PowerShell)
  $env:DB_PATH = "meu_banco.db"; python app.py
  # Linux / macOS
  DB_PATH=meu_banco.db python app.py
  ```

### 4.6 Vídeos de demonstração

- `videos/Entrega2_video_apresentacao.mp4`: apresentação com narração (código, terminal e comparação SHA-256 × Argon2id).
- `videos/Entrega2_video_interface_flask.mp4`: a interface Flask em uso (cadastro, login, erros, bloqueio e CSRF), com legendas.

## 4.7 Estrutura do repositório

```
.
├── app.py               # interface web (Flask)
├── auth.py              # Argon2id, validação de senha, cadastro, login, bloqueio, rehash
├── demo.py              # demonstração em terminal (gera saida_demo.txt)
├── test_auth.py         # testes da lógica de autenticação
├── test_web.py          # testes da interface (CSRF, rotas)
├── templates/           # páginas HTML (base, início, formulário)
├── requirements.txt
├── saida_testes.txt     # evidência: 25 testes OK
├── saida_demo.txt       # evidência: execução do demo.py
├── docs/                # documentação da entrega (PDF e DOCX)
└── videos/              # vídeos de demonstração
```

## 5. Fluxo

1. **Cadastro:** valida usuário e senha → gera salt → deriva Argon2id → grava só a string PHC.
2. **Login:** busca o usuário → deriva com o salt e os parâmetros guardados → `verify` compara em tempo constante.
3. **Erros:** mensagem sempre genérica ("Usuário ou senha inválidos"). Se o usuário não existe, a aplicação verifica contra um hash isca para o tempo de resposta não revelar quais usuários existem.
4. **Bloqueio:** 5 falhas seguidas bloqueiam o usuário por 60 s.
5. **Rehash:** se os parâmetros guardados forem mais fracos que os atuais, o hash é regerado no próximo login correto.

## 6. Testes e evidências

Saídas completas em `saida_testes.txt` (25 testes) e `saida_demo.txt`.

| Teste | Resultado esperado | Obtido |
|---|---|---|
| Cadastro grava só o hash (sem a senha) | Banco contém `$argon2id$…` | ✅ |
| Mesma senha, dois hashes | Diferentes (salt) | ✅ |
| Login com senha correta | Aceito | ✅ |
| Login com senha incorreta | Rejeitado | ✅ |
| Usuário inexistente | Mesma mensagem da senha errada | ✅ |
| Hash adulterado ou malformado | Rejeitado, sem exceção | ✅ |
| Senha curta, vazada ou igual ao usuário | Cadastro recusado | ✅ |
| Senha só de minúsculas, longa e incomum | Aceita (ASVS 6.2.5) | ✅ |
| 5 falhas seguidas | Bloqueio, mesmo com senha certa | ✅ |
| Tentativa de injeção SQL | Tratada como texto, nada vaza | ✅ |
| POST sem token CSRF | HTTP 400 | ✅ |
| Rehash com parâmetros antigos | Hash atualizado no login | ✅ |

## 7. Por que SHA-256 isolado não é adequado para senhas

O SHA-256 foi feito para ser **rápido** (integridade de arquivos, assinaturas). Para senhas, isso é um defeito:

- **Sem salt, é determinístico:** a mesma senha gera sempre o mesmo hash, então tabelas pré-computadas (*rainbow tables*) e a comparação entre usuários funcionam.
- **Sem custo ajustável:** na demonstração, o SHA-256 testa cerca de 2,2 milhões de senhas por segundo em um único núcleo; o Argon2id configurado testa cerca de 14. Com GPU, a diferença cresce muito.
- Salt sozinho não resolve: ele derrota tabelas prontas, mas não a força bruta rápida. É preciso uma função **lenta e que consome memória**.

## 8. Riscos, limitações e melhorias

- A lista de senhas vazadas é só uma amostra didática. Em produção, usar uma base real (ex.: Pwned Passwords).
- O contador de falhas é por usuário: um atacante pode bloquear a conta de outra pessoa (negação de serviço). Melhorar com limite por IP e CAPTCHA.
- Falta MFA (ISO 27002 8.5), recuperação de senha segura e HTTPS (em produção, `SESSION_COOKIE_SECURE=True` atrás de TLS 1.2/1.3).
- Sessão com cookie assinado do Flask; em produção, avaliar sessões no servidor com expiração.
- O banco SQLite é de laboratório; em produção, restringir permissões do arquivo e cifrar backups.
- Um *pepper* (segredo extra guardado fora do banco) reduziria o impacto de vazamento do banco.

## 9. Relação com as normas

- **OWASP Top 10:2025 — A07 Falhas de autenticação** e **A04 Falhas criptográficas**.
- **OWASP ASVS 5.0:** 11.4.2 (KDF lenta), 6.2.1 (mínimo de 8 caracteres), 6.2.5 (sem regras de composição), 6.2.12 (senhas vazadas).
- **ISO/IEC 27002:2022:** 5.17 (informação de autenticação) e 8.5 (autenticação segura).

## 10. Referências

- PYCA. *cryptography documentation: Argon2id*. Disponível em: https://cryptography.io.
- IETF. *RFC 9106: Argon2, Memory-Hard Function for Password Hashing*. 2021.
- OWASP. *Password Storage Cheat Sheet*. Disponível em: https://cheatsheetseries.owasp.org.
- OWASP. *OWASP Top 10:2025* e *ASVS 5.0.0*. 2025.
- ABNT. *NBR ISO/IEC 27002:2022*. 2022.
