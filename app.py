"""
Entrega 2 - Interface web (Flask) para cadastro/login.
Executar:  python app.py   ->  http://127.0.0.1:5000
"""
import os
import secrets

from flask import Flask, abort, redirect, render_template, request, session, url_for

from auth import ServicoAuth

app = Flask(__name__)
# Segredo da sessão vem do ambiente (nunca no código). Sem variável, gera um aleatório
# a cada execução (sessões deixam de valer ao reiniciar: aceitável em laboratório).
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

servico = ServicoAuth(os.environ.get("DB_PATH", "usuarios.db"))


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def checar_csrf():
    if request.method == "POST":
        esperado = session.get("csrf")
        enviado = request.form.get("csrf", "")
        # sem token na sessão = requisição inválida (evita "" == "" passar na comparação)
        if not esperado or not secrets.compare_digest(enviado, esperado):
            abort(400)


@app.after_request
def cabecalhos(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(500)
def erro_interno(_):
    return "Erro interno.", 500          # mensagem genérica, sem stack trace


@app.route("/")
def inicio():
    return render_template("inicio.html", usuario=session.get("usuario"))


@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    msg = ok = None
    if request.method == "POST":
        ok, msg = servico.cadastrar(request.form.get("usuario", ""), request.form.get("senha", ""))
        if ok:
            return redirect(url_for("login"))
    return render_template("form.html", titulo="Cadastro", botao="Cadastrar", msg=msg, ok=ok)


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ok = None
    if request.method == "POST":
        ok, msg = servico.autenticar(request.form.get("usuario", ""), request.form.get("senha", ""))
        if ok:
            session.clear()                       # nova sessão após login
            session["usuario"] = request.form["usuario"].strip().casefold()
            return redirect(url_for("inicio"))
    return render_template("form.html", titulo="Login", botao="Entrar", msg=msg, ok=ok)


@app.route("/sair", methods=["POST"])
def sair():
    session.clear()
    return redirect(url_for("inicio"))


if __name__ == "__main__":
    # threaded=False: a conexão SQLite do ServicoAuth só pode ser usada na thread que a criou
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=False)   # debug desligado: sem console do Werkzeug
