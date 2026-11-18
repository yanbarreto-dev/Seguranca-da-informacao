"""Testes da camada web (Flask test client).  Executar: python -m unittest -v"""
import os
import re
import unittest

os.environ["DB_PATH"] = ":memory:"
import app as aplicacao  # noqa: E402

SENHA = "cavalo-bateria-grampo-2026"


class TestWeb(unittest.TestCase):
    def setUp(self):
        self.c = aplicacao.app.test_client()

    def _token(self, rota):
        html = self.c.get(rota).get_data(as_text=True)
        return re.search(r'name="csrf" value="([0-9a-f]+)"', html).group(1)

    def test_post_sem_csrf_e_rejeitado(self):
        r = self.c.post("/login", data={"usuario": "x", "senha": "y"})
        self.assertEqual(r.status_code, 400)

    def test_fluxo_cadastro_login_logout(self):
        t = self._token("/cadastro")
        r = self.c.post("/cadastro", data={"csrf": t, "usuario": "webuser", "senha": SENHA})
        self.assertEqual(r.status_code, 302)
        t = self._token("/login")
        r = self.c.post("/login", data={"csrf": t, "usuario": "webuser", "senha": SENHA})
        self.assertEqual(r.status_code, 302)
        self.assertIn("webuser", self.c.get("/").get_data(as_text=True))

    def test_login_invalido_mensagem_generica(self):
        t = self._token("/login")
        r = self.c.post("/login", data={"csrf": t, "usuario": "webuser", "senha": "errada-errada-1"})
        self.assertIn("Usuário ou senha inválidos", r.get_data(as_text=True))

    def test_cabecalhos_de_seguranca(self):
        r = self.c.get("/")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
