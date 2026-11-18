"""Testes positivos e negativos da Entrega 2.  Executar: python -m unittest -v"""
import hashlib
import sqlite3
import unittest

import auth
from auth import ServicoAuth

SENHA = "cavalo-bateria-grampo-2026"


class TestHash(unittest.TestCase):
    def test_formato_phc_e_parametros(self):
        h = auth.gerar_hash(SENHA)
        self.assertTrue(h.startswith("$argon2id$v=19$m=47104,t=2,p=1$"))
        self.assertNotIn(SENHA, h)

    def test_salt_unico_mesmo_hash_diferente(self):
        self.assertNotEqual(auth.gerar_hash(SENHA), auth.gerar_hash(SENHA))

    def test_verificacao_correta_e_incorreta(self):
        h = auth.gerar_hash(SENHA)
        self.assertTrue(auth.verificar_hash(SENHA, h))
        self.assertFalse(auth.verificar_hash(SENHA + "x", h))
        self.assertFalse(auth.verificar_hash("", h))

    def test_hash_adulterado_ou_malformado_e_rejeitado(self):
        h = auth.gerar_hash(SENHA)
        ruim = h[:-3] + ("AAA" if not h.endswith("AAA") else "BBB")
        self.assertFalse(auth.verificar_hash(SENHA, ruim))
        self.assertFalse(auth.verificar_hash(SENHA, "lixo"))

    def test_unicode_normalizado(self):
        h = auth.gerar_hash("sênha-com-acento-1")                 # "ê" composto
        self.assertTrue(auth.verificar_hash("se\u0302nha-com-acento-1", h))  # "e" + acento

    def test_sha256_isolado_e_deterministico_e_sem_salt(self):
        # Demonstra o problema: mesma senha -> mesmo hash, sem custo e sem salt
        self.assertEqual(hashlib.sha256(SENHA.encode()).hexdigest(),
                         hashlib.sha256(SENHA.encode()).hexdigest())

    def test_rehash_quando_parametros_antigos(self):
        h = auth.gerar_hash(SENHA)
        self.assertFalse(auth.precisa_rehash(h))
        antigo = h.replace("m=47104", "m=19456")
        self.assertTrue(auth.precisa_rehash(antigo))


class TestPolitica(unittest.TestCase):
    def test_curta(self):
        self.assertFalse(auth.validar_senha("ana", "abc1234")[0])

    def test_longa_demais(self):
        self.assertFalse(auth.validar_senha("ana", "a" * 129)[0])

    def test_vazada(self):
        self.assertFalse(auth.validar_senha("ana", "Password1")[0])

    def test_igual_ao_usuario(self):
        self.assertFalse(auth.validar_senha("usuario_teste", "usuario_teste")[0])

    def test_sem_regra_de_composicao(self):
        # 6.2.5: só letras minúsculas é aceito se for longa e incomum
        self.assertTrue(auth.validar_senha("ana", "apenasminusculaslongas")[0])


class TestServico(unittest.TestCase):
    def setUp(self):
        self.s = ServicoAuth(":memory:")

    def test_cadastro_nao_guarda_senha_em_texto_puro(self):
        self.assertTrue(self.s.cadastrar("Maria", SENHA)[0])
        (h,) = self.s.db.execute("SELECT senha_hash FROM usuarios").fetchone()
        self.assertNotIn(SENHA, h)
        self.assertTrue(h.startswith("$argon2id$"))

    def test_login_correto(self):
        self.s.cadastrar("maria", SENHA)
        self.assertTrue(self.s.autenticar("MARIA ", SENHA)[0])

    def test_login_senha_errada(self):
        self.s.cadastrar("maria", SENHA)
        self.assertFalse(self.s.autenticar("maria", "senha-errada-123")[0])

    def test_mensagem_generica_usuario_inexistente_igual_senha_errada(self):
        self.s.cadastrar("maria", SENHA)
        a = self.s.autenticar("maria", "senha-errada-123")
        b = self.s.autenticar("ninguem", "senha-errada-123")
        self.assertEqual(a, b)

    def test_usuario_duplicado(self):
        self.assertTrue(self.s.cadastrar("maria", SENHA)[0])
        self.assertFalse(self.s.cadastrar("Maria", SENHA)[0])

    def test_bloqueio_apos_falhas_e_liberacao(self):
        self.s.cadastrar("maria", SENHA)
        t = 1000.0
        for _ in range(auth.MAX_FALHAS):
            self.s.autenticar("maria", "errada-errada-1", agora=t)
        ok, msg = self.s.autenticar("maria", SENHA, agora=t + 1)      # certa, mas bloqueado
        self.assertFalse(ok)
        self.assertIn("Muitas tentativas", msg)
        self.assertTrue(self.s.autenticar("maria", SENHA, agora=t + auth.BLOQUEIO_SEG + 1)[0])

    def test_injecao_sql_tratada_como_texto(self):
        self.s.cadastrar("maria", SENHA)
        self.assertFalse(self.s.autenticar("maria' OR '1'='1", "qualquer-coisa-1")[0])
        self.assertFalse(self.s.autenticar("maria", "' OR '1'='1")[0])
        (n,) = self.s.db.execute("SELECT COUNT(*) FROM usuarios").fetchone()
        self.assertEqual(n, 1)

    def test_rehash_transparente_no_login(self):
        # cria um hash legítimo com parâmetros antigos (m=19 MiB, t=2) e grava no banco
        self.s.cadastrar("maria", SENHA)
        salt = b"0123456789abcdef"
        h = auth._kdf(salt, 19456, 2, 1).derive(auth.normalizar(SENHA))
        antigo = f"$argon2id$v=19$m=19456,t=2,p=1${auth._b64(salt)}${auth._b64(h)}"
        self.s.db.execute("UPDATE usuarios SET senha_hash=?", (antigo,))
        self.assertTrue(auth.precisa_rehash(antigo))
        self.assertTrue(self.s.autenticar("maria", SENHA)[0])          # login funciona
        (novo,) = self.s.db.execute("SELECT senha_hash FROM usuarios").fetchone()
        self.assertIn("m=47104", novo)                                  # hash foi atualizado

    def test_parametro_adulterado_invalida_hash(self):
        self.s.cadastrar("maria", SENHA)
        (h,) = self.s.db.execute("SELECT senha_hash FROM usuarios").fetchone()
        self.s.db.execute("UPDATE usuarios SET senha_hash=?", (h.replace("m=47104", "m=19456"),))
        self.assertFalse(self.s.autenticar("maria", SENHA)[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
