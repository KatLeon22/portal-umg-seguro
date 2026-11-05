"""Fase I-C: Cross-Site Scripting (almacenado, reflejado y DOM)."""
import unittest

from tests.base import RAIZ, PruebaPortal

PAYLOAD = '<script>alert("XSS")</script><img src=x onerror=alert(1)>'


class TestXSS(PruebaPortal):
    def test_vulnerable_almacenado(self):
        self.post("/lab/comentarios", {"contenido": PAYLOAD})
        html = self.get("/lab/comentarios").get_data(as_text=True)
        print("\n[VULNERABLE] fragmento:", html[html.find("<li>"):html.find("<li>") + 90])
        self.assertIn('<script>alert("XSS")</script>', html)

    def test_vulnerable_reflejado(self):
        html = self.get("/lab/saludo", query_string={"nombre": PAYLOAD}).get_data(as_text=True)
        self.assertIn("<script>", html)

    def test_seguro_almacenado_codificado(self):
        self.login("ana.lopez@portal.test", "Estudiante#Lab2026")
        self.post("/comentarios", {"contenido": PAYLOAD})
        r = self.get("/comentarios")
        html = r.get_data(as_text=True)
        linea = [l for l in html.splitlines() if "XSS" in l][0].strip()
        print("\n[SEGURO] línea renderizada:", linea)
        self.assertNotIn("<script>alert", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;script&gt;alert(&#34;XSS&#34;)&lt;/script&gt;", html)

    def test_seguro_csp_defensa_en_profundidad(self):
        r = self.get("/login")
        csp = r.headers["Content-Security-Policy"]
        print("\n[SEGURO] CSP:", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)

    def test_dom_seguro_usa_textcontent(self):
        js = (RAIZ / "app/static/comentarios.js").read_text()
        self.assertIn("textContent", js)
        self.assertNotIn(".innerHTML", js)
        lab = (RAIZ / "app/templates/lab/dom.html").read_text()
        self.assertIn(".innerHTML", lab)   # el sumidero inseguro solo existe en el laboratorio


if __name__ == "__main__":
    unittest.main(verbosity=2)
