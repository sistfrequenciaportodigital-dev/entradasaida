#!/usr/bin/env python3
"""
Presença Inteligente — atualiza os hashes da Content-Security-Policy.

QUANDO USAR: sempre que alterar qualquer JavaScript escrito DENTRO do
index.html (os blocos <script> sem "src"). A CSP só deixa rodar o código
cuja "impressão digital" (hash SHA-256) está listada na tag cspMeta.
Se o código mudar e o hash não for renovado, o sistema para de funcionar
(aparece "Refused to execute inline script" no console, tecla F12).

COMO USAR:   python atualizar_csp.py              (usa ./index.html)
             python atualizar_csp.py caminho/do/arquivo.html
"""
import base64, hashlib, re, sys

caminho = sys.argv[1] if len(sys.argv) > 1 else 'index.html'
html = open(caminho, encoding='utf-8').read()

blocos = re.findall(r'(?m)^[ \t]*<script>(.*?)</script>', html, re.S)
if not blocos:
    sys.exit('Nenhum bloco <script> interno encontrado.')
hashes = ["'sha256-%s'" % base64.b64encode(hashlib.sha256(b.encode('utf-8')).digest()).decode()
          for b in blocos]

meta = re.search(r'(<meta http-equiv="Content-Security-Policy" id="cspMeta" content=")([^"]*)(")', html)
if not meta:
    sys.exit('Tag cspMeta não encontrada no arquivo.')
politica = meta.group(2)
m = re.search(r"script-src ((?:'sha256-[A-Za-z0-9+/=]+' ?)+)", politica)
if not m:
    sys.exit('Diretiva script-src com hashes não encontrada.')
nova = politica[:m.start(1)] + ' '.join(hashes) + ' ' + politica[m.end(1):]
nova = re.sub(r"  +", ' ', nova)

if nova == politica:
    print('Os hashes já estão corretos. Nada a alterar.')
else:
    html = html[:meta.start(2)] + nova + html[meta.end(2):]
    open(caminho, 'w', encoding='utf-8').write(html)
    print('CSP atualizada com %d hash(es):' % len(hashes))
    for h in hashes: print('  ' + h)
