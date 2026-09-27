#!/usr/bin/env python3
"""
Presença Inteligente — mantém a Content-Security-Policy e os lacres (SRI).

O QUE FAZ
  1. Hashes dos <script> internos: recalcula o SHA-256 de cada bloco <script>
     sem "src" e atualiza a diretiva script-src da tag cspMeta.
     Use SEMPRE que alterar JavaScript escrito dentro do index.html.
  2. Scripts externos: confere se cada <script src="https://..."> está
     liberado no script-src da CSP. Se faltar, inclui automaticamente.
  3. Com --sri: baixa cada script externo e calcula o SHA-384.
     - Script SEM lacre válido: o lacre é gravado no atributo integrity.
     - Script COM lacre: só confere. Se o arquivo do CDN mudou, o script PARA
       (pode ser adulteração) e não grava nada. Para aceitar mesmo assim
       (ex.: você trocou a versão de propósito), use --sri --forcar.
     Use SEMPRE antes do primeiro deploy da LGPD-V1 (SheetJS 0.20.3).
     Precisa de internet. Nada é gravado se algum download falhar.

COMO USAR
  python atualizar_csp.py                       (usa ./index.html)
  python atualizar_csp.py caminho/index.html
  python atualizar_csp.py --sri                 (também preenche/confere os lacres)
  python atualizar_csp.py --sri --forcar        (aceita lacre diferente do atual)
  python atualizar_csp.py --verificar           (só confere, não grava nada;
                                                 sai com erro se algo estiver
                                                 desatualizado — bom antes do deploy)

Se aparecer "Refused to execute inline script" ou "Failed to find a valid
digest in the 'integrity' attribute" no console (F12), rode este script.
"""
import base64, hashlib, re, sys, urllib.request

args = [a for a in sys.argv[1:] if not a.startswith('--')]
opcoes = {a for a in sys.argv[1:] if a.startswith('--')}
desconhecidas = opcoes - {'--sri', '--verificar', '--forcar'}
if desconhecidas:
    sys.exit('Opção desconhecida: ' + ', '.join(sorted(desconhecidas)))
FAZER_SRI = '--sri' in opcoes
SO_VERIFICAR = '--verificar' in opcoes
FORCAR = '--forcar' in opcoes
caminho = args[0] if args else 'index.html'

html = open(caminho, encoding='utf-8').read()
original = html
problemas = []

# ---------------------------------------------------------------- 1. inline
blocos = re.findall(r'(?m)^[ \t]*<script>(.*?)</script>', html, re.S)
if not blocos:
    sys.exit('Nenhum bloco <script> interno encontrado.')
hashes = ["'sha256-%s'" % base64.b64encode(hashlib.sha256(b.encode('utf-8')).digest()).decode()
          for b in blocos]

RE_META = r'(<meta http-equiv="Content-Security-Policy" id="cspMeta" content=")([^"]*)(")'
meta = re.search(RE_META, html)
if not meta:
    sys.exit('Tag cspMeta não encontrada no arquivo.')
politica = meta.group(2)
m = re.search(r"script-src ((?:'sha256-[A-Za-z0-9+/=]+' ?)+)", politica)
if not m:
    sys.exit('Diretiva script-src com hashes não encontrada.')
nova = politica[:m.start(1)] + ' '.join(hashes) + ' ' + politica[m.end(1):]
nova = re.sub(r"  +", ' ', nova)
if nova != politica:
    problemas.append('hashes dos scripts internos desatualizados')

# ---------------------------------------------------------------- 2. externos na CSP
tags = re.findall(r'<script\b[^>]*\bsrc="(https://[^"]+)"[^>]*>', html)
diretiva = re.search(r'script-src ([^;]*)', nova)
fontes = diretiva.group(1).split()
faltando = [u for u in tags if u not in fontes]
if faltando:
    problemas.append('script externo fora da CSP: ' + ', '.join(faltando))
    nova = nova[:diretiva.end(1)] + ' ' + ' '.join(faltando) + nova[diretiva.end(1):]

html = html[:meta.start(2)] + nova + html[meta.end(2):]

# ---------------------------------------------------------------- 3. SRI
def tag_do(url, texto):
    t = re.search(r'<script\b[^>]*\bsrc="' + re.escape(url) + r'"[^>]*>', texto)
    return t

for url in tags:
    t = tag_do(url, html)
    integ = re.search(r'\bintegrity="([^"]*)"', t.group(0))
    atual = integ.group(1) if integ else ''
    if not re.fullmatch(r'sha(256|384|512)-[A-Za-z0-9+/=]+', atual or ''):
        problemas.append('sem lacre válido: ' + url)

if FAZER_SRI and not SO_VERIFICAR:
    novos = {}
    for url in tags:
        print('Baixando', url)
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'atualizar_csp.py'})
            with urllib.request.urlopen(req, timeout=60) as r:
                if r.status != 200:
                    sys.exit('  ERRO: resposta %s. Nada foi gravado.' % r.status)
                corpo = r.read()
                cors = r.headers.get('Access-Control-Allow-Origin')
        except Exception as e:
            sys.exit('  ERRO ao baixar: %s. Nada foi gravado.' % e)
        if not cors:
            print('  ATENÇÃO: o servidor não enviou Access-Control-Allow-Origin. Com crossorigin="anonymous"'
                  ' o navegador pode bloquear este script. Alternativa: salvar o arquivo junto do index.html'
                  ' e usar o endereço local.')
        lacre = 'sha384-' + base64.b64encode(hashlib.sha384(corpo).digest()).decode()
        print('  %d bytes  %s' % (len(corpo), lacre))
        integ = re.search(r'\bintegrity="(sha384-[A-Za-z0-9+/=]+)"', tag_do(url, html).group(0))
        if integ and integ.group(1) != lacre and not FORCAR:
            sys.exit('  ERRO: o arquivo do CDN NÃO confere com o lacre atual (%s).\n'
                     '  Pode ser adulteração ou troca de versão. Nada foi gravado.\n'
                     '  Se você trocou a versão de propósito, rode com --sri --forcar.' % integ.group(1))
        if integ and integ.group(1) == lacre:
            print('  lacre confere.')
        novos[url] = lacre
    for url, lacre in novos.items():
        t = tag_do(url, html)
        velha = t.group(0)
        if re.search(r'\bintegrity="[^"]*"', velha):
            nova_tag = re.sub(r'\bintegrity="[^"]*"', 'integrity="%s"' % lacre, velha)
        else:
            nova_tag = velha[:-1] + ' integrity="%s">' % lacre
        if 'crossorigin=' not in nova_tag:
            nova_tag = nova_tag[:-1] + ' crossorigin="anonymous">'
        if nova_tag != velha:
            print('  lacre renovado:', url)
        html = html.replace(velha, nova_tag, 1)
    problemas = [p for p in problemas if not p.startswith('sem lacre válido')]

# ---------------------------------------------------------------- saída
if SO_VERIFICAR:
    if problemas:
        print('PENDÊNCIAS (nada foi gravado):')
        for p in problemas: print('  - ' + p)
        if any(p.startswith('sem lacre') for p in problemas):
            print('  → rode: python atualizar_csp.py --sri')
        sys.exit(1)
    print('Tudo em dia: CSP e lacres corretos.')
    sys.exit(0)

if html == original:
    print('Os hashes já estão corretos. Nada a alterar.')
else:
    open(caminho, 'w', encoding='utf-8').write(html)
    print('Arquivo atualizado. Hashes internos (%d):' % len(hashes))
    for h in hashes: print('  ' + h)
for p in problemas:
    if p.startswith('sem lacre válido'):
        print('ATENÇÃO — ' + p + '  → rode: python atualizar_csp.py --sri')
