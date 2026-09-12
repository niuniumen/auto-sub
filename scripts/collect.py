#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect.py — 多源抓取 / 多格式解析 / 指纹去重
纯标准库, 同时可在 GitHub Actions(Ubuntu) 与本地 Windows 运行。
输入: config/sources.txt
输出: sub/all.txt (去重URI, 每行一条), sub/all.b64, sub/collect.stats.json
"""
import os, re, sys, base64, json, time, urllib.request, urllib.error, socket

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC  = os.path.join(ROOT, 'config', 'sources.txt')
OUT  = os.path.join(ROOT, 'sub')
os.makedirs(OUT, exist_ok=True)

SCHEMES = r'(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|socks5?|https?)'
URI_RE  = re.compile(r'(?<![A-Za-z0-9])(' + SCHEMES + r')://[^\s"\'<>\\\]\)\},]+', re.I)
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) auto-sub/1.0'

# ---------- 抓取 ----------
def fetch(url, tries=2):
    last = None
    candidates = [url]
    if 'raw.githubusercontent.com' in url and '/main/' in url:
        candidates.append(url.replace('/main/', '/master/'))
    for u in candidates:
        for i in range(tries):
            try:
                req = urllib.request.Request(u, headers={'User-Agent': UA})
                with urllib.request.urlopen(req, timeout=25) as r:
                    return r.read()
            except Exception as e:
                last = e; time.sleep(1.5)
    raise last

# ---------- base64 容错解码 ----------
def b64try(s):
    t = s.strip().replace('-', '+').replace('_', '/')
    t += '=' * (-len(t) % 4)
    try:
        d = base64.b64decode(t)
        txt = d.decode('utf-8', 'ignore')
        if URI_RE.search(txt):
            return txt
    except Exception:
        pass
    return None

def deep_decode(raw_text):
    """原文 + 整体base64解码 + 逐行base64解码, 返回所有可能含URI的文本块"""
    blocks = [raw_text]
    whole = b64try(raw_text)
    if whole: blocks.append(whole)
    lines = []
    for ln in raw_text.splitlines():
        ln = ln.strip()
        if len(ln) > 24 and not '://' in ln:
            d = b64try(ln)
            if d: lines.append(d)
    if lines: blocks.append('\n'.join(lines))
    return '\n'.join(blocks)

# ---------- Clash YAML -> URI (尽力转换, 零依赖) ----------
def _kv(block, key):
    m = re.search(r'(?i)(?:^|[,{:\s])' + key + r'\s*:\s*("?)(.*?)\1\s*[,}]', block)
    return m.group(2).strip() if m else ''

def clash_to_uris(text):
    out = []
    if 'proxies:' not in text: return out
    body = text.split('proxies:', 1)[1]
    # 括号配平提取每个 "- {...}"
    i, n = 0, len(body)
    while i < n:
        if body[i] == '{':
            d = 0; j = i
            while j < n:
                if body[j] == '{': d += 1
                elif body[j] == '}':
                    d -= 1
                    if d == 0: break
                j += 1
            block = body[i:j+1]; i = j + 1
            try:
                typ = _kv(block, 'type').lower()
                server = _kv(block, 'server'); port = _kv(block, 'port')
                if not (server and port and typ): continue
                import urllib.parse as up
                q = {}
                net = _kv(block, 'network') or 'tcp'
                tls = _kv(block, 'tls').lower()
                sni = _kv(block, 'servername') or _kv(block, 'sni')
                if net: q['type'] = net
                if tls == 'true': q['security'] = 'tls'
                if sni: q['sni'] = sni
                path = _kv(block, 'path')
                if path: q['path'] = path
                host = _kv(block, 'host') or re.search(r'[Hh]ost:\s*"?([^",}]+)', block)
                if isinstance(host, re.Match): host = host.group(1)
                if host: q['host'] = host
                qs = up.urlencode(q, safe='/=:')
                if typ in ('vless',):
                    uid = _kv(block, 'uuid'); out.append(f'vless://{uid}@{server}:{port}?{qs}')
                elif typ == 'vmess':
                    uid = _kv(block, 'uuid'); out.append(f'vmess://{uid}@{server}:{port}?{qs}')
                elif typ == 'trojan':
                    pwd = _kv(block, 'password'); out.append(f'trojan://{pwd}@{server}:{port}?{qs}')
                elif typ in ('ss', 'shadowsocks'):
                    cipher = _kv(block, 'cipher'); pwd = _kv(block, 'password')
                    cred = base64.b64encode(f'{cipher}:{pwd}'.encode()).decode()
                    out.append(f'ss://{cred}@{server}:{port}')
                elif typ in ('hysteria2', 'hy2'):
                    pwd = _kv(block, 'password'); out.append(f'hysteria2://{pwd}@{server}:{port}?{qs}')
                elif typ == 'tuic':
                    uid = _kv(block, 'uuid'); pwd = _kv(block, 'password')
                    out.append(f'tuic://{uid}:{pwd}@{server}:{port}?{qs}')
            except Exception:
                continue
        else:
            i += 1
    return out

# ---------- 指纹去重 ----------
import urllib.parse as up
def is_private(host):
    if re.match(r'^(10\.|127\.|169\.254\.|192\.168\.|0\.|255\.)', host): return True
    m = re.match(r'^172\.(\d+)\.', host)
    if m and 16 <= int(m.group(1)) <= 31: return True
    if ':' in host and (host.startswith('fc') or host.startswith('fe80') or host=='::1'): return True
    return False

def fingerprint(uri):
    try:
        u = up.urlsplit(uri); sch = u.scheme.lower(); host = (u.hostname or '').lower()
        port = u.port or 0
        if not host or not port: return None
        if is_private(host): return None
        q = up.parse_qs(u.query)
        if sch == 'vmess':
            # vmess://base64json 形式
            body = u.netloc + (u.path or '')
            try:
                j = json.loads(base64.b64decode(body + '='*(-len(body)%4)))
                return '|'.join(['vmess', str(j.get('add','')).lower(), str(j.get('port')),
                                 str(j.get('id')), str(j.get('net')), str(j.get('host')), str(j.get('path'))])
            except Exception:
                pass
        ident = u.username or ''
        net = (q.get('type') or q.get('network') or ['tcp'])[0]
        sni = (q.get('sni') or q.get('peer') or q.get('servername') or [''])[0]
        path = u.path or (q.get('path') or [''])[0]
        return '|'.join([sch, host, str(port), ident, net, sni.lower(), path]).lower()
    except Exception:
        return None

def main():
    urls = []
    for ln in open(SRC, encoding='utf-8'):
        ln = ln.strip()
        if ln and not ln.startswith('#'): urls.append(ln)
    seen, kept, report = set(), [], []
    for url in urls:
        n0 = len(kept); err = ''
        try:
            raw = fetch(url)
            text = raw.decode('utf-8', 'ignore')
            text = deep_decode(text)
            uris = [m.group(0).rstrip('.,;') for m in URI_RE.finditer(text)]
            uris += clash_to_uris(text)
            add = 0
            for x in uris:
                fp = fingerprint(x)
                if fp and fp not in seen:
                    seen.add(fp); kept.append(x); add += 1
        except Exception as e:
            err = f'{type(e).__name__}: {e}'
        report.append((url, len(kept)-n0, err))
        print(f'[源] 新增{len(kept)-n0:5}  {url[:75]} {err}', flush=True)
    # 排序: 按协议分组
    order = {'vless':0,'vmess':1,'trojan':2,'ss':3,'hysteria2':4,'hy2':4,'tuic':5}
    def sk(x):
        s=x.split('://',1)[0].lower();return (order.get(s,9),x)
    kept.sort(key=sk)
    txt = '\n'.join(kept) + '\n'
    open(os.path.join(OUT,'all.txt'),'w',encoding='utf-8').write(txt)
    b64 = base64.b64encode(txt.encode()).decode()
    open(os.path.join(OUT,'all.b64'),'w',encoding='utf-8').write(b64)
    byproto = {}
    for x in kept: byproto[x.split('://',1)[0].lower()] = byproto.get(x.split('://',1)[0].lower(),0)+1
    stats = {'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
             'sources_total': len(urls), 'sources_ok': sum(1 for _,_,e in report if not e),
             'unique_nodes': len(kept), 'by_proto': byproto}
    json.dump(stats, open(os.path.join(OUT,'collect.stats.json'),'w',encoding='utf-8'), ensure_ascii=False, indent=2)
    with open(os.path.join(OUT,'sources.report.txt'),'w',encoding='utf-8') as f:
        for u,n,e in report: f.write(f'{n:5}  {u}  {e}\n')
    print('\n==== collect 完成 ====')
    print(json.dumps(stats, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
