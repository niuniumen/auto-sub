#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
speedtest.py — 存活筛选 / 真实测速 (无人值守, 健壮, 限时)
阶段1: TCP 端口粗筛(高并发, 快速砍死节点)
阶段2: 用 Xray 起本地socks, 经节点访问 generate_204 测延迟 + 下载2MB测速度
        (xray 不支持的 hy2/tuic 仅按TCP可达保留)
输入: sub/all.txt
输出: sub/live.txt(按延迟升序TopN), sub/live.b64, sub/speed.stats.json
"""
import os, sys, json, time, socket, base64, threading, subprocess, urllib.parse as up
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUB  = os.path.join(ROOT, 'sub')
ISWIN= sys.platform.startswith('win')
def binpath(*p):
    d = os.path.join(ROOT, 'bin', *p)
    return d + '.exe' if ISWIN else d
XRAY = os.environ.get('XRAY_BIN') or binpath('xray','xray')
CURL = 'curl.exe' if ISWIN else 'curl'

# ---- 可调上限(保证 Actions 时长可控) ----
TCP_WORKERS   = 100
XRAY_WORKERS  = 15
MAX_XRAY_TEST = 360      # 最多实测节点数
TOPN          = 130      # live.txt 最多保留
EXTRA_HY      = 30       # hy2/tuic 仅TCP可达最多附带
TIME_BUDGET   = 720      # 总秒数硬上限
PING_URL      = 'http://www.gstatic.com/generate_204'
DL_URL        = 'https://speed.cloudflare.com/__down?bytes=2000000'

_port_lock = threading.Lock(); _next_port = 21000
def alloc_port():
    global _next_port
    with _port_lock:
        p = _next_port; _next_port += 1; return p
DEADLINE = time.time() + TIME_BUDGET

def parse_node(uri):
    try:
        s = uri.split('://',1); sch=s[0].lower(); rest=s[1]
        u = up.urlsplit(uri); q = {k:v[0] for k,v in up.parse_qs(u.query).items()}
        host=u.hostname; port=u.port
        return dict(sch=sch, host=host, port=port, user=u.username, pwd=u.password, q=q, raw=uri)
    except Exception:
        return None

# ---------- Xray 出站配置 ----------
def stream(n):
    q=n['q']; net=q.get('type') or q.get('network') or 'tcp'
    sec=q.get('security','')
    sni=q.get('sni') or q.get('peer') or ''
    st={'network':net,'security':('tls' if sec=='tls' else 'none')}
    if sec=='tls':
        st['tlsSettings']={'serverName':sni,'allowInsecure':bool(q.get('allowInsecure') in ('1','true')),
                           'fingerprint':'chrome'}
    if net=='ws':
        st['wsSettings']={'path':q.get('path','/'),'headers':{'Host':q.get('host','')}}
    elif net=='grpc':
        st['grpcSettings']={'serviceName':q.get('serviceName','')}
    return st

def xray_outbound(n):
    sch=n['sch']; srv={'address':n['host'],'port':n['port']}
    if sch=='vless':
        return [{'protocol':'vless','settings':{'vnext':[{'address':n['host'],'port':n['port'],
                'users':[{'id':n['user'],'encryption':'none'}]}]},'streamSettings':stream(n)}]
    if sch=='vmess':
        body=n['raw'].split('://',1)[1]
        if '@' not in body:  # 标准 vmess base64json
            j=json.loads(base64.b64decode(body+'='*(-len(body)%4)))
            nq=n['q']; n['host']=j.get('add'); n['port']=int(j.get('port')); n['user']=j.get('id')
            n['q']={'type':j.get('net','tcp'),'sni':j.get('tls')=='' and '' or j.get('host',''),
                    'host':j.get('host',''),'path':j.get('path','/'),
                    'security':'tls' if j.get('tls')=='tls' else ''}
            return [{'protocol':'vmess','settings':{'vnext':[{'address':n['host'],'port':n['port'],
                    'users':[{'id':n['user'],'alterId':int(j.get('aid',0)),'security':'auto'}]}]},
                    'streamSettings':stream(n)}]
        return [{'protocol':'vmess','settings':{'vnext':[{'address':n['host'],'port':n['port'],
                'users':[{'id':n['user'],'alterId':0,'security':'auto'}]}]},'streamSettings':stream(n)}]
    if sch=='trojan':
        return [{'protocol':'trojan','settings':{'servers':[{'address':n['host'],'port':n['port'],
                'password':up.unquote(n['user'] or '')}]},'streamSettings':stream(n)}]
    if sch=='ss':
        cred=n['user'] or ''
        try: cred=base64.b64decode(cred+'='*(-len(cred)%4)).decode()
        except Exception: pass
        if ':' in cred: method,pw=cred.split(':',1)
        else: method,pw='aes-256-gcm',cred
        return [{'protocol':'shadowsocks','settings':{'servers':[{'address':n['host'],'port':n['port'],
                'method':method,'password':pw}]}}]
    return None

def run_xray_test(n):
    if time.time() > DEADLINE: return None
    obs=xray_outbound(n)
    if not obs: return None
    port=alloc_port()
    cfg={'log':{'loglevel':'error'},
         'inbounds':[{'port':port,'listen':'127.0.0.1','protocol':'socks','settings':{'udp':True}}],
         'outbounds':obs}
    cf=os.path.join(ROOT,'bin',f'_t{port}.json'); open(cf,'w',encoding='utf-8').write(json.dumps(cfg))
    p=None
    try:
        kw={}
        if not ISWIN: kw['start_new_session']=True
        p=subprocess.Popen([XRAY,'-c',cf],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,**kw)
        time.sleep(1.1)
        sp=f'127.0.0.1:{port}'
        # 延迟
        r=subprocess.run([CURL,'-s','-o','/dev/null' if not ISWIN else 'NUL','-w','%{time_total}',
                          '--socks5-hostname',sp,'--max-time','6',PING_URL],
                         capture_output=True,text=True,timeout=10)
        lat=r.stdout.strip()
        if r.returncode!=0 or not lat: return None   # 必须真返回204
        lv=float(lat or 99)
        if lv<=0 or lv>=5.0: return None             # 5秒以上视为不可用
        # 下载2MB(带宽仅排序参考, 失败不淘汰)
        r2=subprocess.run([CURL,'-s','-o','NUL' if ISWIN else '/dev/null','-w','%{speed_download}',
                           '--socks5-hostname',sp,'--max-time','8',DL_URL],
                          capture_output=True,text=True,timeout=12)
        try: speed=float(r2.stdout.strip() or 0)/1024/1024
        except Exception: speed=0.0
        return {'uri':n['raw'],'lat':round(lv*1000),'speed':round(speed,2)}
    except Exception:
        return None
    finally:
        if p:
            try:
                if not ISWIN: os.killpg(os.getpgid(p.pid),9)
                else: p.kill()
            except Exception: pass
        try: os.remove(cf)
        except Exception: pass

def tcp_ok(n):
    try:
        with socket.create_connection((n['host'],n['port']),timeout=2.5): return True
    except Exception: return False

def main():
    t0=time.time()
    if not os.path.exists(XRAY):
        print('[警告] 未找到Xray内核:',XRAY,'-> 仅做TCP粗筛')
    uris=[l.strip() for l in open(os.path.join(SUB,'all.txt'),encoding='utf-8') if '://' in l]
    nodes=[x for x in (parse_node(u) for u in uris) if x and x['host'] and x['port']]
    print(f'读取节点 {len(nodes)}')
    # 阶段1 TCP
    tcp_pass=[]
    with ThreadPoolExecutor(TCP_WORKERS) as ex:
        futs={ex.submit(tcp_ok,n):n for n in nodes}
        for f in as_completed(futs):
            n=futs[f]
            try:
                if f.result(): tcp_pass.append(n)
            except Exception: pass
    print(f'TCP粗筛通过 {len(tcp_pass)}  耗时{time.time()-t0:.0f}s')
    # 拆分 xray系 / hy2-tuic
    xray_sch={'vless','vmess','trojan','ss'}
    xt=[n for n in tcp_pass if n['sch'] in xray_sch]
    hy=[n for n in tcp_pass if n['sch'] in ('hysteria2','hy2','tuic')]
    # CF段优先, 其余随机打散
    import random; random.seed(7); random.shuffle(xt)
    xt.sort(key=lambda n:0 if n['q'].get('security')=='tls' else 1)
    xt=xt[:MAX_XRAY_TEST]
    live=[]
    if os.path.exists(XRAY):
        with ThreadPoolExecutor(XRAY_WORKERS) as ex:
            futs=[ex.submit(run_xray_test,n) for n in xt]
            for f in as_completed(futs):
                try:
                    r=f.result()
                    if r: live.append(r)
                except Exception: pass
    print(f'Xray实测通过 {len(live)}  耗时{time.time()-t0:.0f}s')
    live.sort(key=lambda r:r['lat'])
    top=live[:TOPN]
    out=[r['uri'] for r in top]
    # hy2/tuic TCP可达附带
    for n in hy[:EXTRA_HY]: out.append(n['raw'])
    txt='\n'.join(out)+'\n'
    open(os.path.join(SUB,'live.txt'),'w',encoding='utf-8').write(txt)
    open(os.path.join(SUB,'live.b64'),'w',encoding='utf-8').write(base64.b64encode(txt.encode()).decode())
    stats={'ts':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'total':len(nodes),
           'tcp_pass':len(tcp_pass),'xray_tested':len(xt),'alive':len(live),'final':len(out),
           'cost_sec':round(time.time()-t0),
           'top10':[{'lat':r['lat'],'speed_MBs':r['speed']} for r in top[:10]]}
    json.dump(stats,open(os.path.join(SUB,'speed.stats.json'),'w',encoding='utf-8'),ensure_ascii=False,indent=2)
    print('==== speedtest 完成 ====');print(json.dumps(stats,ensure_ascii=False,indent=2))

if __name__=='__main__':
    main()
