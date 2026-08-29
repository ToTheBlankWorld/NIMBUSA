#!/usr/bin/env python3
"""
AVNI Cloud — control center.

Run bare:   avni            -> full-screen TUI
Or CLI:     avni <command>

  status                     host overview (gauges in TUI)
  services                   containers + status + domain
  domains                    domains + live HTTPS + cert expiry
  traffic [24h|7d|30d]       bandwidth charts (vnstat) + per-container net
  perdomain                  per-domain requests + bytes (needs access log)
  bans                       fail2ban jails + banned IPs
  attackers [N]              top N SSH brute-force IPs (+country)
  ipinfo <ip>                full intel on one IP (country/attempts/timeline/users)
  geo <ip>                   country of an IP
  ban|unban <ip> [jail]      temporary fail2ban ban/unban
  blacklist [add|del <x>]    PERMANENT firewall blacklist (ip|cidr|domain)
  whitelist                  fail2ban ignoreip
  ssh                        sshd policy + sessions(+country) + recent logins
  kick <ip|pts/N>            kill SSH session(s) by IP or tty
  users                      system users: sudo/live/locked/key/lastlogin
  accesslog status|on        Traefik per-domain access logging
Theme: AVNI ink #0e0a09 / cream #f2ddc0
"""
import curses, subprocess, shutil, re, json, os, sys, time, glob
from datetime import datetime

IFACE_DEFAULT = None
TRAEFIK = "appwrite-traefik"
ACCESS_LOG = "/var/log/traefik/access.log"
FW = "/root/avni-cloud-tui/avni-firewall.sh"
AUTH_LOGS = ["/var/log/auth.log", "/var/log/auth.log.1"]
_GEO = {}
BLOCKS = "▁▂▃▄▅▆▇█"

# --------------------------------------------------------------------------- shell
def sh(cmd, timeout=8):
    try: return subprocess.run(cmd.split(), capture_output=True, text=True, timeout=timeout).stdout.strip()
    except Exception: return ""
def shl(args, timeout=8):
    try: return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except Exception: return ""
def sh_raw(cmd, timeout=8):
    try: return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout).stdout
    except Exception: return ""
def has(t): return shutil.which(t) is not None

def iface():
    global IFACE_DEFAULT
    if IFACE_DEFAULT: return IFACE_DEFAULT
    m = re.search(r"default.* dev (\S+)", sh("ip route")); IFACE_DEFAULT = m.group(1) if m else "eth0"
    return IFACE_DEFAULT

def human(n):
    n=float(n)
    for u in ("B","K","M","G","T"):
        if n<1024: return f"{n:.0f}{u}" if u=="B" else f"{n:.1f}{u}"
        n/=1024
    return f"{n:.1f}P"

# --------------------------------------------------------------------------- charts (ascii)
def bar(val, mx, width, fill="█", empty="░"):
    if mx<=0: return empty*width
    f=int(round(width*min(val,mx)/mx)); return fill*f+empty*(width-f)
def spark(vals):
    if not vals: return ""
    mx=max(vals) or 1
    return "".join(BLOCKS[min(len(BLOCKS)-1,int((v/mx)*(len(BLOCKS)-1)))] for v in vals)

# --------------------------------------------------------------------------- geo / intel
def geo(ip):
    if ip in _GEO: return _GEO[ip]
    c="?"
    if has("geoiplookup"):
        out=sh(f"geoiplookup {ip}")
        m=re.search(r"GeoIP Country Edition:\s*[A-Z]{2},\s*(.+)", out)
        if m: c=m.group(1).strip()
        elif "not found" in out.lower() or "can't" in out.lower(): c="—"
    _GEO[ip]=c; return c

def ts_of(line):
    m=re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
    if m: return m.group(1).replace("T"," ")
    m=re.match(r"([A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})", line)
    return m.group(1) if m else "?"

def ip_intel(ip):
    cnt=0; first=last=None; users={}
    ipre=re.compile(re.escape(ip))
    ure=re.compile(r"(?:Invalid user|user)\s+([A-Za-z0-9._-]+)")
    for f in AUTH_LOGS:
        if not os.path.exists(f): continue
        try:
            with open(f, errors="ignore") as fh:
                for line in fh:
                    if ipre.search(line) and re.search(r"Failed|Invalid|authenticating|closed by|Disconnect", line):
                        cnt+=1; t=ts_of(line)
                        if first is None or t<first: first=t
                        if last is None or t>last: last=t
                        mu=ure.search(line)
                        if mu: users[mu.group(1)]=users.get(mu.group(1),0)+1
        except Exception: pass
    banned = any(ip in f2b_status(j)["ips"] for j in f2b_jails())
    bl = subprocess.run(["ipset","test","avni_blacklist",ip],capture_output=True).returncode==0
    org=""
    if has("whois"):
        w=sh(f"whois {ip}",10)
        mo=re.search(r"(?:OrgName|org-name|netname|descr):\s*(.+)", w, re.I)
        if mo: org=mo.group(1).strip()
    topu=sorted(users.items(),key=lambda x:-x[1])[:6]
    return {"ip":ip,"country":geo(ip),"attempts":cnt,"first":first or "—","last":last or "—",
            "users":topu,"banned":banned,"blacklisted":bl,"org":org}

# --------------------------------------------------------------------------- docker / services
def overview():
    mem=next((l for l in sh_raw("free -m").splitlines() if l.lower().startswith("mem")),"").split()
    mtot,mused,mavail=(int(mem[1]),int(mem[2]),int(mem[-1])) if len(mem)>=7 else (0,0,0)
    d=sh("df -h /").splitlines(); dl=d[1].split() if len(d)>1 else [""]*6
    du=sh("df / ").splitlines(); dpct=du[1].split()[4] if len(du)>1 else "0%"
    load=open("/proc/loadavg").read().split()[:3]
    return {"host":sh("hostname"),"ip":(sh("curl -s -m4 https://api.ipify.org") or ""),
            "os":sh_raw(". /etc/os-release; echo $PRETTY_NAME").strip(),"kernel":sh("uname -r"),
            "uptime":sh("uptime -p"),"load":load,"ncpu":os.cpu_count() or 1,
            "mem_total":mtot,"mem_used":mused,"mem_avail":mavail,
            "disk_size":dl[1],"disk_used":dl[2],"disk_avail":dl[3],"disk_pct":dl[4]}

def traefik_domains():
    out={}; ids=sh("docker ps -q").split()
    if not ids: return out
    try: data=json.loads(shl(["docker","inspect"]+ids,15) or "[]")
    except Exception: return out
    for c in data:
        name=c.get("Name","").lstrip("/"); labels=(c.get("Config",{}) or {}).get("Labels",{}) or {}
        for k,v in labels.items():
            if k.endswith(".rule") and "Host(" in v:
                for d in re.findall(r"Host\(`([^`]+)`\)",v): out.setdefault(d,name)
    return out

def services():
    rows=[]
    out=shl(["docker","ps","-a","--format","{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"],12)
    for line in out.splitlines():
        p=line.split("\t")
        if len(p)<3: continue
        rows.append({"name":p[0],"image":p[1],"status":p[2],"ports":p[3] if len(p)>3 else ""})
    c2d={}
    for d,c in traefik_domains().items(): c2d.setdefault(c,[]).append(d)
    for r in rows: r["domain"]=",".join(c2d.get(r["name"],[]))
    return rows

def docker_net():
    rows=[]
    for line in shl(["docker","stats","--no-stream","--format","{{.Name}}\t{{.NetIO}}\t{{.CPUPerc}}"],20).splitlines():
        p=line.split("\t")
        if len(p)>=2: rows.append({"name":p[0],"net":p[1],"cpu":p[2] if len(p)>2 else ""})
    return rows

def cert_expiry(domain):
    out=sh_raw(f"echo | timeout 6 openssl s_client -servername {domain} -connect {domain}:443 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null")
    m=re.search(r"notAfter=(.+)",out); return m.group(1).strip() if m else "?"

# --------------------------------------------------------------------------- fail2ban / blacklist
def f2b_jails():
    m=re.search(r"Jail list:\s*(.*)",sh("fail2ban-client status"))
    return [j.strip() for j in m.group(1).split(",")] if m and m.group(1).strip() else []
def f2b_status(jail):
    out=sh(f"fail2ban-client status {jail}")
    g=lambda p,d="0":(re.search(p,out).group(1) if re.search(p,out) else d)
    ips=re.search(r"Banned IP list:\s*(.*)",out)
    return {"failed":g(r"Currently failed:\s*(\d+)"),"banned":g(r"Currently banned:\s*(\d+)"),
            "total":g(r"Total banned:\s*(\d+)"),"ips":ips.group(1).split() if ips and ips.group(1).strip() else []}
def f2b_banned_all():
    return [{"jail":j,"ip":ip} for j in f2b_jails() for ip in f2b_status(j)["ips"]]
def f2b_ignoreip(jail="sshd"): return sh(f"fail2ban-client get {jail} ignoreip")
def ban(ip,jail="sshd"): return sh(f"fail2ban-client set {jail} banip {ip}")
def unban(ip,jail="sshd"): return sh(f"fail2ban-client set {jail} unbanip {ip}")

def blacklist_list(): return [x for x in sh(f"bash {FW} list").splitlines() if x.strip()]
def blacklist_add(x): return sh(f"bash {FW} add {x}",15)
def blacklist_del(x): return sh(f"bash {FW} del {x}",15)
def blacklist_count():
    try: return int(sh(f"bash {FW} count") or "0")
    except Exception: return 0

def attackers(n=15):
    counts={}
    pat=re.compile(r"(Failed password|Invalid user|authenticating user|Connection closed by|Disconnected from invalid)")
    ipre=re.compile(r"(\d{1,3}\.){3}\d{1,3}")
    for f in AUTH_LOGS:
        if not os.path.exists(f): continue
        try:
            with open(f,errors="ignore") as fh:
                for line in fh:
                    if pat.search(line):
                        m=ipre.search(line)
                        if m: counts[m.group(0)]=counts.get(m.group(0),0)+1
        except Exception: pass
    return [{"ip":ip,"count":c} for ip,c in sorted(counts.items(),key=lambda x:-x[1])[:n]]

def whois_ip(ip):
    if not has("whois"): return "install: apt-get install -y whois"
    keep=[l for l in sh(f"whois {ip}",10).splitlines() if re.match(r"^\s*(country|orgname|org-name|netname|descr|inetnum):",l,re.I)]
    return "\n".join(keep[:8]) or "(no whois data)"

# --------------------------------------------------------------------------- IP registry (CrowdSec-style decisions store)
REG_PATH="/var/lib/avni/ips.json"
def registry_load():
    try: return json.load(open(REG_PATH))
    except Exception: return {}
def registry_save(d):
    os.makedirs("/var/lib/avni",exist_ok=True)
    try: json.dump(d,open(REG_PATH,"w"))
    except Exception: pass
def registry_ips(reg): return [(i,e) for i,e in reg.items() if not i.startswith("_")]

def _scan_authlogs(offsets):
    """Read only NEW lines since last byte-offset (keyed by inode) -> fast."""
    att={}; fs={}; ls={}; users={}; new=dict(offsets)
    pat=re.compile(r"(Failed password|Invalid user|authenticating|closed by|Disconnect)")
    ipre=re.compile(r"(\d{1,3}\.){3}\d{1,3}"); ure=re.compile(r"(?:Invalid user|user)\s+([A-Za-z0-9._-]+)")
    for f in AUTH_LOGS:
        if not os.path.exists(f): continue
        try:
            st=os.stat(f); ino=str(st.st_ino); start=offsets.get(ino,0)
            if start>st.st_size: start=0   # rotated/truncated
            with open(f,errors="ignore") as fh:
                fh.seek(start)
                for line in fh:
                    if not pat.search(line): continue
                    m=ipre.search(line)
                    if not m: continue
                    ip=m.group(0); t=ts_of(line); att[ip]=att.get(ip,0)+1
                    if ip not in fs or t<fs[ip]: fs[ip]=t
                    if ip not in ls or t>ls[ip]: ls[ip]=t
                    mu=ure.search(line)
                    if mu: users[ip]=mu.group(1)
                new[ino]=fh.tell()
        except Exception: pass
    return att,fs,ls,users,new

def registry_update(full=False):
    """Incremental: only reads log bytes appended since last run. The persistent
    store keeps every IP forever (even after logs rotate)."""
    reg=registry_load(); now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    meta=reg.get("_meta",{}); offsets={} if full else meta.get("offsets",{})
    if "_meta" not in reg and registry_ips(reg) and not full:
        # pre-incremental store already has counts: mark EOF, go incremental forward
        for f in AUTH_LOGS:
            if os.path.exists(f): offsets[str(os.stat(f).st_ino)]=os.stat(f).st_size
        att,fs,ls,users=({},{},{},{})
    else:
        att,fs,ls,users,offsets=_scan_authlogs(offsets)
    ipre=re.compile(r"(\d{1,3}\.){3}\d{1,3}")
    logins={}
    for line in sh("last -i -n 300").splitlines():
        p=line.split()
        if len(p)>=3 and ipre.fullmatch(p[2] or ""): logins[p[2]]=logins.get(p[2],0)+1
    banned=set()
    for j in f2b_jails(): banned|=set(f2b_status(j)["ips"])
    bl=set(blacklist_list())
    for ip in set(att)|set(logins)|{i for i,_ in registry_ips(reg)}|banned|bl:
        e=reg.get(ip,{})
        e["country"]=e.get("country") or geo(ip)
        e["attempts"]=e.get("attempts",0)+att.get(ip,0)
        if ip in fs: e["first"]=min(e.get("first",fs[ip]),fs[ip])
        if ip in ls: e["last"]=max(e.get("last",""),ls[ip])
        e["logins"]=max(e.get("logins",0),logins.get(ip,0))
        e["banned"]=ip in banned; e["blacklisted"]=ip in bl
        if ip in users: e["last_user"]=users[ip]
        e.setdefault("first",now); e.setdefault("last",now)
        reg[ip]=e
    reg["_meta"]={"offsets":offsets,"updated":now}
    registry_save(reg); return reg

def _recent(ts, hours=24):
    try: return (datetime.now()-datetime.strptime(ts,"%Y-%m-%d %H:%M:%S")).total_seconds() < hours*3600
    except Exception: return False

def registry_filter(reg, which):
    v=list(reg.items())
    if which=="Attackers": v=[(i,e) for i,e in v if e.get("attempts",0)>0 and not e.get("logins")]
    elif which=="Banned":   v=[(i,e) for i,e in v if e.get("banned") or e.get("blacklisted")]
    elif which=="Unbanned": v=[(i,e) for i,e in v if (e.get("attempts",0)>0) and not e.get("banned") and not e.get("blacklisted")]
    elif which=="New":      v=[(i,e) for i,e in v if _recent(e.get("first",""))]
    elif which=="Logins":   v=[(i,e) for i,e in v if e.get("logins",0)>0]
    key={"Attackers":"attempts","Logins":"logins"}.get(which)
    v.sort(key=lambda x:-(x[1].get(key,0)) if key else x[1].get("last",""), reverse=bool(not key))
    if key: v.sort(key=lambda x:-x[1].get(key,0))
    return v

# --------------------------------------------------------------------------- ssh / users
def ssh_sessions():
    s=[]
    for line in sh("who").splitlines():
        p=line.split()
        if len(p)>=5:
            frm=p[-1].strip("()")
            s.append({"user":p[0],"tty":p[1],"from":frm,"country":geo(frm) if re.match(r"\d+\.\d+\.\d+\.\d+",frm) else "local","since":" ".join(p[2:4])})
    return s
def ssh_info():
    t=sh("sshd -T",6)
    g=lambda k:next((l.split(None,1)[1] for l in t.splitlines() if l.lower().startswith(k)),"?")
    recent=[l for l in sh("last -a -n 14").splitlines() if l.strip() and not l.startswith("wtmp")]
    return {"PermitRootLogin":g("permitrootlogin"),"PasswordAuthentication":g("passwordauthentication"),
            "PubkeyAuthentication":g("pubkeyauthentication"),"Port":g("port"),
            "sessions":ssh_sessions(),"recent":recent[:12],"attacker_ips":len(attackers(99999))}

def my_tty():
    try: return os.ttyname(sys.stdin.fileno()).replace("/dev/","")
    except Exception: return ""
def my_ip(): return os.environ.get("SSH_CLIENT","").split()[0] if os.environ.get("SSH_CLIENT") else ""

def kick_tty(tty):
    if tty==my_tty(): return "refused: that is YOUR session"
    subprocess.run(["pkill","-KILL","-t",tty]); return f"kicked session {tty}"
def kick_ip(ip):
    if ip==my_ip(): return "refused: that is YOUR IP"
    killed=[]
    for s in ssh_sessions():
        if s["from"]==ip and s["tty"]!=my_tty():
            subprocess.run(["pkill","-KILL","-t",s["tty"]]); killed.append(s["tty"])
    return f"kicked {ip}: "+(", ".join(killed) if killed else "no live session")

def users_list():
    sudoers=set()
    for grp in ("sudo","admin","wheel"):
        m=sh(f"getent group {grp}")
        if m and ":" in m: sudoers|=set(filter(None,m.split(":")[-1].split(",")))
    live={}
    for line in sh("who").splitlines():
        u=line.split()[0] if line.split() else ""
        live[u]=live.get(u,0)+1
    rows=[]
    for line in sh("getent passwd").splitlines():
        p=line.split(":")
        if len(p)<7: continue
        name,uid,home,shell=p[0],int(p[2]),p[5],p[6]
        if not(uid==0 or uid>=1000) or name=="nobody" or shell.endswith(("nologin","false")): continue
        ll=sh(f"lastlog -u {name}").splitlines()
        last=ll[1].split(None,3)[-1] if len(ll)>1 and "Never" not in ll[1] else "Never"
        locked="L" in (sh(f"passwd -S {name}").split()[1:2] or [""])[0]
        rows.append({"user":name,"uid":uid,"sudo":name in sudoers or uid==0,"shell":shell,
                     "lastlogin":last,"locked":locked,"key":os.path.exists(f"{home}/.ssh/authorized_keys"),
                     "live":live.get(name,0),"groups":sh(f"id -nG {name}")})
    return rows

# --------------------------------------------------------------------------- traffic series
def vnstat_series(mode):
    flag={"24h":"h","7d":"d","30d":"d"}.get(mode,"d")
    try: j=json.loads(sh_raw(f"vnstat --json {flag} -i {iface()}",8) or "{}")
    except Exception: j={}
    out=[]
    try:
        node=j["interfaces"][0]["traffic"]
        arr=node.get("hour") or node.get("hours") or node.get("day") or node.get("days") or []
        for e in arr[-(24 if mode=="24h" else (7 if mode=="7d" else 30)):]:
            d=e.get("date",{}); lab=(f"{d.get('hour',e.get('time',{}).get('hour','')):>2}h" if mode=="24h"
                 else f"{d.get('month','')}/{d.get('day','')}")
            out.append({"label":lab,"rx":e.get("rx",0),"tx":e.get("tx",0)})
    except Exception: pass
    return out
def vnstat_oneline():
    p=sh(f"vnstat --oneline -i {iface()}").split(";")
    return {"today":p[5],"rx":p[3],"tx":p[4],"rate":p[6],"month":p[10],"all":p[13]} if len(p)>=14 else {}

# --------------------------------------------------------------------------- access log
def accesslog_status():
    on="accesslog" in sh(f"docker inspect {TRAEFIK} --format "+"{{json .Args}}").lower()
    return {"enabled":on,"logfile":os.path.exists(ACCESS_LOG)}
def perdomain():
    if not os.path.exists(ACCESS_LOG): return None
    reqs,byts={},{}
    try:
        with open(ACCESS_LOG,errors="ignore") as fh:
            for line in fh:
                try: jj=json.loads(line)
                except Exception: continue
                h=jj.get("RequestHost","?"); reqs[h]=reqs.get(h,0)+1; byts[h]=byts.get(h,0)+int(jj.get("DownstreamContentSize",0) or 0)
    except Exception: return None
    return sorted([{"domain":d,"reqs":reqs[d],"bytes":byts.get(d,0)} for d in reqs],key=lambda x:-x["reqs"])

# =========================================================================== CLI
def cli(argv):
    cmd=argv[0] if argv else "status"; a=argv[1:]
    if cmd in("status","overview"):
        o=overview(); svc=services(); up=sum(1 for s in svc if s["status"].startswith("Up"))
        print(f"AVNI Cloud — {o['host']} ({o['ip']})")
        print(f"  OS {o['os']} · kernel {o['kernel']}")
        print(f"  Uptime {o['uptime']} · Load {' '.join(o['load'])} (cpus {o['ncpu']})")
        print(f"  RAM {o['mem_used']}/{o['mem_total']}MB · Disk {o['disk_used']}/{o['disk_size']} ({o['disk_pct']})")
        print(f"  Services {up}/{len(svc)} up · Domains {len(traefik_domains())} · Banned {f2b_status('sshd')['banned']} · Blacklist {blacklist_count()}")
    elif cmd=="services":
        for s in services():
            print(f"  {'●' if s['status'].startswith('Up') else '○'} {s['name']:<34}{s['status']:<26}{s['domain']}")
    elif cmd=="domains":
        for d,c in sorted(traefik_domains().items()):
            print(f"  {d:<32} HTTP {sh(f'curl -s -m8 -o /dev/null -w %{{http_code}} https://{d}/'):<4} cert:{cert_expiry(d):<22} -> {c}")
    elif cmd=="traffic":
        win=a[0] if a else "7d"; ol=vnstat_oneline()
        print(f"  today {ol.get('today','?')} (rx {ol.get('rx','')}/tx {ol.get('tx','')}) rate {ol.get('rate','')} · month {ol.get('month','')}")
        for e in vnstat_series(win):
            tot=e["rx"]+e["tx"]; print(f"  {e['label']:>6} {human(tot):>8} {bar(tot,max((x['rx']+x['tx']) for x in vnstat_series(win)),30)}")
        print("  per-container:"); [print(f"    {r['name']:<32}{r['net']}") for r in docker_net()]
    elif cmd=="perdomain":
        rows=perdomain()
        if rows is None: print("  needs access log — run: avni accesslog on")
        else:
            for r in rows: print(f"  {r['domain']:<32}{r['reqs']:>9} req {human(r['bytes']):>9}")
    elif cmd=="bans":
        for j in f2b_jails():
            s=f2b_status(j); print(f"  [{j}] banned={s['banned']} total={s['total']}")
            for ip in s["ips"]: print(f"      {ip:<18}{geo(ip)}")
    elif cmd=="attackers":
        n=int(a[0]) if a and a[0].isdigit() else 15; rows=attackers(n); mx=rows[0]["count"] if rows else 1
        for r in rows: print(f"  {r['count']:>7} {r['ip']:<17}{geo(r['ip']):<16}{bar(r['count'],mx,24)}")
    elif cmd=="ipinfo":
        if not a: sys.exit("usage: avni ipinfo <ip>")
        d=ip_intel(a[0])
        print(f"  IP {d['ip']}  ({d['country']})")
        print(f"  attempts {d['attempts']} · first {d['first']} · last {d['last']}")
        print(f"  banned={d['banned']} blacklisted={d['blacklisted']} org={d['org']}")
        print(f"  usernames tried: "+", ".join(f"{u}({c})" for u,c in d['users']))
    elif cmd=="ips":
        which=a[0].capitalize() if a else "All"
        reg=registry_update(); rows=registry_filter(reg,which) if which!="All" else sorted(reg.items(),key=lambda x:-x[1].get("attempts",0))
        print(f"  {which}: {len(rows)} IPs   (total tracked: {len(reg)})")
        print(f"  {'IP':<16}{'COUNTRY':<14}{'ATT':>7}{'LOGIN':>6}  STATUS     LAST")
        for ip,e in rows[:60]:
            st="BLACKLIST" if e.get("blacklisted") else ("BANNED" if e.get("banned") else ("login" if e.get("logins") else "seen"))
            print(f"  {ip:<16}{(e.get('country','?') or '?')[:13]:<14}{e.get('attempts',0):>7}{e.get('logins',0):>6}  {st:<10} {e.get('last','')}")
    elif cmd=="geo": print(geo(a[0]) if a else "usage: avni geo <ip>")
    elif cmd=="ban": print(ban(a[0],a[1] if len(a)>1 else "sshd"),"banned",a[0]) if a else sys.exit("usage")
    elif cmd=="unban": print(unban(a[0],a[1] if len(a)>1 else "sshd"),"unbanned",a[0]) if a else sys.exit("usage")
    elif cmd=="blacklist":
        if not a: [print("  "+x+"  "+geo(x.split('/')[0])) for x in blacklist_list()] or (print("  (empty)") if not blacklist_list() else None)
        elif a[0]=="add" and len(a)>1: print(blacklist_add(a[1]))
        elif a[0]=="del" and len(a)>1: print(blacklist_del(a[1]))
        else: print("usage: avni blacklist [add|del <ip|cidr|domain>]")
    elif cmd=="whitelist": [print(f"  [{j}] {f2b_ignoreip(j)}") for j in f2b_jails()]
    elif cmd=="whois": print(whois_ip(a[0]) if a else "usage: avni whois <ip>")
    elif cmd=="ssh":
        s=ssh_info()
        print(f"  PermitRootLogin={s['PermitRootLogin']} PasswordAuth={s['PasswordAuthentication']} Pubkey={s['PubkeyAuthentication']} Port={s['Port']}")
        print(f"  attacker IPs in auth.log: {s['attacker_ips']}"); print("  live sessions:")
        for x in s["sessions"]: print(f"    {x['user']}@{x['tty']:<8} {x['from']:<16}({x['country']}) since {x['since']}")
        print("  recent:"); [print("    "+r) for r in s["recent"]]
    elif cmd=="kick": print(kick_ip(a[0]) if a and re.match(r"\d+\.\d+\.\d+\.\d+",a[0]) else (kick_tty(a[0]) if a else "usage: avni kick <ip|pts/N>"))
    elif cmd=="users":
        print(f"  {'USER':<12}{'UID':>5} SUDO LIVE LOCK KEY  LASTLOGIN")
        for u in users_list():
            print(f"  {u['user']:<12}{u['uid']:>5} {'yes ' if u['sudo'] else '-   '} {u['live']:>3}  {'L' if u['locked'] else '-'}   {'y' if u['key'] else 'n'}   {u['lastlogin']}")
    elif cmd=="accesslog": accesslog_cmd(a[0] if a else "status")
    else: print(__doc__)

def accesslog_cmd(sub):
    st=accesslog_status()
    if sub=="status": print(f"  enabled={st['enabled']} logfile={st['logfile']} path={ACCESS_LOG}"); return
    print("  Enable per-domain stats (recreates the Appwrite Traefik ingress):")
    print("   1) /root/appwrite/docker-compose.yml traefik command, add:")
    print("        - --accesslog=true\n        - --accesslog.filepath=/var/log/traefik/access.log\n        - --accesslog.format=json")
    print("      volumes: - /var/log/traefik:/var/log/traefik")
    print("   2) cd /root/appwrite && docker compose up -d traefik    3) avni perdomain")

# =========================================================================== TUI
SECTIONS=["Overview","Services","Domains","Traffic","Security","SSH","Users"]
def init_colors():
    curses.start_color(); curses.use_default_colors()
    C=lambda n,f:curses.init_pair(n,f if curses.COLORS>=256 else f%8,-1)
    cream=223 if curses.COLORS>=256 else 3
    curses.init_pair(1,cream,-1); curses.init_pair(2,234 if curses.COLORS>=256 else 0,cream)
    curses.init_pair(3,71 if curses.COLORS>=256 else 2,-1); curses.init_pair(4,203 if curses.COLORS>=256 else 1,-1)
    curses.init_pair(5,245 if curses.COLORS>=256 else 7,-1); curses.init_pair(6,curses.COLOR_WHITE,-1)
    curses.init_pair(7,214 if curses.COLORS>=256 else 3,-1); curses.init_pair(8,110 if curses.COLORS>=256 else 6,-1)

class TUI:
    def __init__(self,scr):
        self.scr=scr; self.sec=0; self.sel=0; self.tw=0
        self.msg="Tab/←→ sections · ↑↓ select · Enter detail · keys in footer · q quit"; self.cache={}
    def data(self,k,fn,ttl=4):
        now=time.time()
        if k not in self.cache or now-self.cache[k][0]>ttl:
            try: self.cache[k]=(now,fn())
            except Exception: self.cache[k]=(now,[])
        return self.cache[k][1]
    def rows(self):
        s=SECTIONS[self.sec]
        if s=="Services": return [(svc_line(r),r) for r in self.data("svc",services)]
        if s=="Domains":  return [(d,{"domain":d,"cont":c}) for d,c in sorted(self.data("dom",traefik_domains,8).items())]
        if s=="Security": return self.sec_rows()
        if s=="SSH":      return [(None,x) for x in self.data("ssh",ssh_info,5)["sessions"]]
        if s=="Users":    return [(None,u) for u in self.data("usr",users_list,10)]
        return []
    def sec_rows(self):
        atk=self.data("atk",lambda:attackers(14),12); mx=atk[0]["count"] if atk else 1
        rows=[]
        for r in atk:
            rows.append((None,{"kind":"atk","ip":r["ip"],"count":r["count"],"mx":mx}))
        return rows
    def clampsel(self,n): self.sel=max(0,min(self.sel,n-1)) if n else 0

    def draw(self):
        scr=self.scr; scr.erase(); h,w=scr.getmaxyx()
        scr.attron(curses.color_pair(2)); scr.addstr(0,0," "*(w-1))
        scr.addstr(0,1,"AVNI CLOUD · control center"[:w-2]); scr.attroff(curses.color_pair(2))
        clk=datetime.now().strftime("%H:%M:%S")
        if w>12: scr.addstr(0,w-len(clk)-1,clk,curses.color_pair(1))
        x=0
        for i,s in enumerate(SECTIONS):
            lab=f" {i+1}.{s} "
            if x+len(lab)>=w: break
            scr.addstr(1,x,lab,curses.color_pair(2) if i==self.sec else curses.color_pair(5)); x+=len(lab)
        scr.hline(2,0,curses.ACS_HLINE,w-1)
        try: self.body(scr,3,h-2,w)
        except Exception as e: scr.addstr(4,2,f"(render: {e})"[:w-3],curses.color_pair(4))
        scr.attron(curses.color_pair(2)); scr.addstr(h-1,0," "*(w-1))
        scr.addstr(h-1,1,self.msg[:max(0,w-22)]); scr.attroff(curses.color_pair(2))
        foot=self.footer()
        if w>len(foot)+2: scr.addstr(h-1,w-len(foot)-1,foot,curses.color_pair(2))
        scr.refresh()

    def gauge(self,scr,y,x,label,used,total,w,unit=""):
        pct=(used/total) if total else 0
        col=3 if pct<0.7 else (7 if pct<0.9 else 4)
        scr.addstr(y,x,f"{label:<8}",curses.color_pair(1))
        bw=max(8,w-30); b=bar(used,total,bw)
        fill=int(round(bw*min(pct,1)))
        scr.addstr(y,x+9,b[:fill],curses.color_pair(col)); scr.addstr(y,x+9+fill,b[fill:],curses.color_pair(5))
        scr.addstr(y,x+10+bw,f"{pct*100:4.0f}% {used}/{total}{unit}"[:24],curses.color_pair(6))

    def body(self,scr,top,bot,w):
        s=SECTIONS[self.sec]
        if s=="Overview": return self.b_overview(scr,top,bot,w)
        if s=="Traffic":  return self.b_traffic(scr,top,bot,w)
        if s=="SSH":      return self.b_ssh(scr,top,bot,w)
        if s=="Users":    return self.b_users(scr,top,bot,w)
        if s=="Security": return self.b_security(scr,top,bot,w)
        rows=self.rows(); self.clampsel(len(rows))
        if not rows: scr.addstr(top+1,2,"(nothing)",curses.color_pair(5)); return
        view=bot-top-1; start=max(0,self.sel-view+1)
        for i,(line,obj) in enumerate(rows[start:start+view]):
            idx=start+i; y=top+1+i; txt=line if line else str(obj)
            if SECTIONS[self.sec]=="Domains": txt=f"{obj['domain']:<34} → {obj['cont']}"
            scr.addstr(y,2,(txt[:w-4]).ljust(w-4) if idx==self.sel else txt[:w-4],
                       curses.color_pair(2) if idx==self.sel else color_for(txt))

    def b_overview(self,scr,top,bot,w):
        o=self.data("ov",overview,5); svc=self.data("svc",services); up=sum(1 for x in svc if x["status"].startswith("Up"))
        ol=self.data("vol",vnstat_oneline,6)
        info=[("Host",f"{o['host']}  {o['ip']}"),("OS",f"{o['os']} · {o['kernel']}"),("Uptime",o["uptime"])]
        for i,(k,v) in enumerate(info):
            scr.addstr(top+1+i,2,f"{k:<8}",curses.color_pair(1)); scr.addstr(top+1+i,11,str(v)[:w-13],curses.color_pair(6))
        y=top+5
        la=float(o["load"][0]); self.gauge(scr,y,2,"Load",round(la,2),o["ncpu"],w,"")
        self.gauge(scr,y+1,2,"Memory",o["mem_used"],o["mem_total"],w,"MB")
        dpct=int(re.sub(r"\D","",o["disk_pct"]) or 0); self.gauge(scr,y+2,2,"Disk",dpct,100,w,"%")
        y+=4
        scr.addstr(y,2,f"Services {up}/{len(svc)} up   Domains {len(self.data('dom',traefik_domains,8))}   "
                       f"Banned {f2b_status('sshd')['banned']}   Blacklist {self.data('blc',blacklist_count,10)}",curses.color_pair(1))
        scr.addstr(y+2,2,f"Net today {ol.get('today','?')}  (rx {ol.get('rx','')} / tx {ol.get('tx','')})  rate {ol.get('rate','')}  ·  month {ol.get('month','')}",curses.color_pair(6))
        att=self.data("atk",lambda:attackers(14),12)
        scr.addstr(y+4,2,"Attack pressure (top IPs): "+spark([a["count"] for a in att]),curses.color_pair(4))

    def b_traffic(self,scr,top,bot,w):
        win=["24h","7d","30d"][self.tw%3]
        scr.addstr(top+1,2,f"Window < {win} >   (↑↓ switches 24h / 7d / 30d)",curses.color_pair(1))
        ser=self.data("vn"+win,lambda:vnstat_series(win),20)
        ol=self.data("vol",vnstat_oneline,6)
        scr.addstr(top+2,2,f"today {ol.get('today','?')}  rate {ol.get('rate','')}  month {ol.get('month','')}",curses.color_pair(6))
        y=top+4; mx=max((e["rx"]+e["tx"]) for e in ser) if ser else 1
        for e in ser[-(bot-top-6):]:
            tot=e["rx"]+e["tx"]
            scr.addstr(y,2,f"{e['label']:>6} {human(tot):>8} ",curses.color_pair(6))
            bw=max(6,w-40); scr.addstr(y,18,bar(tot,mx,bw),curses.color_pair(8)); y+=1
            if y>=bot-1: break
        if not ser: scr.addstr(y,2,"(vnstat is still collecting — history fills in over the coming days)",curses.color_pair(5))

    def b_ssh(self,scr,top,bot,w):
        s=self.data("ssh",ssh_info,5); warn=s["PasswordAuthentication"]=="yes"
        scr.addstr(top+1,2,f"PermitRootLogin {s['PermitRootLogin']}   PasswordAuth {s['PasswordAuthentication']}   Pubkey {s['PubkeyAuthentication']}   Port {s['Port']}",
                   curses.color_pair(4 if warn else 3))
        scr.addstr(top+2,2,f"distinct attacker IPs in auth.log: {s['attacker_ips']}",curses.color_pair(1))
        scr.addstr(top+4,2,"LIVE SESSIONS  (↑↓ select · k kick session · K kick+blacklist IP):",curses.color_pair(1))
        sess=s["sessions"]; self.clampsel(len(sess)); y=top+5
        for i,x in enumerate(sess):
            mark="»" if i==self.sel else " "; me=" (you)" if x["tty"]==my_tty() else ""
            line=f"{mark} {x['user']}@{x['tty']:<9}{x['from']:<16} {x['country']:<14} since {x['since']}{me}"
            scr.addstr(y,2,line[:w-4],curses.color_pair(2) if i==self.sel else curses.color_pair(6)); y+=1
        y+=1; scr.addstr(y,2,"recent logins:",curses.color_pair(1)); y+=1
        for r in s["recent"]:
            if y>=bot-1: break
            scr.addstr(y,4,r[:w-6],curses.color_pair(5)); y+=1

    def b_users(self,scr,top,bot,w):
        us=self.data("usr",users_list,10); self.clampsel(len(us))
        scr.addstr(top+1,2,f"{'USER':<12}{'UID':>5}  SUDO LIVE LOCK KEY  LASTLOGIN   (↑↓ · L lock · Uu unlock)",curses.color_pair(1))
        y=top+2
        for i,u in enumerate(us):
            mark="»" if i==self.sel else " "
            line=(f"{mark}{u['user']:<12}{u['uid']:>5}  {'yes' if u['sudo'] else ' - ':<4} {u['live']:>3}   "
                  f"{'L' if u['locked'] else '-'}   {'y' if u['key'] else 'n'}   {u['lastlogin']}")
            scr.addstr(y,2,line[:w-4],curses.color_pair(2) if i==self.sel else (curses.color_pair(4) if u['locked'] else curses.color_pair(6))); y+=1
        if self.sel<len(us):
            u=us[self.sel]; scr.addstr(bot-1,2,f"groups: {u['groups']}"[:w-4],curses.color_pair(5))

    def b_security(self,scr,top,bot,w):
        banned=self.data("ban",f2b_banned_all,4); bl=self.data("blc2",blacklist_list,8)
        scr.addstr(top+1,2,f"fail2ban banned: {len(banned)}   permanent blacklist: {len(bl)}   "
                           "(b ban · B blacklist · u unban · w whois · Enter detail · g blacklist view)",curses.color_pair(1))
        scr.addstr(top+3,2,"TOP ATTACKERS (attempts · country):",curses.color_pair(1))
        rows=self.sec_rows(); self.clampsel(len(rows)); y=top+4
        for i,(_,o) in enumerate(rows[:bot-top-5]):
            mark="»" if i==self.sel else " "
            bnd="●BL" if (subprocess.run(["ipset","test","avni_blacklist",o["ip"]],capture_output=True).returncode==0) else ("●b" if any(o["ip"] in f2b_status(j)["ips"] for j in ["sshd"]) else "  ")
            line=f"{mark}{o['count']:>7} {o['ip']:<16}{geo(o['ip']):<14}{bnd:<4}"
            scr.addstr(y,2,line[:w-34],curses.color_pair(2) if i==self.sel else curses.color_pair(6))
            scr.addstr(y,min(w-30,2+len(line)),bar(o["count"],o["mx"],24),curses.color_pair(4)); y+=1

    def footer(self):
        s=SECTIONS[self.sec]
        return {"Security":"b ban·B blacklist·u unban·w whois·Enter detail·r·q",
                "Services":"s start·x stop·R restart·l logs·r·q",
                "SSH":"k kick·K kick+blacklist·r·q","Users":"L lock·U unlock·r·q",
                "Domains":"Enter detail·r·q","Traffic":"↑↓ window·r·q"}.get(s,"r refresh·q quit")

    def detail_ip(self,ip):
        d=ip_intel(ip)
        lines=[f"IP        {d['ip']}   ({d['country']})",
               f"attempts  {d['attempts']}",
               f"first     {d['first']}", f"last      {d['last']}",
               f"banned    {d['banned']}      blacklisted {d['blacklisted']}",
               f"org       {d['org']}",
               "usernames "+", ".join(f"{u}({c})" for u,c in d["users"]) or "usernames  —","",
               "[b]an temp   [B]lacklist permanent   [u]nban   [w]hois   [any] close"]
        ch=self.popup(f"IP intel · {ip}",lines,wait=True)
        if ch in (ord('b'),): self.msg="ban "+ip+": "+(ban(ip) or "ok"); self.cache.pop("ban",None)
        elif ch==ord('B'): self.msg=blacklist_add(ip); self.cache.pop("blc2",None)
        elif ch==ord('u'): self.msg="unban "+ip+": "+(unban(ip) or "ok"); self.cache.pop("ban",None)
        elif ch==ord('w'): self.popup("whois "+ip,whois_ip(ip).splitlines(),wait=True)

    def act(self,ch):
        s=SECTIONS[self.sec]; rows=self.rows(); obj=rows[self.sel][1] if rows and self.sel<len(rows) else None
        if s=="Traffic" and ch in (curses.KEY_UP,curses.KEY_DOWN,ord('j'),ord('k')):
            self.tw+=1 if ch in (curses.KEY_DOWN,ord('j')) else -1; return
        if s=="Security":
            o=self.sec_rows()[self.sel][1] if self.sec_rows() and self.sel<len(self.sec_rows()) else None
            ip=o["ip"] if o else None
            if ch in (curses.KEY_ENTER,10,13) and ip: self.detail_ip(ip)
            elif ch==ord('b') and ip: self.msg="ban "+ip+": "+(ban(ip) or "ok"); self.cache.pop("ban",None)
            elif ch==ord('B') and ip: self.msg=blacklist_add(ip); self.cache.pop("blc2",None); self.cache.pop("blc",None)
            elif ch==ord('u') and ip: self.msg="unban "+ip+": "+(unban(ip) or "ok"); self.cache.pop("ban",None)
            elif ch==ord('w') and ip: self.popup("whois "+ip,whois_ip(ip).splitlines(),wait=True)
            elif ch==ord('g'): self.popup("Permanent blacklist",[x+"   "+geo(x.split('/')[0]) for x in blacklist_list()] or ["(empty)"],wait=True)
            elif ch==ord('a'):
                v=self.prompt("ban/blacklist IP or domain: ")
                if v: self.msg=blacklist_add(v); self.cache.pop("blc2",None)
        elif s=="Services" and obj:
            n=obj["name"]
            if ch==ord('R'): self.msg=f"restarting {n}…"; sh(f"docker restart {n}",40); self.cache.pop("svc",None); self.msg=f"restarted {n}"
            elif ch==ord('x'): sh(f"docker stop {n}",40); self.cache.pop("svc",None); self.msg=f"stopped {n}"
            elif ch==ord('s'): sh(f"docker start {n}",40); self.cache.pop("svc",None); self.msg=f"started {n}"
            elif ch==ord('l'): self.popup("logs "+n,sh(f"docker logs --tail 60 {n}",10).splitlines(),wait=True)
        elif s=="SSH" and obj:
            if ch==ord('k'): self.msg=kick_tty(obj["tty"]); self.cache.pop("ssh",None)
            elif ch==ord('K'): self.msg=kick_ip(obj["from"])+" + "+blacklist_add(obj["from"]); self.cache.pop("ssh",None)
        elif s=="Domains" and obj and ch in (curses.KEY_ENTER,10,13):
            d=obj["domain"]; code=sh(f"curl -s -m8 -o /dev/null -w %{{http_code}} https://{d}/")
            self.popup("domain · "+d,[f"backend  {obj['cont']}",f"HTTP     {code}",f"cert exp {cert_expiry(d)}",
                                      f"IPs      {sh('getent ahostsv4 '+d).splitlines()[0].split()[0] if sh('getent ahostsv4 '+d) else '?'}"],wait=True)
        elif s=="Users" and obj:
            if ch==ord('L') and obj["user"] not in("root",): sh(f"usermod -L {obj['user']}"); self.cache.pop("usr",None); self.msg=f"locked {obj['user']}"
            elif ch in (ord('U'),ord('u')): sh(f"usermod -U {obj['user']}"); self.cache.pop("usr",None); self.msg=f"unlocked {obj['user']}"

    def prompt(self,label):
        curses.echo(); curses.curs_set(1); h,w=self.scr.getmaxyx()
        self.scr.addstr(h-1,0," "*(w-1),curses.color_pair(2)); self.scr.addstr(h-1,1,label,curses.color_pair(2))
        try: v=self.scr.getstr(h-1,1+len(label),50).decode().strip()
        except Exception: v=""
        curses.noecho(); curses.curs_set(0); return v
    def popup(self,title,lines,wait=False):
        h,w=self.scr.getmaxyx(); win=curses.newwin(min(h-4,len(lines)+4),w-6,2,3); win.box()
        win.addstr(0,2,f" {title} ",curses.color_pair(1))
        for i,l in enumerate(lines[:h-7]):
            try: win.addstr(1+i,2,str(l)[:w-10],curses.color_pair(6))
            except Exception: pass
        win.refresh(); ch=win.getch() if wait else -1; return ch

    def loop(self):
        curses.curs_set(0); self.scr.timeout(1500)
        while True:
            self.draw(); ch=self.scr.getch()
            if ch==-1: continue
            if ch in (ord('q'),27): break
            elif ch in (curses.KEY_RIGHT,9): self.sec=(self.sec+1)%len(SECTIONS); self.sel=0
            elif ch==curses.KEY_LEFT: self.sec=(self.sec-1)%len(SECTIONS); self.sel=0
            elif ord('1')<=ch<=ord('7'): self.sec=ch-ord('1'); self.sel=0
            elif ch in (curses.KEY_DOWN,) and SECTIONS[self.sec]!="Traffic": self.sel+=1
            elif ch in (curses.KEY_UP,) and SECTIONS[self.sec]!="Traffic": self.sel=max(0,self.sel-1)
            elif ch==ord('r'): self.cache.clear(); self.msg="refreshed"
            else: self.act(ch)

def svc_line(r):
    return f"{'●' if r['status'].startswith('Up') else '○'} {r['name']:<32}{r['status']:<24}{(' '+r['domain']) if r['domain'] else ''}"
def color_for(line):
    if line.startswith("○") or "unhealthy" in line: return curses.color_pair(4)
    if line.startswith("●"): return curses.color_pair(3)
    return curses.color_pair(6)
def tui_main(scr): init_colors(); TUI(scr).loop()

def main():
    if len(sys.argv)>1: cli(sys.argv[1:])
    elif not sys.stdout.isatty(): print("avni: not a TTY. Try a subcommand (avni status) or run in a terminal."); sys.exit(1)
    else: curses.wrapper(tui_main)

if __name__=="__main__": main()
