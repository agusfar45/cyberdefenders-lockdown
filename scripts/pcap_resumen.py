"""Resumen de capture.pcapng: IPs, puertos, User-Agents HTTP, SMB (Tree Connect, archivos) y conexiones salientes."""
import collections
import re
import sys

from scapy.all import PcapNgReader, IP, TCP, UDP, Raw

ruta = sys.argv[1]
pares = collections.Counter()
syn_dst = collections.Counter()
puertos_por_src = collections.defaultdict(set)
agentes = collections.Counter()
peticiones = []
smb_payloads = []
primer = None
todos = []
for i, p in enumerate(PcapNgReader(ruta)):
    if IP not in p:
        continue
    t = float(p.time)
    primer = primer or t
    ip = p[IP]
    if TCP in p:
        tcp = p[TCP]
        if tcp.flags & 0x02 and not tcp.flags & 0x10:
            syn_dst[(ip.src, ip.dst, tcp.dport)] += 1
            puertos_por_src[(ip.src, ip.dst)].add(tcp.dport)
        pares[(ip.src, ip.dst, "tcp")] += 1
        if Raw in p:
            datos = bytes(p[Raw].load)
            if tcp.dport in (80, 8080) and re.match(rb"^(GET|POST|HEAD|PUT|OPTIONS|PROPFIND) ", datos):
                linea = datos.split(b"\r\n", 1)[0].decode("latin-1")
                ua = re.search(rb"\r\nUser-Agent: ([^\r\n]*)", datos, re.I)
                ua = ua.group(1).decode("latin-1") if ua else "(sin UA)"
                agentes[(ip.src, ua)] += 1
                peticiones.append((t - primer, ip.src, ip.dst, linea, ua))
            if 445 in (tcp.sport, tcp.dport):
                smb_payloads.append((i, t - primer, ip.src, ip.dst, tcp.sport, tcp.dport, datos))
    elif UDP in p:
        pares[(ip.src, ip.dst, "udp")] += 1

print("== Pares con más paquetes")
for (s, d, pr), n in pares.most_common(15):
    print(f"  {s:>15} -> {d:<15} {pr} {n}")
print("\n== Orígenes que sondearon más puertos (SYN)")
for (s, d), ps in sorted(puertos_por_src.items(), key=lambda x: -len(x[1]))[:10]:
    print(f"  {s} -> {d}: {len(ps)} puertos  {sorted(ps)[:25]}")
print("\n== User-Agents HTTP")
for (s, ua), n in agentes.most_common(20):
    print(f"  {n:5}  {s}  {ua}")
print("\n== Primeras 15 peticiones HTTP")
for r in peticiones[:15]:
    print(f"  {r[0]:8.2f}s {r[1]} -> {r[2]}  {r[3]}  [{r[4]}]")
print("\n== SMB: rutas UNC y nombres de archivo (UTF-16) en orden")
vistos = set()
for i, t, s, d, sp, dp, datos in smb_payloads:
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", datos):
        txt = m.group().decode("utf-16-le")
        clave = (txt, s)
        if clave in vistos:
            continue
        vistos.add(clave)
        print(f"  #{i:<6} {t:8.2f}s {s}:{sp} -> {d}:{dp}  {txt}")
print("\n== Conexiones TCP iniciadas por la víctima hacia afuera (SYN)")
for (s, d, dp), n in syn_dst.most_common():
    if dp not in (445, 80, 139, 135) and n < 5:
        print(f"  {s} -> {d}:{dp}  x{n}")
