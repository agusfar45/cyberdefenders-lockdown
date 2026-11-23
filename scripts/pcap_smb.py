"""SMB2 en capture.pcapng: Tree Connect (rutas UNC), Create (archivos) y Write (contenido subido).
Parseo manual del encabezado SMB2 sobre el payload TCP del puerto 445 (sin reensamblar: alcanza para
pedidos chicos). Además lista los flujos hacia el puerto 4443."""
import struct
import sys

from scapy.all import PcapNgReader, IP, TCP

COMANDOS = {0: "NEGOTIATE", 1: "SESSION_SETUP", 3: "TREE_CONNECT", 5: "CREATE", 6: "CLOSE", 8: "READ", 9: "WRITE", 14: "QUERY_DIRECTORY"}
primer = None
escrito = {}
for i, p in enumerate(PcapNgReader(sys.argv[1]), 1):
    if IP not in p or TCP not in p:
        continue
    t = float(p.time)
    primer = primer or t
    tcp = p[TCP]
    datos = bytes(tcp.payload)
    if 4443 in (tcp.sport, tcp.dport) and datos:
        texto = datos.decode("latin-1").replace("\r", "")
        print(f"[4443] #{i} {t-primer:8.2f}s {p[IP].src}:{tcp.sport} -> {p[IP].dst}:{tcp.dport} {texto[:300]!r}")
        continue
    if tcp.dport != 445 or len(datos) < 68:
        continue
    pos = 0
    while pos + 4 + 64 <= len(datos):
        largo = struct.unpack(">I", b"\x00" + datos[pos + 1:pos + 4])[0]
        smb = datos[pos + 4:pos + 4 + largo]
        pos += 4 + largo
        if smb[:4] != b"\xfeSMB":
            break
        cmd = struct.unpack("<H", smb[12:14])[0]
        cuerpo = smb[64:]
        if cmd == 3 and len(cuerpo) >= 8:
            off, ln = struct.unpack("<HH", cuerpo[4:8])
            ruta = smb[off:off + ln].decode("utf-16-le", "replace")
            print(f"#{i:<6} {t-primer:8.2f}s TREE_CONNECT  {ruta}")
        elif cmd == 5 and len(cuerpo) >= 56:
            off, ln = struct.unpack("<HH", cuerpo[44:48])
            disp = struct.unpack("<I", cuerpo[36:40])[0]
            nombre = smb[off:off + ln].decode("utf-16-le", "replace") or "(raíz)"
            print(f"#{i:<6} {t-primer:8.2f}s CREATE        {nombre}  (disposición {disp})")
        elif cmd == 9 and len(cuerpo) >= 48:
            off, ln, offset_arch = struct.unpack("<HIQ", cuerpo[2:16])
            contenido = smb[off:off + ln]
            print(f"#{i:<6} {t-primer:8.2f}s WRITE         {ln} bytes en offset {offset_arch}: {contenido[:120]!r}")
            escrito.setdefault(i, contenido)
