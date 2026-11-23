"""Busca una cadena (ASCII y UTF-16LE) en un volcado de memoria y muestra offsets y contexto."""
import mmap
import re
import sys

ruta, cadena = sys.argv[1], sys.argv[2]
patron = re.compile(re.escape(cadena.encode()) + b"|" + re.escape(cadena.encode("utf-16-le")), re.I)
with open(ruta, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
    n = 0
    for x in patron.finditer(m):
        n += 1
        if n <= 12:
            ctx = m[max(0, x.start() - 80):x.end() + 80].replace(b"\x00", b"")
            limpio = re.sub(rb"[^\x20-\x7e]", b".", ctx).decode()
            print(f"0x{x.start():010x}  {limpio}")
    print("Total:", n)
