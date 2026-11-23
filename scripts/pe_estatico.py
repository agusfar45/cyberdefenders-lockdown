"""Análisis estático de updatenow.exe leído DIRECTO DEL ZIP A MEMORIA: nunca se escribe en disco ni se ejecuta.
Uso: python pe_estatico.py <zip> <contraseña>"""
import hashlib
import math
import re
import sys
import zipfile

import pefile

with zipfile.ZipFile(sys.argv[1]) as z:
    datos = z.read("updatenow.exe", pwd=sys.argv[2].encode())

print("Tamaño:", len(datos))
for alg in ("md5", "sha1", "sha256"):
    print(f"{alg.upper():7} {hashlib.new(alg, datos).hexdigest()}")


def entropia(b):
    if not b:
        return 0.0
    cuenta = [0] * 256
    for x in b:
        cuenta[x] += 1
    return -sum(c / len(b) * math.log2(c / len(b)) for c in cuenta if c)


pe = pefile.PE(data=datos)
print("\nMáquina:", hex(pe.FILE_HEADER.Machine), " Compilado (TimeDateStamp):", pe.FILE_HEADER.TimeDateStamp)
print("Punto de entrada:", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
print("\nSección     VirtSize    RawSize  Entropía")
for s in pe.sections:
    nombre = s.Name.rstrip(b"\x00").decode("latin-1")
    print(f"{nombre:<10} {s.Misc_VirtualSize:>9} {s.SizeOfRawData:>10}  {entropia(s.get_data()):.2f}")
print("\nImportaciones:")
for imp in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
    print(" ", imp.dll.decode(), [i.name.decode() for i in imp.imports if i.name][:8])
m = re.search(rb"\$Info: This file is packed with the (\w+) executable packer[^\n]*", datos)
print("\nFirma de packer en el binario:", m.group().decode() if m else "(no encontrada)")
v = re.search(rb"UPX!", datos)
print("Marca UPX!:", bool(v), " Versión:", re.search(rb"\d\.\d{2}\x00UPX!", datos))
print("\nCadenas ASCII interesantes:")
for c in sorted(set(re.findall(rb"[\x20-\x7e]{6,}", datos))):
    if re.search(rb"(https?://|\.(com|net|org|ru|top|xyz|ro|io)\b|smtp|ftp|AutoIt|\.NET|mscoree)", c, re.I):
        print("  ", c.decode()[:120])
