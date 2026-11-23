"""Hashea un zip y lista su contenido SIN extraer nada."""
import hashlib
import sys
import zipfile

ruta = sys.argv[1]
sha, md5 = hashlib.sha256(), hashlib.md5()
with open(ruta, "rb") as f:
    for bloque in iter(lambda: f.read(8 << 20), b""):
        sha.update(bloque)
        md5.update(bloque)
print(f"SHA-256: {sha.hexdigest()}")
print(f"MD5:     {md5.hexdigest()}")

with zipfile.ZipFile(ruta) as z:
    print(f"\n{'Tamaño':>14}  {'Comprimido':>14}  Cifrado  Método  CRC32     Fecha               Nombre")
    for i in z.infolist():
        cifrado = "sí" if i.flag_bits & 0x1 else "no"
        aes = " (AES)" if i.compress_type == 99 else ""
        fecha = "%04d-%02d-%02d %02d:%02d:%02d" % i.date_time
        print(f"{i.file_size:>14,}  {i.compress_size:>14,}  {cifrado:<7}  {i.compress_type:<6}{aes} {i.CRC:08x}  {fecha}  {i.filename}")
    if z.comment:
        print("\nComentario del zip:", z.comment.decode("latin-1"))
