"""CRC32, MD5 y SHA-256 de cada archivo pasado como argumento."""
import hashlib
import os
import sys
import zlib

for ruta in sys.argv[1:]:
    crc, md5, sha = 0, hashlib.md5(), hashlib.sha256()
    with open(ruta, "rb") as f:
        for b in iter(lambda: f.read(8 << 20), b""):
            crc = zlib.crc32(b, crc)
            md5.update(b)
            sha.update(b)
    print(f"{os.path.basename(ruta)}  crc32={crc:08x}  md5={md5.hexdigest()}  sha256={sha.hexdigest()}")
