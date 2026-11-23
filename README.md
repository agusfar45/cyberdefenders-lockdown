# Write-up: CyberDefenders "Lockdown"

Análisis forense de red, memoria y malware de un servidor Windows con IIS comprometido.
Laboratorio: **[Lockdown en CyberDefenders.org](https://cyberdefenders.org/blueteam-ctf-challenges/lockdown/)**
(retirado) · Dificultad: fácil · Resuelto: 11/11.

> Siguiendo las [reglas de CyberDefenders](https://help.cyberdefenders.org/en/articles/8938030-submit-cyberrange-lab-walkthroughs),
> las respuestas aparecen **parcialmente ocultas** (`█`). El objetivo es mostrar cómo se llega a cada una,
> no darla resuelta.

## Escenario

Un Windows Server 2019 con IIS fue comprometido. El lab entrega tres evidencias:

- una captura de red (`capture.pcapng`);
- un volcado de memoria RAM hecho con FTK Imager (`memdump.mem`, 4,5 GiB);
- la muestra de malware (`updatenow.exe`).

## Cómo trabajé

**Cadena de custodia.** Hasheé el zip antes de extraer nada, listé su contenido sin extraerlo y, después de
extraerlo, verifiqué cada archivo contra el CRC32 del índice. Las evidencias quedaron fuera de carpetas
sincronizadas con la nube. Detalle en [notas/recepcion.md](notas/recepcion.md).

| Archivo | SHA-256 |
|---|---|
| capture.pcapng | `cd93ae35b3a4989232dae009bdfb93cbf148ccbfe5087b96c9ad823034ca0bfb` |
| memdump.mem | `94ffad6a879395ec1ce438dfc1347e825200767c07d3e2a6167a34fb764ce64f` |
| updatenow.exe | `c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f` |

**Manejo del malware.** Windows Defender puso la muestra en cuarentena al extraerla y la dejé así: no
desactivé el antivirus ni la restauré. Para el análisis estático la leí **desde el zip directo a memoria**
con Python ([scripts/pe_estatico.py](scripts/pe_estatico.py)), sin escribirla en disco ni ejecutarla. En
VirusTotal consulté solo el hash, sin subir el archivo.

**Herramientas.** Python con scapy (scripts propios en [scripts/](scripts/), sin Wireshark), Volatility 3
(2.28.2), pefile y VirusTotal (consulta por hash).

## Línea de tiempo

En la captura, los tiempos son segundos desde el primer paquete. En la memoria, hora UTC.

| Momento | Evento | Fuente |
|---|---|---|
| 05:30 | Arranca el servicio de IIS (`svchost.exe -k iissvcs`) | `windows.pstree` |
| 05:34 | `RegSvcs.exe` corre desde una carpeta Startup del usuario `admin` (ver "Hallazgo extra") | `windows.cmdline` |
| 05:44 | Arranca el worker de IIS | `windows.pstree` |
| +80 s | El atacante hace un escaneo SYN de más de 1000 puertos | pcap |
| +94 s | Enumeración HTTP automatizada (`PROPFIND`, `OPTIONS`, rutas aleatorias) | pcap |
| +263 s | Se conecta por SMB a dos recursos compartidos | pcap |
| +342 s | Sube al share una web shell ASP.NET | pcap |
| +402 s | El servidor abre una reverse shell cifrada hacia el atacante | pcap + `windows.netscan` |
| 06:08 | El worker de IIS lanza el implante desde la carpeta Startup de todos los usuarios | `windows.pstree` |
| 06:09 | El respondedor abre FTK Imager para el volcado | `windows.pstree` |

## Preguntas

### Red

**Q1. ¿Qué IP hizo el reconocimiento?** `10.0.2.█`

Conté, por cada par origen→destino, los puertos que recibieron un SYN sin ACK. Una IP interna tocó
**1002 puertos distintos** del servidor y generó cerca del 70 % de los paquetes de la captura.
Script: [scripts/pcap_resumen.py](scripts/pcap_resumen.py).

**Q2. ¿Qué herramienta se usó para enumerar HTTP?** `N███`

En las peticiones HTTP de esa IP, el `User-Agent` nombra directamente al motor de scripts del escáner, y
las rutas (`/nmaplowercheck…`, `PROPFIND`, `OPTIONS`) son las de sus scripts HTTP por defecto.

**Q3. ¿Qué dos rutas UNC se acceden primero por SMB?** `\\10.0.2.15\D████████, \\10.0.2.15\I██$`

scapy disecciona SMB2 en capas propias, así que buscar `Raw` no encuentra nada. Parseé a mano el
encabezado SMB2 sobre el payload TCP del puerto 445: comando 3 (`TREE_CONNECT`), con la ruta en UTF-16 en
el offset que indica el cuerpo. Los dos pedidos van seguidos (paquetes 2672 y 2678). Script:
[scripts/pcap_smb.py](scripts/pcap_smb.py).

**Q4. ¿Qué archivo malicioso se sube?** `s████.aspx`

El mismo script muestra un `CREATE` con disposición 5 (*overwrite_if*) seguido de un `WRITE` de 1 MB que
empieza con `<%@ Page Language="C#" %>`. Es una web shell ASP.NET en un share que IIS publica.

**Q5. ¿Por qué puerto vuelve la reverse shell?** `44██`

Es la única conexión que **inicia el servidor** hacia la IP del atacante. El tráfico es binario y
cifrado, compatible con Meterpreter.

### Memoria (Volatility 3)

**Q6. Dirección base del kernel.** `0xf800792█████`

`vol -f memdump.mem windows.info` → `Kernel Base`. El build 17763 confirma que es Windows Server 2019.

**Q7. Ruta completa del implante de persistencia.**
`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\u████████.exe`

`windows.cmdline` y `windows.pstree`: un proceso cuyo padre es el worker de IIS y que corre desde la
carpeta de inicio **de todos los usuarios** (MITRE T1547.001).

**Q8. ¿Qué proceso maneja la reverse shell y lanza el implante, y con qué PID?** `w████.exe, 43██`

Crucé dos plugins:
- `windows.netscan`: el dueño de la conexión al puerto de la Q5;
- `windows.pstree`: el padre del implante de la Q7.

Es el mismo proceso. La cadena es `services.exe → svchost.exe (iissvcs) → [worker de IIS] → implante`: la
web shell corre dentro del worker de IIS.

### Malware

**Q9. ¿Qué packer se usó?** `U██`

[scripts/pe_estatico.py](scripts/pe_estatico.py) con pefile:
- secciones `…0` (sin datos en disco) y `…1` (entropía 7,94);
- la firma del packer, versión 3.91;
- solo 6 importaciones de `KERNEL32` (`LoadLibraryA`, `GetProcAddress`, `VirtualProtect`…), que es lo que
  necesita un stub de descompresión.

DetectItEasy, en la ficha de VirusTotal, agrega que adentro hay un script **AutoIt** compilado.

**Q10. ¿A qué FQDN se comunica?** `c████.hyperhost.██`

Aparece en los dominios contactados por las sandboxes de VirusTotal, que además etiquetan la muestra con
`smtp-communication`. **No me quedé con eso: lo busqué en el volcado de memoria**
([scripts/buscar_mem.py](scripts/buscar_mem.py), ASCII y UTF-16). Aparece 4 veces dentro de la
configuración descifrada del malware: un User-Agent falso, el puerto **587** (SMTP), el servidor y la
cuenta remitente. Es decir, el C2 es un servidor de correo.

**Q11. ¿A qué familia pertenece?** `A████ T████`

Varios indicios apuntan a la misma familia:
- la detección de Microsoft, que es también la que disparó Defender al extraerla;
- exfiltración por SMTP;
- un loader AutoIt comprimido;
- el payload .NET inyectado en `RegSvcs.exe`, que aparece en la memoria.

Otros motores la llaman Nymeria, Strab o FormBook, porque etiquetan el *loader* AutoIt y no el payload
final.

## Hallazgo extra: había una infección anterior

`RegSvcs.exe` (PID 4200) arrancó **34 minutos antes** de que la web shell lanzara el implante, y su línea de
comandos apunta a otro ejecutable en la carpeta Startup del usuario `admin`. `RegSvcs.exe` es un binario
legítimo de .NET y el proceso que esta familia suele vaciar para inyectarse. Todo indica que el servidor
**ya estaba infectado** antes del ataque que muestra la captura. En un caso real, lo siguiente sería:
- `windows.malfind` sobre ese PID;
- volcar sus regiones de memoria;
- revisar el perfil `admin`.

## MITRE ATT&CK

| Táctica | Técnica | Evidencia |
|---|---|---|
| Reconocimiento | T1595 Active Scanning | Escaneo de puertos y enumeración HTTP |
| Acceso inicial | T1190 Exploit Public-Facing Application | Share SMB escribible que IIS publica |
| Persistencia | T1505.003 Web Shell | Página `.aspx` subida por SMB |
| Ejecución | T1059 Command and Scripting Interpreter | Reverse shell desde el worker de IIS |
| Persistencia | T1547.001 Startup Folder | Implante en la carpeta Startup |
| Evasión | T1027.002 Software Packing | Packer + AutoIt |
| Evasión | T1055 Process Injection | Payload dentro de `RegSvcs.exe` |
| Exfiltración | T1048 Exfiltration Over Alternative Protocol | SMTP por el puerto 587 |

## Recomendaciones

1. No compartir por SMB, y menos con escritura, una carpeta que IIS sirve.
2. Bloquear el puerto 445 desde redes no confiables y limitar el tráfico **saliente** del servidor web:
   nada de puertos altos ni SMTP hacia afuera.
3. Impedir que el worker de IIS cree procesos hijos (regla ASR de Defender, AppLocker o WDAC) y alertar si
   pasa.
4. Monitorear las carpetas Startup y las conexiones salientes de `RegSvcs.exe`.
5. Rotar todas las credenciales que hubiera en el servidor, porque esta familia es un infostealer.

## Lo que aprendí

- **scapy no deja SMB en `Raw`**: lo disecciona en capas. Para buscar datos dentro de SMB hay que tomar
  `bytes(tcp.payload)`.
- **`netscan` + `pstree`** responden "quién habla con quién" y "quién lanzó a quién". Cruzarlos ata la
  conexión de red al proceso que creó el implante.
- **Un veredicto de VirusTotal no es evidencia propia.** Encontrar el dominio del C2 en la memoria del
  equipo sí lo es, y además muestra el protocolo de exfiltración.
- **Una muestra se analiza sin tocar el disco**: `zipfile` + `pefile` sobre bytes en memoria alcanzan para
  hashes, secciones, entropía e importaciones.

## Archivos

| Archivo | Para qué |
|---|---|
| [scripts/inventario_zip.py](scripts/inventario_zip.py) | Hashea el zip y lista el contenido sin extraer |
| [scripts/hashes.py](scripts/hashes.py) | CRC32, MD5 y SHA-256 de las evidencias extraídas |
| [scripts/pcap_resumen.py](scripts/pcap_resumen.py) | Pares de IPs, escaneo SYN, User-Agents y peticiones HTTP |
| [scripts/pcap_smb.py](scripts/pcap_smb.py) | SMB2 a mano: `TREE_CONNECT`, `CREATE`, `WRITE`; flujos de la reverse shell |
| [scripts/pe_estatico.py](scripts/pe_estatico.py) | Análisis estático del PE desde el zip, sin escribirlo en disco |
| [scripts/buscar_mem.py](scripts/buscar_mem.py) | Busca una cadena (ASCII/UTF-16) en el volcado con `mmap` |

No incluyo las evidencias ni la muestra: se descargan desde la página del lab.

---

Agustín Farfán · Ingeniería en Informática (UCASAL) ·
[laboratorio forense](https://github.com/agusfar45/laboratorio-perito-informatico) ·
[analizador de pcap](https://github.com/agusfar45/analizador-pcap-forense)
