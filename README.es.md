[English](README.md) | **Español**

# VulnScan

```
 __   __    _      ___
 \ \ / /  _| |_ _ / __| __ __ _ _ _
  \ V / || | | ' \\__ \/ _/ _` | ' \
   \_/ \_,_|_|_||_|___/\__\__,_|_||_|
```

Script de línea de comandos que descubre los servicios expuestos de un host o red con **Nmap** y busca las **vulnerabilidades (CVE)** asociadas a cada servicio detectado consultando la API pública de la **NVD** (National Vulnerability Database).

Todo el código está en un único archivo (`vulnscan.py`) para que sea un ejecutable autónomo y autodocumentado.

> ⚠️ **Uso responsable**: escanea únicamente sistemas de tu propiedad o para los que tengas autorización expresa. El escaneo de puertos sin permiso puede ser ilegal.

## Características

- Escaneo **TCP** (SYN, top 1000 puertos) y/o **UDP** (top 100 puertos).
- Detección de versiones de servicios (`-sV`) y huella del sistema operativo (`-O`).
- Soporte para IPs individuales y rangos **CIDR** (IPv4), varios objetivos por ejecución.
- Búsqueda de CVE en la NVD por software y versión detectados.
- Modo agresivo opcional para reducir el tiempo de escaneo.
- Salida compacta en columnas, adaptada al número de CVE encontrados.

## Cómo funciona

1. **Escaneo**: ejecuta Nmap sobre el objetivo (a través de `python-nmap`).
   - TCP: `-sS -sV --version-intensity 0 -n -O`
   - UDP: `-sU --top-ports=100 -sV --version-intensity 0 --min-hostgroup 100 -n -O`
   - Con `-A`: añade `-T5 --min-rate 1000`.
2. **Análisis**: extrae los hosts activos, su SO y los puertos abiertos con producto, versión e información del servicio.
3. **Búsqueda de CVE**: para cada servicio con producto identificado consulta
   `https://services.nvd.nist.gov/rest/json/cves/2.0` usando `keywordSearch=<software> <versión>`.
4. **Resultados**: imprime por host y puerto el servicio detectado y la lista de CVE.

## Requisitos

- **Python 3.12 o superior** (el código usa sintaxis de f-strings introducida en 3.12).
- **[Nmap](https://nmap.org/)** instalado y disponible en el `PATH`.
- **Privilegios de root/administrador**: los escaneos SYN (`-sS`), UDP (`-sU`) y la detección de SO (`-O`) los requieren.
- Conexión a Internet para consultar la API de la NVD.
- Dependencias Python (ver `requirements.txt`): `python-nmap`, `requests` y `tabulate`, más las dependencias de `requests` (`certifi`, `charset-normalizer`, `idna`, `urllib3`).

## Instalación

1. Instalar Nmap (ejemplo en Debian/Ubuntu)
```bash
sudo apt install nmap
```

2. Clonar el proyecto
```bash
git clone https://github.com/bytem1nd/vulnscan && cd vulnscan
```

3. Crear y activar un entorno virtual (recomendado)
```bash
python3 -m venv vulnscan-venv
source vulnscan-venv/bin/activate
``` 

4. Instalar dependencias
```bash
pip install -r requirements.txt
```

## Uso

```
vulnscan.py [-h] [-q] [-t] [-u] [-A] host(s) [host(s) ...]
```

| Opción | Descripción |
| --- | --- |
| `host(s)` | Una o más direcciones IPv4 o rangos CIDR (p. ej. `192.168.1.0/24`). |
| `-t`, `--tcp` | Activa el escaneo TCP (activo por defecto). |
| `-u`, `--udp` | Activa el escaneo UDP. Desactiva el TCP salvo que se indique también `-t` (`-tu`). |
| `-A`, `--aggressive` | Reduce el tiempo de escaneo a costa de sigilo y precisión. |
| `-q`, `--quiet` | No muestra el banner. |
| `-h`, `--help` | Muestra la ayuda. |

> Las direcciones se validan como IPv4 o CIDR con prefijo numérico (0-32); no se aceptan nombres de host ni máscaras de red.

### Ejemplos

```bash
# Escaneo TCP de una IP
sudo vulnscan-venv/bin/python vulnscan.py 192.168.1.10

# Escaneo TCP de toda una red
sudo vulnscan-venv/bin/python vulnscan.py 192.168.1.0/24

# Solo UDP
sudo vulnscan-venv/bin/python vulnscan.py -u 192.168.1.1

# TCP y UDP, en modo agresivo y sin banner
sudo vulnscan-venv/bin/python vulnscan.py -tuAq 192.168.1.1 10.0.0.5
```

> Usa la ruta del `python` del entorno virtual con `sudo`, ya que `sudo` no hereda el entorno activado.

### Ejemplo de salida

```
[*] Scanning 192.168.1.10 (TCP)...
[+] Scanned 192.168.1.10 (TCP) on 14.532 seconds
[*] Searching vulnerabilities of 192.168.1.10...
  - Searching OpenSSH 8.2p1
[+] Searching done!!
[*] Showing results...
  - 192.168.1.10/tcp (OS: Linux 5.4)
	22/tcp - ssh v8.2p1 (Ubuntu Linux; protocol 2.0)
		CVE-XXXX-XXXXX    CVE-XXXX-XXXXX
```

## API key de la NVD (opcional)

Sin clave, la NVD permite unas **5 peticiones cada 30 segundos**, por lo que escanear muchos servicios puede provocar errores de límite de tasa. Puedes solicitar una clave gratuita en <https://nvd.nist.gov/developers/request-an-api-key> y exportarla:

```bash
export NVD_API_KEY="tu-clave"
sudo --preserve-env=NVD_API_KEY vulnscan-venv/bin/python vulnscan.py 192.168.1.10
```

Si una consulta falla (red, límite de tasa, respuesta inválida), se muestra un aviso y se continúa con el resto de servicios.

## Limitaciones conocidas

- Solo IPv4; no admite nombres de dominio.
- La búsqueda por palabra clave en la NVD puede devolver falsos positivos (coincidencias por nombre/versión, no por CPE exacto) o falsos negativos si el banner no revela producto o versión.
- Se usa `--version-intensity 0` para ir más rápido, lo que reduce la precisión de la detección de versiones.
- Solo se consideran los puertos en estado `open`.