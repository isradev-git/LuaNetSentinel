# LuaNetSentinel

**Auditor y mini-IDS de red defensivo, para línea de comandos.**

> Analiza una red **autorizada**, detecta exposición y patrones sospechosos, asigna riesgo y genera informes. Pensado para correr en un cyberdeck portátil y, a la vez, servir como proyecto enseñable (portfolio / TFG de ASIR).

![tests](https://img.shields.io/badge/tests-38%20passing-brightgreen)
![i18n](https://img.shields.io/badge/i18n-es%20%C2%B7%20en-blueviolet)
![python](https://img.shields.io/badge/python-%E2%89%A53.11-blue)
![lint](https://img.shields.io/badge/lint-ruff-orange)

---

## Idea central

**Tres colectores → un cerebro → un informe.**

```
   nmap (scanner) ┐
   tráfico (scapy)├─→  Finding (modelo único) ─→ scoring + correlación ─→ JSON / HTML / TUI / alertas
   logs web       ┘                              baseline + drift
```

Tres fuentes muy distintas (puertos, paquetes, logs HTTP) producen el **mismo** objeto `Finding`. El núcleo lo puntúa, correlaciona hosts que aparecen en varias fuentes (+15 de riesgo) y lo saca por cuatro salidas. Añadir una detección = soltar un fichero en `rules/`, sin tocar los colectores.

## Uso autorizado — léelo

Solo para **redes propias o con permiso explícito por escrito**. Un *scope guard* (`config/scope.yaml`) bloquea cualquier objetivo fuera del ámbito declarado **antes** de lanzar nmap. Nada ofensivo: escaneo, detección de exposición, hardening, análisis de tráfico/logs y reporting.

## Instalación

Requiere Python ≥ 3.11 y deps de sistema `nmap` y `libpcap`.

```bash
git clone https://github.com/isradev-git/LuaNetSentinel.git
cd LuaNetSentinel
just dev          # pip install -e ".[dev]"   (o el comando pip directo)
```

## Uso

```bash
lns                                    # sin args → TUI (s escanea · t .pcap · w log web · e informe · l idioma)
lns --lang en scan 192.168.1.0/24      # salida en inglés (o `lns lang en` para fijarlo)
lns scan 192.168.1.0/24                # escaneo autorizado + reglas
lns traffic --pcap captura.pcap        # análisis de tráfico (offline o --iface live)
lns weblog /var/log/nginx/access.log   # firmas de ataque en logs web
lns watch 192.168.1.0/24               # vigilancia: re-escaneo + alertas anti-spam
lns baseline set | show | drift        # estado conocido y detección de cambios
lns cve OpenSSH 7.4                     # CVEs de un producto/versión (NVD, cache offline)
lns report --format html -o informe.html
lns rules list
```

Detecciones incluidas: SSH/servicios legacy expuestos, TLS débil/cert caducado, DNS tunneling (entropía), credenciales en claro, beaconing (C2), ARP spoofing, SQLi/XSS/path-traversal/escáneres en logs, drift contra baseline, y **enriquecimiento CVE** del scanner contra NVD (consulta cacheada en SQLite, degrada a caché sin conexión).

### Idiomas / Languages

Español (por defecto) o inglés, en **toda** la salida: findings, informes JSON/HTML, TUI y mensajes. Prioridad: `--lang es|en` › variable `LNS_LANG` › `config/settings.yaml` (lo fija `lns lang en`) › español. En la TUI, la tecla `l` alterna idioma al vuelo; el primer arranque pregunta el idioma.

## Desarrollo

```bash
just test                              # pytest
just lint                              # ruff + mypy
pytest tests/test_traffic.py -k beacon # un test
```

Tests corren **offline** (sin nmap): el parseo de XML, la construcción de paquetes scapy en memoria y el parseo de logs no tocan la red.

## Arquitectura y spec

Diseño completo, modelo de datos, scoring, roadmap y notas de defensa de TFG en **[`proyecto.md`](proyecto.md)**. Resumen de la estructura:

```
lns/        núcleo (finding, rules, scoring, correlation, baseline, store) + colectores + TUI + export + alerting
rules/      plugins auto-descubiertos: scanner/ traffic/ weblog/
nse/        suspicious-services.nse  (único Lua del proyecto)
lab/        docker-compose con red interna aislada para pruebas
```

## Stack

`typer` (CLI) · `textual` (TUI) · `scapy` (tráfico) · `jinja2` (HTML) · `sqlite3` stdlib (sin ORM) · `pytest` + `ruff` + CI en GitHub Actions.

## Licencia

[MIT](LICENSE) © 2026 Israel Zamora.
