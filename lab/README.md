# Lab de pruebas (aislado)

Objetivo vulnerable en red interna sin puertos al host. Se escanea desde
dentro de la red, no desde el host.

```bash
docker compose -f lab/docker-compose.yml up -d
# escanear desde el contenedor scanner, en la misma red interna:
docker compose -f lab/docker-compose.yml exec scanner \
  nmap -oX - -sV --script ssl-enum-ciphers,ssl-cert target legacy
docker compose -f lab/docker-compose.yml down
```

El XML resultante se puede pasar a `lns` (vía `scanner.parse_xml`) para validar
reglas sin tocar ninguna red real.
