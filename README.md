# High-Performance Network Stress & Proxy Management Panel

Panel de control web moderno y ultrarrápido desarrollado en Go (Golang) con una interfaz en Tailwind CSS y WebSockets, diseñado para la gestión avanzada de proxies (SOCKS5, SOCKS4 e HTTP/HTTPS) y la ejecución de pruebas de estrés y generación de tráfico de red concurrente de alto rendimiento.

---

## Vista Previa

### Panel Principal
<img width="1919" height="912" alt="image" src="https://github.com/user-attachments/assets/855f0b9c-8b4f-4b9f-9319-03e97df9ceac" />

### Editor de Proxies
<img width="1919" height="904" alt="image" src="https://github.com/user-attachments/assets/bab09761-222c-4b0b-836c-068205fe55b0" />

---

## Características Principales

* Motor en Go (Golang): Rendimiento nativo extremo con consumo eficiente de recursos mediante concurrencia masiva con goroutines.
* Gestión Multi-Proxy: Interfaz integrada para actualizar, persistir y contar en tiempo real listas separadas de proxies:
  - SOCKS5 (proxies.txt)
  - SOCKS4 (proxies_socks4.txt)
  - HTTP/HTTPS (proxies_http.txt)
* Disparador Combinado Total: Capacidad de prueba utilizando todas las listas de proxies configuradas de forma simultánea.
* Monitoreo por WebSockets: Logs, eventos y contadores de peticiones en tiempo real transmitidos al panel sin recargar la página.
* Control de Parada Inmediata: Mecanismo de cancelación por canales (stopChan) y cierre limpio de sockets activos.
* Múltiples Protocolos de Prueba:
  - HTTP Flood: Generación de peticiones concurrentes en Capa 7 con soporte TLS/HTTPS transparente.
  - TCP Flood: Conexiones dinámicas optimizadas con mutación de datos y ciclo de vida de sockets controlado.
  - UDP Flood: Envío concurrente de paquetes de datos mediante dialers directos o proxies SOCKS5.
* Estadísticas Dinámicas: Contadores visuales instantáneos del estado de los proxies.

---

## Requisitos del Sistema

* Go (versión 1.21 o superior) instalado en tu equipo.

---

## Dependencias

El proyecto utiliza las siguientes librerías oficiales y de terceros:
* github.com/gorilla/websocket
* golang.org/x/net/proxy

---

## Instalación y Configuración

1. Clona el repositorio:
git clone https://github.com/Riddle360/DDOSproxy.go.git
cd DDOSproxy.go

2. Inicializa o descarga los módulos necesarios:
go mod tidy

3. Ejecuta el servidor:
go run main.go

4. Abre tu navegador y accede a:
http://localhost:3000
