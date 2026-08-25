# High-Performance Network Stress & Proxy Management Panel

Panel de control web moderno y ultrarrápido desarrollado en **Go (Golang)** con una interfaz en **Tailwind CSS** y WebSockets, diseñado para la gestión avanzada de proxies (**SOCKS5, SOCKS4 e HTTP/HTTPS**) y la ejecución de pruebas de estrés y generación de tráfico de red concurrente de alto rendimiento.

---

## Vista Previa

### Panel Principal
<img width="1919" height="912" alt="image" src="https://github.com/user-attachments/assets/855f0b9c-8b4f-4b9f-9319-03e97df9ceac" />

### Editor de Proxies
<img width="1919" height="904" alt="image" src="https://github.com/user-attachments/assets/bab09761-222c-4b0b-836c-068205fe55b0" />

---

## Características Principales

* **Motor en Go (Golang):** Rendimiento nativo extremo con consumo mínimo de recursos gracias a la concurrencia masiva mediante *goroutines*.
* **Gestión Multi-Proxy:** Interfaz integrada para actualizar, persistir y contar en tiempo real listas separadas de proxies:
  * **SOCKS5 (`proxies.txt`)**
  * **SOCKS4 (`proxies_socks4.txt`)**
  * **HTTP/HTTPS (`proxies_http.txt`)**
* **Disparador Combinado Total:** Capacidad de saturación masiva utilizando todas las listas de proxies configuradas de forma simultánea.
* **Monitoreo por WebSockets:** Logs, eventos y contadores de peticiones en tiempo real transmitidos al panel sin necesidad de recargar la página.
* **Control de Parada Inmediata:** Mecanismo optimizado de cancelación de contextos para detener ataques de forma instantánea, incluso con delays mínimos.
* **Múltiples Protocolos de Prueba:**
  * **HTTP Flood:** Generación masiva de peticiones concurrentes en Capa 7 (con soporte TLS/HTTPS transparente).
  * **TCP Flood:** Saturación de sockets y conexiones de red en paralelo.
  * **UDP Flood:** Envío masivo de paquetes de datos a puertos de destino.
* **Estadísticas Dinámicas:** Contadores visuales instantáneos del total de proxies válidos listos para la acción.

---

## Requisitos del Sistema

* **Go (versión 1.21 o superior recomendada)** instalado en tu equipo.

---

## Instalación y Configuración

1. Clona el repositorio:
   `git clone https://github.com/Riddle360/DDOSproxy.go.git`
   `cd DDOSproxy.go`

2. Asegúrate de tener la dependencia de WebSockets (`gorilla/websocket`):
   `go get github.com/gorilla/websocket`

3. Ejecuta el servidor:
   `go run main.go`

4. Abre tu navegador y accede a:
   `http://localhost:3000`
