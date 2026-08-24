# High-Performance Network Stress & Proxy Management Panel

Panel de control web moderno y ultrarrápido desarrollado en **Go (Golang)** con una interfaz en **Tailwind CSS** y WebSockets, diseñado para la gestión dual de proxies (SOCKS5 e HTTP) y la ejecución de pruebas de estrés y generación de tráfico de red concurrente de alto rendimiento.

---

## Vista Previa

### Panel Principal
<img width="1550" height="881" alt="image" src="https://github.com/user-attachments/assets/c3fa6130-679a-4f57-bce1-f9271adf900c" />

### Editor de Proxies
<img width="1905" height="872" alt="image" src="https://github.com/user-attachments/assets/ab020edf-3e36-4189-9fb3-7de9a63152cf" />

---

## Características Principales

* **Motor en Go (Golang):** Rendimiento nativo extremo con consumo mínimo de CPU gracias a la concurrencia masiva mediante *goroutines*.
* **Gestión Dual de Proxies:** Interfaz integrada para actualizar, persistir y contar en tiempo real listas separadas de proxies **SOCKS5 (`proxies.txt`)** e **HTTP/HTTPS (`proxies_http.txt`)**.
* **Disparador Combinado Total:** Capacidad de saturación masiva utilizando ambas listas de proxies de forma simultánea.
* **Monitoreo por WebSockets:** Logs y eventos del servidor transmitidos al panel web en tiempo real sin recargar la página.
* **Múltiples Protocolos de Prueba:**
  * **HTTP Flood:** Generación masiva de peticiones concurrentes en Capa 7.
  * **TCP Flood / TCP SYN Flood:** Saturación de sockets y conexiones de red en paralelo.
  * **UDP Flood:** Envío masivo de paquetes de datos a puertos de destino.
* **Estadísticas Dinámicas:** Contadores visuales instantáneos del total de proxies válidos listos para la acción.

---

## Requisitos del Sistema

* **Go (versión 1.21 o superior recomendada)** instalado en tu equipo.

---

## Instalación y Configuración

1. Clona el repositorio:
   ```bash
   git clone [https://github.com/TU_USUARIO/TU_NUEVO_REPO.git](https://github.com/TU_USUARIO/TU_NUEVO_REPO.git)
   cd TU_NUEVO_REPO
