package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// Парсит ss:// URL и возвращает метод, пароль, адрес сервера и порт
func parseSSURL(ssURL string) (method, password, serverAddr string, err error) {
	if !strings.HasPrefix(ssURL, "ss://") {
		err = errors.New("URL должен начинаться с ss://")
		return
	}

	ssURL = strings.TrimPrefix(ssURL, "ss://")
	// Отделяем параметры (если есть)
	parts := strings.Split(ssURL, "/?")
	ssURL = parts[0]

	// Разделяем на [base64]@[server]:[port]
	atIndex := strings.Index(ssURL, "@")
	if atIndex == -1 {
		err = errors.New("Некорректный формат URL")
		return
	}

	base64Part := ssURL[:atIndex]
	serverPart := ssURL[atIndex+1:]

	// Декодируем base64 часть
	decoded, err := base64.URLEncoding.DecodeString(base64Part)
	if err != nil {
		err = fmt.Errorf("Ошибка декодирования base64: %v", err)
		return
	}

	// Разделяем на метод и пароль
	methodPassword := string(decoded)
	colonIndex := strings.Index(methodPassword, ":")
	if colonIndex == -1 {
		err = errors.New("Некорректный формат метода и пароля")
		return
	}

	method = methodPassword[:colonIndex]
	password = methodPassword[colonIndex+1:]

	serverAddr = serverPart
	return
}

// Создает Shadowsocks Dialer
func newShadowsocksDialer(method, password, serverAddr string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	cipher, err := core.PickCipher(method, nil, password)
	if err != nil {
		return nil, fmt.Errorf("Ошибка создания шифра: %v", err)
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			return nil, fmt.Errorf("Ошибка подключения к серверу Shadowsocks: %v", err)
		}
		conn = cipher.StreamConn(conn)

		targetAddr := socks.ParseAddr(addr)
		if targetAddr == nil {
			conn.Close()
			return nil, fmt.Errorf("Ошибка парсинга адреса назначения: %v", addr)
		}
		if _, err := conn.Write(targetAddr); err != nil {
			conn.Close()
			return nil, fmt.Errorf("Ошибка отправки адреса назначения: %v", err)
		}
		return conn, nil
	}, nil
}

func main() {
	ssURL := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpHUXh1RU5GQmxraUxwc1RFajl5bmpj@194.54.157.166:25338/?outline=1&prefix=POST%20"

	method, password, serverAddr, err := parseSSURL(ssURL)
	if err != nil {
		log.Fatalf("Ошибка парсинга ss:// URL: %v", err)
	}

	fmt.Printf("Метод: %s\nПароль: %s\nСервер: %s\n", method, password, serverAddr)

	shadowsocksDialer, err := newShadowsocksDialer(method, password, serverAddr)
	if err != nil {
		log.Fatalf("Ошибка создания Shadowsocks Dialer: %v", err)
	}

	transport := &http.Transport{
		DialContext: shadowsocksDialer,
	}

	proxyHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleConnect(w, r, shadowsocksDialer)
		} else {
			handleHTTP(w, r, transport)
		}
	}

	server := &http.Server{
		Addr:    ":8080", // Порт, на котором будет работать прокси
		Handler: http.HandlerFunc(proxyHandler),
	}

	fmt.Println("HTTP прокси сервер запущен на порту 8080")
	log.Fatal(server.ListenAndServe())
}

// Обработка CONNECT запросов (HTTPS)
func handleConnect(w http.ResponseWriter, r *http.Request, dialer func(ctx context.Context, network, addr string) (net.Conn, error)) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Отправляем клиенту подтверждение соединения
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		clientConn.Close()
		return
	}

	// Устанавливаем соединение с целевым сервером через Shadowsocks
	targetConn, err := dialer(r.Context(), "tcp", r.Host)
	if err != nil {
		clientConn.Close()
		return
	}

	// Прокачиваем данные между клиентом и целевым сервером
	go transfer(clientConn, targetConn)
	go transfer(targetConn, clientConn)
}

// Обработка обычных HTTP запросов
func handleHTTP(w http.ResponseWriter, r *http.Request, transport *http.Transport) {
	req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header = r.Header

	resp, err := transport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	// Копируем заголовки и тело ответа клиенту
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// Функция для передачи данных между соединениями
func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}
