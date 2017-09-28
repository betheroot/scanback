package main

import (
	"encoding/json"
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"os/exec"
	"strconv"
)

type Configuration struct {
	Port          int    `json:"port"`
	Address       string `json:"address"`
	Domain        string `json:"domain"`
	User          string `json:"user"`
	Password      string `json:"password"`
	Nmap          string `json:"nmap"`
	ScanDirectory string `json:"scanDirectory"`
	CertFile      string `json:"certFile"`
	KeyFile       string `json:"keyFile"`
}

type requestWithQueue func(w http.ResponseWriter, r *http.Request, q chan net.IP, c *Configuration)

func init() {
	log.SetLevel(log.InfoLevel)
}

func configurationFrom(configFile string) Configuration {
	var config Configuration
	jsonConfig, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Couldn't %s", err)
	}

	err = json.Unmarshal(jsonConfig, &config)
	if err != nil {
		log.Fatalf("Couldn't parse JSON in %s: %s", configFile, err)
	}

	return config
}

func addIp(w http.ResponseWriter, request *http.Request, queue chan net.IP, config *Configuration) {
	mangledIp, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		log.Fatalf("A bad thing: %s", err)
	}

	ip := net.ParseIP(mangledIp)
	log.Infof("Added %s to queue", ip)
	queue <- ip
	msg := fmt.Sprintf("Added %s to queue", ip)
	fmt.Fprintf(w, display(msg))
}

func display(input string) string {
	return fmt.Sprintf(
		"<html>"+
			"<head>"+
			"<title>betheroot</title>"+
			"</head>"+
			"<body>"+
			"<h1>%s</h1>"+
			"</body>"+
			"</html>", input)
}

func scanner(queue <-chan net.IP, config *Configuration) {
	for {
		ip := <-queue
		scan(ip, config)
	}
}

func scan(ip net.IP, config *Configuration) {
	log.Infof("Beginning scan of %s", ip)
	scanName := config.ScanDirectory + "/scanback_" + ip.String()
	cmd := exec.Command(config.Nmap, "-Pn", "-oA", scanName, ip.String())
	err := cmd.Run()
	if err != nil {
		log.Errorf("Error scanning %s: %s", ip, err)
	}
	log.Infof("Finished scan of %s", ip)
}

func main() {
	configFile := flag.String("config", "scanback.conf", "JSON configuration file")
	flag.Parse()
	config := configurationFrom(*configFile)

	queue := make(chan net.IP)
	go scanner(queue, &config)
	mux := http.NewServeMux()
	mux.HandleFunc("/", auth(addIp, &config, queue))

	server := &http.Server{
		Addr:    config.Address + ":" + strconv.Itoa(config.Port),
		Handler: mux,
	}

	log.Fatal(server.ListenAndServe())
}

func auth(fn requestWithQueue, config *Configuration, queue chan net.IP) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`"Basic realm=%s"`, config.Domain))
		user, pass, _ := r.BasicAuth()
		if !(user == config.User && pass == config.Password) {
			log.Infof("Got %s %s", user, pass)
			http.Error(w, "Unauthorized.", 401)
			return
		}
		fn(w, r, queue, config)
	}
}
