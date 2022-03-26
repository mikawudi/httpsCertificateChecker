package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	addressList string
	address     []string
	wxtoken     string
	dayofnotice int
)

func checkCert(urlAddress string, client http.Client) (int, string, error) {
	urlInfo, err := url.Parse(urlAddress)
	host := urlInfo.Hostname()
	hostArray := strings.Split(host, ".")
	if len(hostArray) > 2 {
		item := hostArray[len(hostArray)-2:]
		host = item[0] + "." + item[1]
	}
	resp, err := client.Get(urlAddress)
	if err != nil {
		return 0, "", err
	}
	defer func() {
		resp.Body.Close()
	}()
	isDominCert := false
	certDomainName := ""
	dayOfEnd := 0
	for _, cert := range resp.TLS.PeerCertificates {
		if cert.DNSNames == nil || len(cert.DNSNames) == 0 {
			continue
		}
		for _, dnsName := range cert.DNSNames {
			if strings.Contains(dnsName, host) {
				certDomainName = dnsName
				isDominCert = true
			}
		}
		if !isDominCert {
			continue
		}
		lastTime := int64(cert.NotAfter.Sub(time.Now()).Hours() / 24)
		dayOfEnd = int(lastTime)
	}
	if isDominCert {
		return dayOfEnd, certDomainName, nil
	}
	return 0, "", errors.New("not found cert in chain")
}

func sendToWx(msg string, wxKey string) error {
	var url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=" + wxKey
	content := make(map[string]any)
	content["msgtype"] = "text"
	content["text"] = map[string]string{
		"content": msg,
	}
	data, err := json.Marshal(content)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New("http statusCode is " + strconv.FormatInt(int64(resp.StatusCode), 10) + ": body is " + string(respBody))
	}
	log.Println(string(respBody))
	return nil
}

func checkFlags() {
	flag.StringVar(&addressList, "addresses", "", "wait check list split by ','")
	flag.StringVar(&wxtoken, "wxtoken", "", "wx robot token")
	flag.IntVar(&dayofnotice, "day", 10, "close day of notice by wx, default is 10")
	flag.Parse()
	if addressList == "" {
		log.Panicln("addresses is empty")
	}
	if wxtoken == "" {
		log.Panicln("wxtoken is empty")
	}
	for _, adr := range strings.Split(addressList, ",") {
		address = append(address, strings.Trim(adr, " "))
	}
}

func main() {
	checkFlags()
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 30 * time.Second,
	}
	for _, adr := range address {
		day, certDomainName, err := checkCert("https://"+adr, client)
		if err != nil {
			log.Println(err.Error())
			continue
		}
		message := "证书:" + certDomainName + " 剩余:" + strconv.FormatInt(int64(day), 10) + "天过期, 请准备好更新工作 (当前告警阈值:" + strconv.FormatInt(int64(dayofnotice), 10) + "天)"
		log.Println(message)
		if day < dayofnotice {
			sendToWx(message, wxtoken)
		}
	}
}
