package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/miekg/dns"
)

type dnsMap struct {
	DNSServer       string             // Server IP to query
	Endpoint        string             // Name of dns endpoint to query
	ErrorTimestamps []time.Time        // Timestamp of errors in last 15 mins
	FailureLast     time.Time          // Timestamp of most recent failure
	ResponseTimes   map[string]float64 // Slice of [1m,5m,15m] average reponse times (like Load)
	Responses       []dnsResponse      `json:"-"` // Slice of full DNS Responses, remove from json
	SuccessLast     time.Time          // Timestamp of most recent success
	Value           string             // Content of first A record for most recent response
}

var clusterlb dnsMap
var dryrun bool
var externalval dnsMap
var hostname string
var k8slocal dnsMap

type dnsResponse struct {
	Message   dns.Msg // Contains .Answer of []dns.RR
	Duration  time.Duration
	Endpoint  string
	Success   bool
	TimeStamp time.Time
}

var responses = make(chan dnsResponse, 10) // Buffer to avoid deadlocks

func init() {
	hostname, _ = os.Hostname()

	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")

	k8slocal = dnsMap{
		Endpoint:      "internalDNSNameHere",
		DNSServer:     string(net.JoinHostPort(config.Servers[0], config.Port)),
		ResponseTimes: make(map[string]float64),
	}
	clusterlb = dnsMap{Endpoint: "VPCInteral",
		DNSServer:     "internalIP:53",
		ResponseTimes: make(map[string]float64),
	}
	externalval = dnsMap{Endpoint: "publicName",
		DNSServer:     "8.8.8.8:53",
		ResponseTimes: make(map[string]float64),
	}

}

func averageResponses(xs []dnsResponse) float64 {
	total := 0.0
	for _, v := range xs {
		total += v.Duration.Seconds()
	}
	s := (total / float64(len(xs))) * 1000 // Seconds to milliseconds
	if math.IsNaN(s) {
		return 0.0
	}
	return s
}

func computeValues(it *dnsMap) {
	// Ensure values are truncated to 180 responses,
	// and 3 most recent error timestamps, then use the
	// responses to compute three values: 1m,5m,15m avgs
	// from  12, 60, and 180 responses

	s := len(it.Responses)

	var tempSlice12, tempSlice60, tempSlice180 []dnsResponse

	if s < 12 {
		tempSlice12 = it.Responses[:]
	} else {
		tempSlice12 = it.Responses[(len(it.Responses) - 12):]
	}
	if s < 60 {
		tempSlice60 = it.Responses[:]
	} else {
		tempSlice60 = it.Responses[(len(it.Responses) - 60):]
	}
	if s < 180 {
		tempSlice180 = it.Responses[:]
	} else {
		tempSlice180 = it.Responses[(len(it.Responses) - 180):]
	}

	it.ResponseTimes["1m"] = averageResponses(tempSlice12)
	it.ResponseTimes["5m"] = averageResponses(tempSlice60)
	it.ResponseTimes["15m"] = averageResponses(tempSlice180)

	//// Maintenance section ////
	if len(it.Responses) > 180 {
		// Clean up responses, truncate at length of 180 to avoid crazy growth
		it.Responses = it.Responses[(len(it.Responses) - 180):]
	}

	n := time.Now()
	fifteenMinsPrior := n.Add(-15 * time.Minute)
	var newErrors []time.Time
	for _, v := range it.ErrorTimestamps {
		if v.Before(fifteenMinsPrior) {
			continue // Noop
		} else {
			newErrors = append(newErrors, v)
		}
	}
	it.ErrorTimestamps = newErrors

}

func updateDNSrecords(in <-chan dnsResponse) {
	for {
		select {
		case resp := <-in:
			if resp.Endpoint == k8slocal.Endpoint {
				k8slocal.Responses = append(k8slocal.Responses, resp)
				aRec := resp.Message.Answer[0].(*dns.A)
				k8slocal.Value = aRec.A.String()
				if resp.Success {
					k8slocal.SuccessLast = resp.TimeStamp
				} else {
					k8slocal.FailureLast = resp.TimeStamp
					k8slocal.ErrorTimestamps = append(k8slocal.ErrorTimestamps, resp.TimeStamp)
				}
			} else if resp.Endpoint == clusterlb.Endpoint {
				clusterlb.Responses = append(clusterlb.Responses, resp)
				aRec := resp.Message.Answer[0].(*dns.A)
				clusterlb.Value = aRec.A.String()
				if resp.Success {
					clusterlb.SuccessLast = resp.TimeStamp
				} else {
					clusterlb.FailureLast = resp.TimeStamp
					clusterlb.ErrorTimestamps = append(clusterlb.ErrorTimestamps, resp.TimeStamp)
				}
			} else if resp.Endpoint == externalval.Endpoint {
				externalval.Responses = append(externalval.Responses, resp)
				aRec := resp.Message.Answer[0].(*dns.A)
				externalval.Value = aRec.A.String()
				if resp.Success {
					externalval.SuccessLast = resp.TimeStamp
				} else {
					externalval.FailureLast = resp.TimeStamp
					externalval.ErrorTimestamps = append(externalval.ErrorTimestamps, resp.TimeStamp)
				}
			} else {
				log.Printf("Unmatched endpoint: %v \n", resp.Endpoint)
			}
		default:
			time.Sleep(500 * time.Millisecond) // DEBUG
		}
	}
}

func processEndpoints() {
	tick := time.Tick(2 * time.Second)
	for {
		select {
		case <-tick:
			computeValues(&k8slocal)
			computeValues(&clusterlb)
			computeValues(&externalval)
		default:
			time.Sleep(500 * time.Millisecond) // noop
		}
	}
}

func checkDNS(cs chan<- dnsResponse, endpoint string, dnsserver string) {
	tick := time.Tick(5 * time.Second) // Look up the endpoint, continually every 5 seconds
	for {
		select {
		case <-tick:
			success := true
			c := new(dns.Client)
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(endpoint), dns.TypeA) // Look for A records
			m.RecursionDesired = true
			resp, rtt, err := c.Exchange(m, dnsserver) // Request with RTT & DNS response
			currentTime := time.Now()
			if resp == nil {
				success = false
				log.Printf("::: DNS query error: %s\n", err.Error())
			} else if resp.Rcode != dns.RcodeSuccess {
				success = false
				log.Printf("::: Invalid DNS response for %v \n", endpoint)
			}
			cs <- dnsResponse{
				Duration:  rtt,
				Endpoint:  endpoint,
				Message:   *resp,
				Success:   success,
				TimeStamp: currentTime}
		}
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	cpyCluster := []dnsMap{k8slocal, clusterlb, externalval}
	jsonData, err := json.MarshalIndent(cpyCluster, "", "  ")
	if err != nil {
		log.Printf("Failed to parse JSON \n %v", err)
	}
	w.Header().Set("responding-pod", hostname)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("charset", "utf-8")
	w.Write(jsonData)
}

func livenessCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("responding-pod", hostname)
	fmt.Fprintf(w, "%s", "pong")
}

func main() {
	flag.BoolVar(&dryrun, "n", false, "Prevent GCP internal checks (k8s, internal)")
	flag.Parse()

	log.Println("Service started on port 6500")
	if dryrun {
		log.Println(" ::: Dry run enabled. Querying only external address values")
		// Launch only external resolver in a goroutine
		go checkDNS(responses, externalval.Endpoint, externalval.DNSServer)
	} else {
		// Launch all resolvers in separate goroutines
		go checkDNS(responses, k8slocal.Endpoint, k8slocal.DNSServer)
		go checkDNS(responses, clusterlb.Endpoint, clusterlb.DNSServer)
		go checkDNS(responses, externalval.Endpoint, externalval.DNSServer)
	}
	log.Println("DNS resolvers launched")
	// Always launch the consumer
	go updateDNSrecords(responses)
	// Separate goroutine to monitor and compute averages
	go processEndpoints()
	log.Println("Response consumer launched")

	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/ping", livenessCheck)
	http.ListenAndServe(":6500", nil)
}
