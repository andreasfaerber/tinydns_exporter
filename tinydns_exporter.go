package main

import (
	"flag"
	"net/http"
	"sync"
	"bufio"
	"os"
	"strings"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

const (
	namespace = "tinydns" // For Prometheus metrics.
)

var (
	listenAddress = flag.String("telemetry.address", "127.0.0.1:9119", "Address on which to expose metrics.")
	metricsPath  = flag.String("telemetry.endpoint", "/metrics", "Path under which to expose metrics.")
	ipv4TinystatsFile = flag.String("ipv4tinystats.file", "/service/tinydns/log/main/tinystats.out", "Tinystats output file (ipv4) - set to \"disabled\" to disable")
	ipv6TinystatsFile = flag.String("ipv6tinystats.file", "/service/tinydns.ipv6/log/main/tinystats.out", "Tinystats output file (ipv6) - set to \"disabled\" to disable")

        ipv4QueryA, ipv4QueryNS, ipv4QueryCNAME,
        ipv4QuerySOA, ipv4QueryPTR, ipv4QueryHINFO,
        ipv4QueryMX, ipv4QueryTXT, ipv4QueryRP,
        ipv4QuerySIG, ipv4QueryKEY, ipv4QueryAAAA,
        ipv4QueryAXFR, ipv4QueryANY, ipv4QueryTOTAL,
        ipv4QueryOTHER, ipv4QueryNOTAUTH, ipv4QueryNOTIMPL,
        ipv4QueryBADCLASS, ipv4QueryNOQUERY string

        ipv6QueryA, ipv6QueryNS, ipv6QueryCNAME,
        ipv6QuerySOA, ipv6QueryPTR, ipv6QueryHINFO,
        ipv6QueryMX, ipv6QueryTXT, ipv6QueryRP,
        ipv6QuerySIG, ipv6QueryKEY, ipv6QueryAAAA,
        ipv6QueryAXFR, ipv6QueryANY, ipv6QueryTOTAL,
        ipv6QueryOTHER, ipv6QueryNOTAUTH, ipv6QueryNOTIMPL,
        ipv6QueryBADCLASS, ipv6QueryNOQUERY string
)


type Exporter struct {
	mutex          sync.RWMutex
        ipv4QueryA         prometheus.Gauge
        ipv4QueryNS        prometheus.Gauge
        ipv4QueryCNAME     prometheus.Gauge
        ipv4QuerySOA       prometheus.Gauge
        ipv4QueryPTR       prometheus.Gauge
        ipv4QueryHINFO     prometheus.Gauge
        ipv4QueryMX        prometheus.Gauge
        ipv4QueryTXT       prometheus.Gauge
        ipv4QueryRP        prometheus.Gauge
        ipv4QuerySIG       prometheus.Gauge
        ipv4QueryKEY       prometheus.Gauge
        ipv4QueryAAAA      prometheus.Gauge
        ipv4QueryAXFR      prometheus.Gauge
        ipv4QueryANY       prometheus.Gauge
        ipv4QueryTOTAL     prometheus.Gauge
        ipv4QueryOTHER     prometheus.Gauge
        ipv4QueryNOTAUTH   prometheus.Gauge
        ipv4QueryNOTIMPL   prometheus.Gauge
        ipv4QueryBADCLASS  prometheus.Gauge
        ipv4QueryNOQUERY   prometheus.Gauge
        ipv6QueryA         prometheus.Gauge
        ipv6QueryNS        prometheus.Gauge
        ipv6QueryCNAME     prometheus.Gauge
        ipv6QuerySOA       prometheus.Gauge
        ipv6QueryPTR       prometheus.Gauge
        ipv6QueryHINFO     prometheus.Gauge
        ipv6QueryMX        prometheus.Gauge
        ipv6QueryTXT       prometheus.Gauge
        ipv6QueryRP        prometheus.Gauge
        ipv6QuerySIG       prometheus.Gauge
        ipv6QueryKEY       prometheus.Gauge
        ipv6QueryAAAA      prometheus.Gauge
        ipv6QueryAXFR      prometheus.Gauge
        ipv6QueryANY       prometheus.Gauge
        ipv6QueryTOTAL     prometheus.Gauge
        ipv6QueryOTHER     prometheus.Gauge
        ipv6QueryNOTAUTH   prometheus.Gauge
        ipv6QueryNOTIMPL   prometheus.Gauge
        ipv6QueryBADCLASS  prometheus.Gauge
        ipv6QueryNOQUERY   prometheus.Gauge
}

// NewTinestatsExporter returns an initialized Exporter.
func NewTinystatsExporter() *Exporter {
	return &Exporter{
          ipv4QueryA: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "ipv4QueryA",
			Help:      "number of A record queries via ipv4",
		}),
          ipv4QueryNS: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryNS",
                        Help:      "number of NS record queries via ipv4",
                }),
          ipv4QueryCNAME: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryCNAME",
                        Help:      "number of CNAME record queries via ipv4",
                }),
          ipv4QuerySOA: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QuerySOA",
                        Help:      "number of SOA record queries via ipv4",
		}),
          ipv4QueryPTR: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryPTR",
                        Help:      "number of PTR record queries via ipv4",
		}),
          ipv4QueryHINFO: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryHINFO",
                        Help:      "number of HINFO record queries via ipv4",
		}),
          ipv4QueryMX: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryMX",
                        Help:      "number of MX record queries via ipv4",
		}),
          ipv4QueryTXT: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryTXT",
                        Help:      "number of TXT record queries via ipv4",
		}),
          ipv4QueryRP: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryRP",
                        Help:      "number of RP record queries via ipv4",
		}),
          ipv4QuerySIG: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QuerySIG",
                        Help:      "number of SIG record queries via ipv4",
		}),
          ipv4QueryKEY: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryKEY",
                        Help:      "number of KEY record queries via ipv4",
		}),
          ipv4QueryAAAA: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryAAAA",
                        Help:      "number of AAAA record queries via ipv4",
		}),
          ipv4QueryAXFR: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryAXFR",
                        Help:      "number of AXFR record queries via ipv4",
		}),
          ipv4QueryANY: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryANY",
                        Help:      "number of ANY record queries via ipv4",
		}),
          ipv4QueryTOTAL: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryTOTAL",
                        Help:      "total number queries via ipv4",
		}),
          ipv4QueryOTHER: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryOTHER",
                        Help:      "number of unrecognized record queries via ipv4",
		}),
          ipv4QueryNOTAUTH: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryNOAUTH",
                        Help:      "number of queries for non authorative records via ipv4",
		}),
          ipv4QueryNOTIMPL: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryNOTIMPL",
                        Help:      "number of not implemented queries via ipv4",
		}),
          ipv4QueryBADCLASS: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryBADCLASS",
                        Help:      "number of queries not implemented via ipv4",
		}),
          ipv4QueryNOQUERY: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv4QueryNOQUERY",
                        Help:      "number of empty or errorneous queries via ipv4",
		}),
          ipv6QueryA: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "ipv6QueryA",
			Help:      "number of A record queries via ipv6",
		}),
          ipv6QueryNS: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryNS",
                        Help:      "number of NS record queries via ipv6",
                }),
          ipv6QueryCNAME: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryCNAME",
                        Help:      "number of CNAME record queries via ipv6",
                }),
          ipv6QuerySOA: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QuerySOA",
                        Help:      "number of SOA record queries via ipv6",
		}),
          ipv6QueryPTR: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryPTR",
                        Help:      "number of PTR record queries via ipv6",
		}),
          ipv6QueryHINFO: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryHINFO",
                        Help:      "number of HINFO record queries via ipv6",
		}),
          ipv6QueryMX: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryMX",
                        Help:      "number of MX record queries via ipv6",
		}),
          ipv6QueryTXT: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryTXT",
                        Help:      "number of TXT record queries via ipv6",
		}),
          ipv6QueryRP: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryRP",
                        Help:      "number of RP record queries via ipv6",
		}),
          ipv6QuerySIG: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QuerySIG",
                        Help:      "number of SIG record queries via ipv6",
		}),
          ipv6QueryKEY: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryKEY",
                        Help:      "number of KEY record queries via ipv6",
		}),
          ipv6QueryAAAA: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryAAAA",
                        Help:      "number of AAAA record queries via ipv6",
		}),
          ipv6QueryAXFR: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryAXFR",
                        Help:      "number of AXFR record queries via ipv6",
		}),
          ipv6QueryANY: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryANY",
                        Help:      "number of ANY record queries via ipv6",
		}),
          ipv6QueryTOTAL: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryTOTAL",
                        Help:      "total number queries via ipv6",
		}),
          ipv6QueryOTHER: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryOTHER",
                        Help:      "number of unrecognized record queries via ipv6",
		}),
          ipv6QueryNOTAUTH: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryNOAUTH",
                        Help:      "number of queries for non authorative records via ipv6",
		}),
          ipv6QueryNOTIMPL: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryNOTIMPL",
                        Help:      "number of not implemented queries via ipv6",
		}),
          ipv6QueryBADCLASS: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryBADCLASS",
                        Help:      "number of queries not implemented via ipv6",
		}),
          ipv6QueryNOQUERY: prometheus.NewGauge(prometheus.GaugeOpts{
                        Namespace: namespace,
                        Name:      "ipv6QueryNOQUERY",
                        Help:      "number of empty or errorneous queries via ipv6",
		}),

	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {

    e.ipv4QueryA.Describe(ch)
    e.ipv4QueryNS.Describe(ch)
    e.ipv4QueryCNAME.Describe(ch)
    e.ipv4QuerySOA.Describe(ch)
    e.ipv4QueryPTR.Describe(ch)
    e.ipv4QueryHINFO.Describe(ch)
    e.ipv4QueryMX.Describe(ch)
    e.ipv4QueryTXT.Describe(ch)
    e.ipv4QueryRP.Describe(ch)
    e.ipv4QuerySIG.Describe(ch)
    e.ipv4QueryKEY.Describe(ch)
    e.ipv4QueryAAAA.Describe(ch)
    e.ipv4QueryAXFR.Describe(ch)
    e.ipv4QueryANY.Describe(ch)
    e.ipv4QueryTOTAL.Describe(ch)
    e.ipv4QueryOTHER.Describe(ch)
    e.ipv4QueryNOTAUTH.Describe(ch)
    e.ipv4QueryNOTIMPL.Describe(ch)
    e.ipv4QueryBADCLASS.Describe(ch)
    e.ipv4QueryNOQUERY.Describe(ch)

    e.ipv6QueryA.Describe(ch)
    e.ipv6QueryNS.Describe(ch)
    e.ipv6QueryCNAME.Describe(ch)
    e.ipv6QuerySOA.Describe(ch)
    e.ipv6QueryPTR.Describe(ch)
    e.ipv6QueryHINFO.Describe(ch)
    e.ipv6QueryMX.Describe(ch)
    e.ipv6QueryTXT.Describe(ch)
    e.ipv6QueryRP.Describe(ch)
    e.ipv6QuerySIG.Describe(ch)
    e.ipv6QueryKEY.Describe(ch)
    e.ipv6QueryAAAA.Describe(ch)
    e.ipv6QueryAXFR.Describe(ch)
    e.ipv6QueryANY.Describe(ch)
    e.ipv6QueryTOTAL.Describe(ch)
    e.ipv6QueryOTHER.Describe(ch)
    e.ipv6QueryNOTAUTH.Describe(ch)
    e.ipv6QueryNOTIMPL.Describe(ch)
    e.ipv6QueryBADCLASS.Describe(ch)
    e.ipv6QueryNOQUERY.Describe(ch)


}

func parseTinystatsFile() {

    if (*ipv4TinystatsFile != "disabled") {
        statsFile, err := os.Open(*ipv4TinystatsFile)
        if err != nil {
            log.Infof("error opening file, skipping: %s", *ipv4TinystatsFile)
        } else {
            reader := bufio.NewReader(statsFile)
            line, err := reader.ReadString('\n')
            if err == nil {
                q := strings.Split(line, ":")
    
                ipv4QueryA, ipv4QueryNS, ipv4QueryCNAME,
                ipv4QuerySOA, ipv4QueryPTR, ipv4QueryHINFO,
                ipv4QueryMX, ipv4QueryTXT, ipv4QueryRP,
                ipv4QuerySIG, ipv4QueryKEY, ipv4QueryAAAA,
                ipv4QueryAXFR, ipv4QueryANY, ipv4QueryTOTAL,
                ipv4QueryOTHER, ipv4QueryNOTAUTH, ipv4QueryNOTIMPL,
                ipv4QueryBADCLASS, ipv4QueryNOQUERY= q[0], q[1],
                q[2], q[3], q[4], q[5], q[6], q[7], q[8],
                q[9], q[10], q[11], q[12], q[13], q[14],
                q[15], q[16], q[17], q[18], q[19]
                statsFile.Close()
            }
        }
    }

    if (*ipv6TinystatsFile != "disabled") {
        statsFile, err := os.Open(*ipv6TinystatsFile)
        if err != nil {
            log.Infof("error opening file, skipping: %s", *ipv6TinystatsFile)
        } else {
            reader := bufio.NewReader(statsFile)
            line, err := reader.ReadString('\n')
            if err == nil {
                q := strings.Split(line, ":")
        
                ipv6QueryA, ipv6QueryNS, ipv6QueryCNAME,
                ipv6QuerySOA, ipv6QueryPTR, ipv6QueryHINFO,
                ipv6QueryMX, ipv6QueryTXT, ipv6QueryRP,
                ipv6QuerySIG, ipv6QueryKEY, ipv6QueryAAAA,
                ipv6QueryAXFR, ipv6QueryANY, ipv6QueryTOTAL,
                ipv6QueryOTHER, ipv6QueryNOTAUTH, ipv6QueryNOTIMPL,
                ipv6QueryBADCLASS, ipv6QueryNOQUERY= q[0], q[1],
                q[2], q[3], q[4], q[5], q[6], q[7], q[8],
                q[9], q[10], q[11], q[12], q[13], q[14],
                q[15], q[16], q[17], q[18], q[19]
                statsFile.Close()
            }
        }
    }
}

func (e *Exporter) scrape(ch chan<- prometheus.Metric) error {

    parseTinystatsFile()
    r, err := strconv.ParseFloat(ipv4QueryA, 64)
    if err == nil { e.ipv4QueryA.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryNS, 64)
    if err == nil { e.ipv4QueryNS.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryCNAME, 64)
    if err == nil { e.ipv4QueryCNAME.Set(r) }
    r, err = strconv.ParseFloat(ipv4QuerySOA, 64)
    if err == nil { e.ipv4QuerySOA.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryPTR, 64)
    if err == nil { e.ipv4QueryPTR.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryHINFO, 64)
    if err == nil { e.ipv4QueryHINFO.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryMX, 64)
    if err == nil { e.ipv4QueryTXT.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryRP, 64)
    if err == nil { e.ipv4QueryRP.Set(r) }
    r, err = strconv.ParseFloat(ipv4QuerySIG, 64)
    if err == nil { e.ipv4QuerySIG.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryKEY, 64)
    if err == nil { e.ipv4QueryKEY.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryAAAA, 64)
    if err == nil { e.ipv4QueryAAAA.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryAXFR, 64)
    if err == nil { e.ipv4QueryAXFR.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryANY, 64)
    if err == nil { e.ipv4QueryANY.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryTOTAL, 64)
    if err == nil { e.ipv4QueryTOTAL.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryOTHER, 64)
    if err == nil { e.ipv4QueryOTHER.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryNOTAUTH, 64)
    if err == nil { e.ipv4QueryNOTAUTH.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryNOTIMPL, 64)
    if err == nil { e.ipv4QueryNOTIMPL.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryBADCLASS, 64)
    if err == nil { e.ipv4QueryBADCLASS.Set(r) }
    r, err = strconv.ParseFloat(ipv4QueryNOQUERY, 64)
    if err == nil { e.ipv4QueryNOQUERY.Set(r) }

    r, err = strconv.ParseFloat(ipv6QueryA, 64)
    if err == nil { e.ipv6QueryA.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryNS, 64)
    if err == nil { e.ipv6QueryNS.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryCNAME, 64)
    if err == nil { e.ipv6QueryCNAME.Set(r) }
    r, err = strconv.ParseFloat(ipv6QuerySOA, 64)
    if err == nil { e.ipv6QuerySOA.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryPTR, 64)
    if err == nil { e.ipv6QueryPTR.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryHINFO, 64)
    if err == nil { e.ipv6QueryHINFO.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryMX, 64)
    if err == nil { e.ipv6QueryTXT.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryRP, 64)
    if err == nil { e.ipv6QueryRP.Set(r) }
    r, err = strconv.ParseFloat(ipv6QuerySIG, 64)
    if err == nil { e.ipv6QuerySIG.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryKEY, 64)
    if err == nil { e.ipv6QueryKEY.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryAAAA, 64)
    if err == nil { e.ipv6QueryAAAA.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryAXFR, 64)
    if err == nil { e.ipv6QueryAXFR.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryANY, 64)
    if err == nil { e.ipv6QueryANY.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryTOTAL, 64)
    if err == nil { e.ipv6QueryTOTAL.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryOTHER, 64)
    if err == nil { e.ipv6QueryOTHER.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryNOTAUTH, 64)
    if err == nil { e.ipv6QueryNOTAUTH.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryNOTIMPL, 64)
    if err == nil { e.ipv4QueryNOTIMPL.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryBADCLASS, 64)
    if err == nil { e.ipv4QueryBADCLASS.Set(r) }
    r, err = strconv.ParseFloat(ipv6QueryNOQUERY, 64)
    if err == nil { e.ipv4QueryNOQUERY.Set(r) }
 
    return nil
}

// Collect fetches the stats of a user and delivers them
// as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock() // To protect metrics from concurrent collects.
	defer e.mutex.Unlock()
        if err := e.scrape(ch); err != nil {
		log.Infof("Error scraping tinystats: %s", err)
	}
        e.ipv4QueryA.Collect(ch)
        e.ipv4QueryNS.Collect(ch)
        e.ipv4QueryCNAME.Collect(ch)
        e.ipv4QuerySOA.Collect(ch)
        e.ipv4QueryPTR.Collect(ch)
        e.ipv4QueryHINFO.Collect(ch)
        e.ipv4QueryMX.Collect(ch)
        e.ipv4QueryTXT.Collect(ch)
        e.ipv4QueryRP.Collect(ch)
        e.ipv4QuerySIG.Collect(ch)
        e.ipv4QueryKEY.Collect(ch)
        e.ipv4QueryAAAA.Collect(ch)
        e.ipv4QueryAXFR.Collect(ch)
        e.ipv4QueryANY.Collect(ch)
        e.ipv4QueryTOTAL.Collect(ch)
        e.ipv4QueryOTHER.Collect(ch)
        e.ipv4QueryNOTAUTH.Collect(ch)
        e.ipv4QueryNOTIMPL.Collect(ch)
        e.ipv4QueryBADCLASS.Collect(ch)
        e.ipv4QueryNOQUERY.Collect(ch)

        e.ipv6QueryA.Collect(ch)
        e.ipv6QueryNS.Collect(ch)
        e.ipv6QueryCNAME.Collect(ch)
        e.ipv6QuerySOA.Collect(ch)
        e.ipv6QueryPTR.Collect(ch)
        e.ipv6QueryHINFO.Collect(ch)
        e.ipv6QueryMX.Collect(ch)
        e.ipv6QueryTXT.Collect(ch)
        e.ipv6QueryRP.Collect(ch)
        e.ipv6QuerySIG.Collect(ch)
        e.ipv6QueryKEY.Collect(ch)
        e.ipv6QueryAAAA.Collect(ch)
        e.ipv6QueryAXFR.Collect(ch)
        e.ipv6QueryANY.Collect(ch)
        e.ipv6QueryTOTAL.Collect(ch)
        e.ipv6QueryOTHER.Collect(ch)
        e.ipv6QueryNOTAUTH.Collect(ch)
        e.ipv6QueryNOTIMPL.Collect(ch)
        e.ipv6QueryBADCLASS.Collect(ch)
        e.ipv6QueryNOQUERY.Collect(ch)

	return
}

func main() {
	flag.Parse()
	exporter := NewTinystatsExporter()
	prometheus.MustRegister(exporter)
	http.Handle(*metricsPath, prometheus.Handler())
        http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	    w.Write([]byte(`<html>
                <head><title>Tinystats Exporter</title></head>
                <body>
                   <h1>Tinystats Exporter</h1>
                   <p><a href='` + *metricsPath + `'>Metrics</a></p>
                   </body>
                </html>
              `))
	})
	log.Infof("Starting Server: %s", *listenAddress)
	log.Infof("ipv4tinystats file: %s", *ipv4TinystatsFile)
	log.Infof("ipv6tinystats file: %s", *ipv6TinystatsFile)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
