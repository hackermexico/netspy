	package main

	import (
		"bufio"
		"context"
		"encoding/hex"
		"encoding/json"
		"errors"
		"fmt"
		"io"
		"log"
		"net"
		"os"
		"os/exec"
		"path/filepath"
		"runtime"
		"strconv"
		"strings"
		"sync"
		"sync/atomic"
		"time"
		"regexp"

		"github.com/fatih/color"
		"github.com/google/gopacket"
		"github.com/google/gopacket/layers"
		"github.com/google/gopacket/pcap"
		"github.com/google/gopacket/pcapgo"
	)

	// ------------------------ Configuration & Globals ------------------------

	const (
		DefaultSnapLen       = 1600
		DefaultPromiscuous   = true
		DefaultTimeout       = pcap.BlockForever
		AlertsFilename       = "netspy_alerts.jsonl"
		DefaultPcapOut       = "netspypro_capture.pcap"
		DefaultMitmListen    = "8080"
		DefaultExportBufSize = 10000
	)

	var (
		colAlert = color.New(color.FgHiRed, color.Bold).SprintFunc()
		colInfo  = color.New(color.FgHiGreen).SprintFunc()
		colWarn  = color.New(color.FgHiYellow).SprintFunc()
		colMuted = color.New(color.FgHiBlack).SprintFunc()

		// Precompiled regex patterns for sensitive data
		sensitivePatterns []*CompiledPattern

		// Counters
		counterCaptured uint64
		counterAnalyzed uint64
		counterAlerts   uint64
		counterDropped  uint64
		counterExported uint64
		counterShown    uint64
		counterBytes    uint64

		// Buffer pool to reduce allocations
		bufPool *sync.Pool

		// Active exporter
		globalExporter *ExportBuffer

		// Application signatures (domain contains -> app)
		appSignatures = map[string]string{
			"web.whatsapp.com":     "WhatsApp Web",
			"web.telegram.org":     "Telegram Web",
			"api.telegram.org":     "Telegram API",
			"messenger.com":        "Facebook Messenger",
			"facebook.com":         "Facebook",
			"upload.twitter.com":   "X (Twitter)",
			"api.twitter.com":      "X (Twitter)",
			"twitter.com":          "X (Twitter)",
			"api.push.apple.com":   "Apple Push",
			"api.stripe.com":       "Stripe",
			"paypal.com":           "PayPal",
			"accounts.google.com":  "Google Accounts",
			"login.live.com":       "Microsoft Login",
			"auth0.com":            "Auth0",
			"github.com":           "GitHub",
			"gitlab.com":           "GitLab",
			"slack.com":            "Slack",
			"api.slack.com":        "Slack API",
			"discord.com":          "Discord",
			"accounts.google":      "Google",
			"appleid.apple.com":    "AppleID",
			"bank":                 "Bank-related",
			"paypal":               "PayPal",
		}

		// runtime state
		state = &State{
			Stealth:     false,
			DumpHex:     false,
			RateLimit:   0,
			PCAPWrite:   false,
			PCAPOutFile: DefaultPcapOut,
			Filters:     NewFilters(),
		}
	)

	// ------------------------ Types ------------------------

	// State holds runtime options, protected by RWMutex where needed.
	type State struct {
		sync.RWMutex
		Stealth     bool
		DumpHex     bool
		RateLimit   int // prints per second (0 = unlimited)
		PCAPWrite   bool
		PCAPOutFile string
		Filters     *Filters
	}

	// CompiledPattern wraps regexp-like logic; using string match for speed in many cases
	type CompiledPattern struct {
		Name string
		Re   *regexpLike
	}

	// We will implement a lightweight regexp-like structure to avoid importing regexp repeatedly.
	// But to keep complexity reasonable, we will implement a minimal wrapper around Go's regexp.
	type regexpLike struct {
		raw string
		// For simplicity and robustness we use Go's regexp internally.
		re *regexpWrapper
	}

	// ExportBuffer handles PCAP writing asynchronously
	type ExportBuffer struct {
		sync.Mutex
		file       *os.File
		writer     *pcapgo.Writer
		buf        chan gopacket.Packet
		closing    bool
		closeSig   chan struct{}
		wg         sync.WaitGroup
		bytesSaved uint64
	}

	// Filters for capture
	type Filters struct {
		sync.RWMutex
		Protocol string   // tcp/udp/http/https
		Ports    []int    // explicit ports
		SrcIPs   []string // source IP filters (substr match)
		DstIPs   []string // dest IP filters (substr match)
		BPF      string   // raw BPF expression (overrides certain built ones)
	}

	// Alert structure (JSONL)
	type Alert struct {
		Time        time.Time `json:"time"`
		Interface   string    `json:"interface"`
		Src         string    `json:"src"`
		Dst         string    `json:"dst"`
		Protocol    string    `json:"protocol"`
		App         string    `json:"app,omitempty"`
		Reason      string    `json:"reason"`
		Snippet     string    `json:"snippet"`
		PacketLen   int       `json:"packet_len"`
		Hostnames   []string  `json:"hostnames,omitempty"`
		HexDumpFile string    `json:"hexdump_file,omitempty"`
	}

	// CaptureTask holds pcap handle and control channels
	type CaptureTask struct {
		iface   string
		handle  *pcap.Handle
		stop    chan struct{}
		export  *ExportBuffer
		workers int
		bpf     string
	}

	// ------------------------ Minimal regexp wrapper ------------------------

	/*
	We create a small wrapper around Go's regexp to:
	 - Keep the code straightforward.
	 - Precompile patterns once.
	*/


	type regexpWrapper struct {
		r *regexp.Regexp
	}

	func compileRegexp(s string) (*regexpWrapper, error) {
		r, err := regexp.Compile(s)
		if err != nil {
			return nil, err
		}
		return &regexpWrapper{r: r}, nil
	}

	func (rw *regexpWrapper) MatchString(s string) bool {
		return rw.r.MatchString(s)
	}

	func (rw *regexpWrapper) FindString(s string) string {
		return rw.r.FindString(s)
	}

	// regexpLike constructor
	func newRegexpLike(raw string) (*regexpLike, error) {
		rw, err := compileRegexp(raw)
		if err != nil {
			return nil, err
		}
		return &regexpLike{raw: raw, re: rw}, nil
	}

	// Match wrapper
	func (r *regexpLike) Match(s string) bool {
		if r == nil || r.re == nil {
			return false
		}
		return r.re.MatchString(s)
	}

	// Find wrapper
	func (r *regexpLike) Find(s string) string {
		if r == nil || r.re == nil {
			return ""
		}
		return r.re.FindString(s)
	}

	// ------------------------ Initialization ------------------------

	func init() {
		// Buffer pool
		bufPool = &sync.Pool{
			New: func() interface{} {
				b := make([]byte, 0, 4096)
				return &b
			},
		}

		// Precompile patterns (broad, tune in lab)
		patterns := map[string]string{
			"password":      `(?i)password[^A-Za-z0-9]{0,3}[:=]\s*["']?[A-Za-z0-9!@#\$%\^&\*\(\)_\-\+=]{3,}`,
			"token":         `(?i)token[^A-Za-z0-9]{0,3}[:=]\s*[A-Za-z0-9\-\._]{8,}`,
			"apikey":        `(?i)api[_-]?key[^A-Za-z0-9]{0,3}[:=]\s*[A-Za-z0-9\-\._]{8,}`,
			"authorization": `(?i)authorization[^A-Za-z0-9]{0,3}[:=]\s*["']?Bearer\s+[A-Za-z0-9\-\._]{10,}`,
			"privatekey":    `(?i)-----BEGIN (RSA |)?PRIVATE KEY-----`,
			"ssh-rsa":       `(?i)ssh-rsa\s+[A-Za-z0-9+/=]{100,}`,
			"jwt":           `(?i)[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}`,
		}

		for name, pat := range patterns {
			r, err := newRegexpLike(pat)
			if err != nil {
				log.Printf("failed compiling pattern %s: %v", name, err)
				continue
			}
			sensitivePatterns = append(sensitivePatterns, &CompiledPattern{
				Name: name,
				Re:   r,
			})
		}
	}

	// CompiledPattern wrapper methods
	func (cp *CompiledPattern) Match(s string) bool {
		return cp.Re.Match(s)
	}

	func (cp *CompiledPattern) Find(s string) string {
		return cp.Re.Find(s)
	}

	// ------------------------ Filters helpers ------------------------

	func NewFilters() *Filters {
		return &Filters{
			Protocol: "",
			Ports:    []int{},
			SrcIPs:   []string{},
			DstIPs:   []string{},
			BPF:      "",
		}
	}

	func (f *Filters) Matches(pkt gopacket.Packet) bool {
		f.RLock()
		defer f.RUnlock()

		// Protocol check
		if f.Protocol != "" {
			switch strings.ToLower(f.Protocol) {
			case "tcp":
				if pkt.TransportLayer() == nil || pkt.TransportLayer().LayerType() != layers.LayerTypeTCP {
					return false
				}
			case "udp":
				if pkt.TransportLayer() == nil || pkt.TransportLayer().LayerType() != layers.LayerTypeUDP {
					return false
				}
			case "http":
				// check ports 80/8080
				if !portInPacket(pkt, []int{80, 8080, 8000}) {
					return false
				}
			case "https":
				if !portInPacket(pkt, []int{443, 8443}) {
					return false
				}
			default:
				// unknown -> pass
			}
		}

		// Ports
		if len(f.Ports) > 0 {
			if !portInPacket(pkt, f.Ports) {
				return false
			}
		}

		// IPs
		if len(f.SrcIPs) > 0 || len(f.DstIPs) > 0 {
			netLayer := pkt.NetworkLayer()
			if netLayer == nil {
				return false
			}
			src := netLayer.NetworkFlow().Src().String()
			dst := netLayer.NetworkFlow().Dst().String()
			if len(f.SrcIPs) > 0 {
				match := false
				for _, s := range f.SrcIPs {
					if strings.Contains(src, s) {
						match = true
						break
					}
				}
				if !match {
					return false
				}
			}
			if len(f.DstIPs) > 0 {
				match := false
				for _, s := range f.DstIPs {
					if strings.Contains(dst, s) {
						match = true
						break
					}
				}
				if !match {
					return false
				}
			}
		}

		// BPF not applied here (applied at capture)
		return true
	}

	func portInPacket(pkt gopacket.Packet, ports []int) bool {
		tl := pkt.TransportLayer()
		if tl == nil {
			return false
		}
		switch v := tl.(type) {
		case *layers.TCP:
			for _, p := range ports {
				if int(v.SrcPort) == p || int(v.DstPort) == p {
					return true
				}
			}
		case *layers.UDP:
			for _, p := range ports {
				if int(v.SrcPort) == p || int(v.DstPort) == p {
					return true
				}
			}
		default:
			_ = v
		}
		return false
	}

	// ------------------------ ExportBuffer (PCAP writer) ------------------------

	func NewExportBuffer(filename string, bufsize int) (*ExportBuffer, error) {
		f, err := os.Create(filename)
		if err != nil {
			return nil, err
		}
		w := pcapgo.NewWriter(f)
		if err := w.WriteFileHeader(DefaultSnapLen, layers.LinkTypeEthernet); err != nil {
			f.Close()
			return nil, err
		}
		eb := &ExportBuffer{
			file:     f,
			writer:   w,
			buf:      make(chan gopacket.Packet, bufsize),
			closeSig: make(chan struct{}),
		}
		eb.wg.Add(1)
		go eb.loop()
		return eb, nil
	}

	func (eb *ExportBuffer) loop() {
		defer eb.wg.Done()
		for {
			select {
			case pkt, ok := <-eb.buf:
				if !ok {
					return
				}
				data := pkt.Data()
				ci := pkt.Metadata().CaptureInfo
				if err := eb.writer.WritePacket(ci, data); err != nil {
					log.Printf("pcap write error: %v", err)
					continue
				}
				atomic.AddUint64(&eb.bytesSaved, uint64(len(data)))
				atomic.AddUint64(&counterExported, 1)
			case <-eb.closeSig:
				return
			}
		}
	}

	func (eb *ExportBuffer) Push(pkt gopacket.Packet) {
		eb.Lock()
		if eb.closing {
			eb.Unlock()
			return
		}
		eb.Unlock()
		select {
		case eb.buf <- pkt:
		default:
			// drop if full
			atomic.AddUint64(&counterDropped, 1)
		}
	}

	func (eb *ExportBuffer) Close() {
		eb.Lock()
		if eb.closing {
			eb.Unlock()
			return
		}
		eb.closing = true
		close(eb.buf)
		eb.Unlock()
		eb.wg.Wait()
		eb.file.Close()
		close(eb.closeSig)
	}

	// ------------------------ Packet analysis ------------------------

	func analyzePacket(pkt gopacket.Packet, iface string, exporter *ExportBuffer) {
		atomic.AddUint64(&counterAnalyzed, 1)

		// Quick filters
		if !state.Filters.Matches(pkt) {
			atomic.AddUint64(&counterDropped, 1)
			return
		}

		// Optionally export
		if state.PCAPWrite && exporter != nil {
			exporter.Push(pkt)
		}

		// Basic metadata
		netL := pkt.NetworkLayer()
		trL := pkt.TransportLayer()
		length := len(pkt.Data())
		src := "?"
		dst := "?"
		proto := "unknown"

		if netL != nil {
			src = netL.NetworkFlow().Src().String()
			dst = netL.NetworkFlow().Dst().String()
		}
		if trL != nil {
			proto = trL.LayerType().String()
		}

		// Compute payload
		var payload []byte
		if app := pkt.ApplicationLayer(); app != nil {
			payload = app.Payload()
		} else if trL != nil {
			switch t := trL.(type) {
			case *layers.TCP:
				payload = t.Payload
			case *layers.UDP:
				payload = t.Payload
			default:
				_ = t
			}
		}

		atomic.AddUint64(&counterCaptured, 1)
		atomic.AddUint64(&counterBytes, uint64(length))

		// No payload
		if len(payload) == 0 {
			if !state.Stealth {
				atomic.AddUint64(&counterShown, 1)
				fmt.Printf("%s %s -> %s %s %d bytes\n", colMuted(now()), src, dst, colInfo(proto), length)
			}
			return
		}

		// Inspect payload (limit)
		limit := 4096
		inspect := payload
		if len(inspect) > limit {
			inspect = inspect[:limit]
		}
		text := string(inspect)

		// App classification
		app := classifyAppFromPacket(pkt, text)

		// Pattern scanning
		found, reason, snippet := scanSensitive(text)
		if !found {
			// additional heuristic: forms
			low := strings.ToLower(text)
			if strings.Contains(low, "password=") || strings.Contains(low, "passwd=") || strings.Contains(low, "login=") || strings.Contains(low, "username=") {
				found = true
				reason = "form-credential-like"
				snippet = safeSnippet(text, 300)
			}
		}

		// If found -> alert
		if found {
			atomic.AddUint64(&counterAlerts, 1)

			// perform reverse DNS lookup on IPs (best-effort)
			hostnames := resolveIPs([]string{src, dst})

			alert := &Alert{
				Time:      time.Now().UTC(),
				Interface: iface,
				Src:       src,
				Dst:       dst,
				Protocol:  proto,
				App:       app,
				Reason:    reason,
				Snippet:   snippet,
				PacketLen: length,
				Hostnames: hostnames,
			}

			// optionally hexdump payload to file and include path
			if state.DumpHex {
				if fn, err := hexdumpToFile("alert", payload); err == nil {
					alert.HexDumpFile = fn
				}
			}

			saveAlert(alert)
			printAlert(alert, payload)
			return
		}

		// Not an alert: print summary depending on stealth and rate limit
		if state.Stealth {
			return
		}
		// Rate limiting (if set)
		if state.RateLimit > 0 {
			// compute sleep to roughly keep rate; simple approach
			time.Sleep(time.Duration(1000/state.RateLimit) * time.Millisecond)
		}

		atomic.AddUint64(&counterShown, 1)
		trunc := safeSnippet(text, 200)
		fmt.Printf("%s %s -> %s %s %d bytes | %s\n", colMuted(now()), src, dst, colInfo(app+" "+proto), length, trunc)

		if state.DumpHex {
			dumpHexAscii(payload)
		}
	}

	func scanSensitive(text string) (bool, string, string) {
		for _, cp := range sensitivePatterns {
			if cp.Match(text) {
				found := cp.Find(text)
				return true, cp.Name, safeSnippet(found, 300)
			}
		}
		return false, "", ""
	}

	func classifyAppFromPacket(pkt gopacket.Packet, payloadText string) string {
		// Check Host header in payload for common web apps, else check IP->domain maybe later
		low := strings.ToLower(payloadText)
		if strings.Contains(low, "host: web.whatsapp.com") || strings.Contains(low, "web.whatsapp.com") {
			return "WhatsApp Web"
		}
		if strings.Contains(low, "host: web.telegram.org") || strings.Contains(low, "web.telegram.org") || strings.Contains(low, "api.telegram.org") {
			return "Telegram"
		}
		if strings.Contains(low, "host: messenger.com") || strings.Contains(low, "facebook.com") || strings.Contains(low, "host: graph.facebook.com") {
			return "Facebook/Meta"
		}
		if strings.Contains(low, "host: api.twitter.com") || strings.Contains(low, "twitter.com") || strings.Contains(low, "x.com") {
			return "X (Twitter)"
		}
		// fallback: check destination IP against appSignatures via reverse lookup? expensive; skip.
		return "Generic"
	}

	// ------------------------ Utilities ------------------------

	func now() string {
		return time.Now().Format("2006-01-02 15:04:05")
	}

	func safeSnippet(s string, max int) string {
		if len(s) <= max {
			return s
		}
		return s[:max] + "..."
	}

	func hexdumpToFile(prefix string, data []byte) (string, error) {
		fn := fmt.Sprintf("%s_hexdump_%d.txt", prefix, time.Now().UnixNano())
		f, err := os.Create(fn)
		if err != nil {
			return "", err
		}
		defer f.Close()
		const width = 16
		for off := 0; off < len(data); off += width {
			end := off + width
			if end > len(data) {
				end = len(data)
			}
			chunk := data[off:end]
			hexPart := hex.EncodeToString(chunk)
			hexSpaced := ""
			for i := 0; i < len(hexPart); i += 2 {
				hexSpaced += hexPart[i:i+2] + " "
			}
			ascii := ""
			for _, b := range chunk {
				if b >= 32 && b <= 126 {
					ascii += string(b)
				} else {
					ascii += "."
				}
			}
			fmt.Fprintf(f, "%04x  %-48s  %s\n", off, hexSpaced, ascii)
		}
		return fn, nil
	}

	func dumpHexAscii(data []byte) {
		const width = 16
		for off := 0; off < len(data); off += width {
			end := off + width
			if end > len(data) {
				end = len(data)
			}
			chunk := data[off:end]
			hexPart := hex.EncodeToString(chunk)
			hexSpaced := ""
			for i := 0; i < len(hexPart); i += 2 {
				hexSpaced += hexPart[i:i+2] + " "
			}
			ascii := ""
			for _, b := range chunk {
				if b >= 32 && b <= 126 {
					ascii += string(b)
				} else {
					ascii += "."
				}
			}
			fmt.Printf("%04x  %-48s  %s\n", off, hexSpaced, ascii)
		}
	}

	func saveAlert(a *Alert) {
		f, err := os.OpenFile(AlertsFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			log.Printf("no se pudo abrir archivo de alertas: %v", err)
			return
		}
		defer f.Close()
		js, _ := json.Marshal(a)
		f.WriteString(string(js) + "\n")
	}

	// Reverse DNS lookups for a list of IPs; returns unique hostnames (best-effort)
	func resolveIPs(ips []string) []string {
		out := []string{}
		seen := map[string]bool{}
		for _, ip := range ips {
			// strip port if present
			if strings.Contains(ip, ":") {
				parts := strings.Split(ip, ":")
				ip = parts[0]
			}
			addrs, err := net.LookupAddr(ip)
			if err == nil {
				for _, a := range addrs {
					a = strings.TrimSuffix(a, ".")
					if !seen[a] {
						out = append(out, a)
						seen[a] = true
					}
				}
			}
		}
		return out
	}

	func printAlert(a *Alert, payload []byte) {
		fmt.Println()
		fmt.Printf("%s %s ALERT %s -> %s (%s) len=%d\n", colAlert("!!!"), now(), a.Src, a.Dst, a.Protocol, a.PacketLen)
		if a.App != "" {
			fmt.Printf("App: %s\n", colInfo(a.App))
		}
		fmt.Printf("Reason: %s\n", a.Reason)
		fmt.Printf("Snippet: %s\n", a.Snippet)
		if len(a.Hostnames) > 0 {
			fmt.Printf("Hostnames: %v\n", a.Hostnames)
		}
		if state.DumpHex && len(payload) > 0 {
			fmt.Println(colWarn("--- Hex dump (truncated) ---"))
			limit := 1024
			if len(payload) < limit {
				limit = len(payload)
			}
			dumpHexAscii(payload[:limit])
		}
		fmt.Println()
	}

	// ------------------------ Capture orchestration ------------------------

	func listInterfaces() ([]pcap.Interface, error) {
		ifaces, err := pcap.FindAllDevs()
		if err != nil {
			return nil, err
		}
		fmt.Println(colInfo("Interfaces encontradas:"))
		for i, it := range ifaces {
			desc := it.Description
			if desc == "" {
				desc = "sin descripción"
			}
			fmt.Printf("[%d] %s : %s\n", i, it.Name, desc)
			for _, a := range it.Addresses {
				fmt.Printf("     - %s / %s\n", a.IP.String(), a.Netmask.String())
			}
		}
		return ifaces, nil
	}

	func chooseInterfaceInteractive() (string, error) {
		ifaces, err := listInterfaces()
		if err != nil {
			return "", err
		}
		if len(ifaces) == 0 {
			return "", errors.New("no hay interfaces disponibles")
		}
		fmt.Print("Selecciona interfaz (número): ")
		var idx int
		_, err = fmt.Scan(&idx)
		if err != nil {
			return "", err
		}
		if idx < 0 || idx >= len(ifaces) {
			return "", errors.New("índice fuera de rango")
		}
		return ifaces[idx].Name, nil
	}

	func buildBPF(f *Filters) string {
		f.RLock()
		defer f.RUnlock()
		parts := []string{}
		if f.BPF != "" {
			parts = append(parts, "("+f.BPF+")")
		}
		// Protocol
		if f.Protocol != "" {
			switch strings.ToLower(f.Protocol) {
			case "tcp":
				parts = append(parts, "tcp")
			case "udp":
				parts = append(parts, "udp")
			case "http":
				parts = append(parts, "tcp and (port 80 or port 8080 or port 8000)")
			case "https":
				parts = append(parts, "tcp and (port 443 or port 8443)")
			}
		}
		// Ports
		if len(f.Ports) > 0 {
			pParts := []string{}
			for _, p := range f.Ports {
				pParts = append(pParts, fmt.Sprintf("port %d", p))
			}
			parts = append(parts, "("+strings.Join(pParts, " or ")+")")
		}
		// IPs
		if len(f.SrcIPs) > 0 {
			src := []string{}
			for _, s := range f.SrcIPs {
				src = append(src, fmt.Sprintf("src host %s", s))
			}
			parts = append(parts, "("+strings.Join(src, " or ")+")")
		}
		if len(f.DstIPs) > 0 {
			dst := []string{}
			for _, s := range f.DstIPs {
				dst = append(dst, fmt.Sprintf("dst host %s", s))
			}
			parts = append(parts, "("+strings.Join(dst, " or ")+")")
		}
		if len(parts) == 0 {
			return ""
		}
		return strings.Join(parts, " and ")
	}

	func startCapture(ctx context.Context, iface string, snaplen int32, promisc bool, timeout time.Duration, bpf string, exporter *ExportBuffer, workers int) (*CaptureTask, error) {
		handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
		if err != nil {
			return nil, fmt.Errorf("pcap.OpenLive error: %v", err)
		}
		if bpf != "" {
			if err := handle.SetBPFFilter(bpf); err != nil {
				handle.Close()
				return nil, fmt.Errorf("failed to set BPF: %v", err)
			}
		}
		task := &CaptureTask{
			iface:   iface,
			handle:  handle,
			stop:    make(chan struct{}),
			export:  exporter,
			workers: workers,
			bpf:     bpf,
		}

		// Packet source
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		packetChan := src.Packets()

		// Worker pool
		for i := 0; i < workers; i++ {
			go func(id int) {
				for {
					select {
					case pkt, ok := <-packetChan:
						if !ok {
							return
						}
						analyzePacket(pkt, iface, exporter)
					case <-task.stop:
						return
					case <-ctx.Done():
						return
					}
				}
			}(i)
		}

		// Monitor context cancellation: close handle when ctx done
		go func() {
			<-ctx.Done()
			handle.Close()
		}()

		return task, nil
	}

	func stopCapture(task *CaptureTask) {
		close(task.stop)
		if task.handle != nil {
			task.handle.Close()
		}
		if task.export != nil {
			task.export.Close()
		}
		// small wait for goroutines to drain
		time.Sleep(200 * time.Millisecond)
	}

	// ------------------------ Interactive CLI & Controls ------------------------

	func printHeaderSimple() {
		fmt.Println(colInfo("NetSpyPro v1.0 - Sniffer ético (modo pro)"))
		fmt.Println(colMuted("Uso responsable: solo en entornos controlados y con permiso."))
		fmt.Println()
	}

	func showMenu() {
		printHeaderSimple()
		fmt.Println("1) Listar interfaces")
		fmt.Println("2) Configurar filtros")
		fmt.Println("3) Iniciar captura")
		fmt.Println("4) Iniciar captura y exportar PCAP")
		fmt.Println("5) Mostrar métricas")
		fmt.Println("6) Toggle stealth mode (solo alertas)")
		fmt.Println("7) Toggle dump HEX/ASCII")
		fmt.Println("8) Iniciar mitmproxy (opcional)")
		fmt.Println("9) Mostrar últimas alertas")
		fmt.Println("10) Guardar / Cargar perfil de filtros")
		fmt.Println("0) Salir")
		fmt.Print("Opción: ")
	}

	func main() {
		// Use all CPU cores
		runtime.GOMAXPROCS(runtime.NumCPU())

		reader := bufio.NewReader(os.Stdin)

		// Start stats reporter goroutine
		ctxStats, cancelStats := context.WithCancel(context.Background())
		go statsReporter(ctxStats)

		for {
			showMenu()
			choice, _ := reader.ReadString('\n')
			choice = strings.TrimSpace(choice)
			switch choice {
			case "1":
				_, err := listInterfaces()
				if err != nil {
					fmt.Println(colWarn("error listando interfaces:"), err)
				}
				pause()
			case "2":
				configureFilters(reader)
			case "3":
				iface, err := chooseInterfaceInteractive()
				if err != nil {
					fmt.Println(colWarn(err))
					pause()
					continue
				}
				bpf := buildBPF(state.Filters)
				fmt.Println(colInfo("BPF:"), bpf)
				// exporter nil
				ctxCap, cancelCap := context.WithCancel(context.Background())
				exporter := (*ExportBuffer)(nil)
				globalExporter = exporter
				workers := runtime.NumCPU()
				task, err := startCapture(ctxCap, iface, DefaultSnapLen, DefaultPromiscuous, DefaultTimeout, bpf, exporter, workers)
				if err != nil {
					fmt.Println(colWarn("error iniciando captura:"), err)
					cancelCap()
					pause()
					continue
				}
				fmt.Println(colInfo("Captura iniciada en"), iface)
				fmt.Println(colMuted("Presiona ENTER para detener captura..."))
				reader.ReadString('\n')
				cancelCap()
				stopCapture(task)
				fmt.Println(colInfo("Captura detenida"))
				pause()
			case "4":
				iface, err := chooseInterfaceInteractive()
				if err != nil {
					fmt.Println(colWarn(err))
					pause()
					continue
				}
				bpf := buildBPF(state.Filters)
				fmt.Println(colInfo("BPF:"), bpf)
				fmt.Printf("Nombre archivo PCAP (enter = %s): ", state.PCAPOutFile)
				outf, _ := reader.ReadString('\n')
				outf = strings.TrimSpace(outf)
				if outf != "" {
					state.PCAPOutFile = outf
				}
				exporter, err := NewExportBuffer(state.PCAPOutFile, DefaultExportBufSize)
				if err != nil {
					fmt.Println(colWarn("no se pudo crear PCAP writer:"), err)
					pause()
					continue
				}
				state.PCAPWrite = true
				globalExporter = exporter
				ctxCap, cancelCap := context.WithCancel(context.Background())
				workers := runtime.NumCPU()
				task, err := startCapture(ctxCap, iface, DefaultSnapLen, DefaultPromiscuous, DefaultTimeout, bpf, exporter, workers)
				if err != nil {
					fmt.Println(colWarn("error iniciando captura:"), err)
					cancelCap()
					exporter.Close()
					pause()
					continue
				}
				fmt.Println(colInfo("Captura + export PCAP iniciada en"), iface)
				fmt.Println(colMuted("Presiona ENTER para detener captura..."))
				reader.ReadString('\n')
				cancelCap()
				stopCapture(task)
				fmt.Println(colInfo("Captura detenida"))
				fmt.Printf("PCAP guardado en %s (bytes ~ %s)\n", state.PCAPOutFile, humanBytes(atomic.LoadUint64(&exporter.bytesSaved)))
				globalExporter = nil
				state.PCAPWrite = false
				pause()
			case "5":
				printMetrics()
				pause()
			case "6":
				toggleStealth()
				pause()
			case "7":
				toggleDumpHex()
				pause()
			case "8":
				err := startMitmProxy(DefaultMitmListen)
				if err != nil {
					fmt.Println(colWarn("Error iniciando mitmproxy:"), err)
				} else {
					fmt.Println(colInfo("mitmproxy iniciado en puerto " + DefaultMitmListen))
				}
				pause()
			case "9":
				showLastAlerts()
				pause()
			case "10":
				configProfile(reader)
			case "0":
				fmt.Println(colInfo("Saliendo..."))
				cancelStats()
				return
			default:
				fmt.Println(colWarn("Opción inválida"))
				pause()
			}
		}
	}

	// ------------------------ Interactive subroutines ------------------------

	func pause() {
		fmt.Println(colMuted("Presiona ENTER para continuar..."))
		bufio.NewReader(os.Stdin).ReadBytes('\n')
	}

	func configureFilters(reader *bufio.Reader) {
		fmt.Println(colInfo("Configurar filtros (dejar vacío para mantener):"))

		// Protocol
		fmt.Printf("Protocolo actual: %s. Nuevo (tcp/udp/http/https): ", state.Filters.Protocol)
		proto, _ := reader.ReadString('\n')
		proto = strings.TrimSpace(proto)
		if proto != "" {
			state.Filters.Lock()
			state.Filters.Protocol = proto
			state.Filters.Unlock()
		}

		// Ports
		fmt.Printf("Puertos actuales: %v. Nuevo (ej: 80,443 o 8000-8010): ", state.Filters.Ports)
		portsLine, _ := reader.ReadString('\n')
		portsLine = strings.TrimSpace(portsLine)
		if portsLine != "" {
			ports := parsePorts(portsLine)
			state.Filters.Lock()
			state.Filters.Ports = ports
			state.Filters.Unlock()
		}

		// Src IPs
		fmt.Printf("Src IPs actuales: %v. Nuevo (comma sep): ", state.Filters.SrcIPs)
		srcs, _ := reader.ReadString('\n')
		srcs = strings.TrimSpace(srcs)
		if srcs != "" {
			parts := splitCSV(srcs)
			state.Filters.Lock()
			state.Filters.SrcIPs = parts
			state.Filters.Unlock()
		}

		// Dst IPs
		fmt.Printf("Dst IPs actuales: %v. Nuevo (comma sep): ", state.Filters.DstIPs)
		dsts, _ := reader.ReadString('\n')
		dsts = strings.TrimSpace(dsts)
		if dsts != "" {
			parts := splitCSV(dsts)
			state.Filters.Lock()
			state.Filters.DstIPs = parts
			state.Filters.Unlock()
		}

		// BPF
		fmt.Printf("BPF actual: %s. Nuevo BPF (blank para mantener): ", state.Filters.BPF)
		bpf, _ := reader.ReadString('\n')
		bpf = strings.TrimSpace(bpf)
		if bpf != "" {
			state.Filters.Lock()
			state.Filters.BPF = bpf
			state.Filters.Unlock()
		}

		// RateLimit
		fmt.Printf("RateLimit actual: %d. Nuevo (prints per sec, 0 unlimited): ", state.RateLimit)
		rl, _ := reader.ReadString('\n')
		rl = strings.TrimSpace(rl)
		if rl != "" {
			v, err := strconv.Atoi(rl)
			if err == nil {
				state.RateLimit = v
			} else {
				fmt.Println(colWarn("valor rate inválido"))
			}
		}

		// PCAP out
		fmt.Printf("Export PCAP actual: %v. Cambiar nombre archivo (enter para mantener %s): ", state.PCAPWrite, state.PCAPOutFile)
		pfn, _ := reader.ReadString('\n')
		pfn = strings.TrimSpace(pfn)
		if pfn != "" {
			state.PCAPOutFile = pfn
		}

		fmt.Println(colInfo("Filtros actualizados"))
	}

	// Parse port lists like "80,443,8000-8010"
	func parsePorts(s string) []int {
		out := []int{}
		parts := strings.Split(s, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if strings.Contains(p, "-") {
				sp := strings.Split(p, "-")
				if len(sp) == 2 {
					a, err1 := strconv.Atoi(strings.TrimSpace(sp[0]))
					b, err2 := strconv.Atoi(strings.TrimSpace(sp[1]))
					if err1 == nil && err2 == nil && a <= b {
						for i := a; i <= b; i++ {
							out = append(out, i)
						}
					}
				}
			} else {
				v, err := strconv.Atoi(p)
				if err == nil {
					out = append(out, v)
				}
			}
		}
		return out
	}

	func splitCSV(s string) []string {
		out := []string{}
		for _, p := range strings.Split(s, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}

	// ------------------------ Stats reporter ------------------------

	func statsReporter(ctx context.Context) {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				printMetrics()
			}
		}
	}

	func printMetrics() {
		fmt.Println("=== Metrics ===")
		fmt.Printf("Captured pkts: %d\n", atomic.LoadUint64(&counterCaptured))
		fmt.Printf("Analyzed pkts: %d\n", atomic.LoadUint64(&counterAnalyzed))
		fmt.Printf("Shown pkts: %d\n", atomic.LoadUint64(&counterShown))
		fmt.Printf("Alerts: %d\n", atomic.LoadUint64(&counterAlerts))
		fmt.Printf("Exported pkts: %d\n", atomic.LoadUint64(&counterExported))
		fmt.Printf("Dropped (buffer): %d\n", atomic.LoadUint64(&counterDropped))
		fmt.Printf("Bytes processed: %s\n", humanBytes(atomic.LoadUint64(&counterBytes)))
		fmt.Println("================")
	}

	func humanBytes(n uint64) string {
		const unit = 1024
		if n < unit {
			return fmt.Sprintf("%d B", n)
		}
		div, exp := uint64(unit), 0
		for n/div >= unit {
			div *= unit
			exp++
		}
		return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
	}

	// ------------------------ Toggle functions ------------------------

	func toggleStealth() {
		state.Lock()
		state.Stealth = !state.Stealth
		s := "DESACTIVADO"
		if state.Stealth {
			s = "ACTIVADO"
		}
		fmt.Println(colInfo("Stealth mode " + s))
		state.Unlock()
	}

	func toggleDumpHex() {
		state.Lock()
		state.DumpHex = !state.DumpHex
		s := "DESACTIVADO"
		if state.DumpHex {
			s = "ACTIVADO"
		}
		fmt.Println(colInfo("Dump HEX/ASCII " + s))
		state.Unlock()
	}

	// ------------------------ mitmproxy helper ------------------------

	func startMitmProxy(port string) error {
		exe, err := exec.LookPath("mitmproxy")
		if err != nil {
			return fmt.Errorf("mitmproxy no encontrado en PATH")
		}
		logDir := "netspy_mitm_logs"
		_ = os.MkdirAll(logDir, 0755)
		stdoutFile, err := os.Create(filepath.Join(logDir, "mitm_stdout.log"))
		if err != nil {
			return err
		}
		stderrFile, err := os.Create(filepath.Join(logDir, "mitm_stderr.log"))
		if err != nil {
			stdoutFile.Close()
			return err
		}
		cmd := exec.Command(exe, "--listen-port", port)
		cmd.Stdout = stdoutFile
		cmd.Stderr = stderrFile
		if err := cmd.Start(); err != nil {
			stdoutFile.Close()
			stderrFile.Close()
			return err
		}
		fmt.Printf("mitmproxy PID %d iniciado; logs en %s\n", cmd.Process.Pid, logDir)
		return nil
	}

	// ------------------------ Alerts viewing ------------------------

	func showLastAlerts() {
		f, err := os.Open(AlertsFilename)
		if err != nil {
			fmt.Println(colWarn("No hay archivo de alertas o no se puede abrir:"), err)
			return
		}
		defer f.Close()
		fmt.Println(colInfo("Últimas alertas (últimas 200 líneas):"))
		data, _ := io.ReadAll(f)
		lines := strings.Split(string(data), "\n")
		start := 0
		if len(lines) > 200 {
			start = len(lines) - 200
		}
		for i := start; i < len(lines); i++ {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				continue
			}
			fmt.Println(line)
		}
	}

	// ------------------------ Profiles (save/load) ------------------------

	func configProfile(reader *bufio.Reader) {
		fmt.Println("1) Guardar perfil actual")
		fmt.Println("2) Cargar perfil")
		fmt.Print("Opción: ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)
		switch choice {
		case "1":
			fmt.Print("Nombre de perfil (ej: lab1): ")
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			if name == "" {
				fmt.Println(colWarn("nombre vacío"))
				return
			}
			fn := fmt.Sprintf("netspy_profile_%s.json", name)
			saveProfile(fn)
			fmt.Println(colInfo("Perfil guardado en"), fn)
		case "2":
			fmt.Print("Nombre de perfil a cargar: ")
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			if name == "" {
				fmt.Println(colWarn("nombre vacío"))
				return
			}
			fn := fmt.Sprintf("netspy_profile_%s.json", name)
			if err := loadProfile(fn); err != nil {
				fmt.Println(colWarn("error cargando perfil:"), err)
			} else {
				fmt.Println(colInfo("Perfil cargado:"), fn)
			}
		default:
			fmt.Println(colWarn("opción inválida"))
		}
	}

	func saveProfile(filename string) {
		state.Filters.RLock()
		defer state.Filters.RUnlock()
		pro := map[string]interface{}{
			"protocol": state.Filters.Protocol,
			"ports":    state.Filters.Ports,
			"src_ips":  state.Filters.SrcIPs,
			"dst_ips":  state.Filters.DstIPs,
			"bpf":      state.Filters.BPF,
			"ratelimit": state.RateLimit,
			"pcap_out":  state.PCAPOutFile,
		}
		js, _ := json.MarshalIndent(pro, "", "  ")
		_ = os.WriteFile(filename, js, 0644)
	}

	func loadProfile(filename string) error {
		bs, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		var pro map[string]interface{}
		if err := json.Unmarshal(bs, &pro); err != nil {
			return err
		}
		state.Filters.Lock()
		if v, ok := pro["protocol"].(string); ok {
			state.Filters.Protocol = v
		}
		if v, ok := pro["bpf"].(string); ok {
			state.Filters.BPF = v
		}
		if v, ok := pro["ports"].([]interface{}); ok {
			ports := []int{}
			for _, pv := range v {
				switch t := pv.(type) {
				case float64:
					ports = append(ports, int(t))
				case int:
					ports = append(ports, t)
				}
			}
			state.Filters.Ports = ports
		}
		if v, ok := pro["src_ips"].([]interface{}); ok {
			ips := []string{}
			for _, ip := range v {
				if s, ok := ip.(string); ok {
					ips = append(ips, s)
				}
			}
			state.Filters.SrcIPs = ips
		}
		if v, ok := pro["dst_ips"].([]interface{}); ok {
			ips := []string{}
			for _, ip := range v {
				if s, ok := ip.(string); ok {
					ips = append(ips, s)
				}
			}
			state.Filters.DstIPs = ips
		}
		state.Filters.Unlock()
		if v, ok := pro["ratelimit"].(float64); ok {
			state.RateLimit = int(v)
		}
		if v, ok := pro["pcap_out"].(string); ok {
			state.PCAPOutFile = v
		}
		return nil
	}

	// ------------------------ Helpers ------------------------

	func printMetrics2	() {
		printMetricsSimple()
	}

	func printMetricsSimple() {
		fmt.Println("=== NetSpyPro Metrics ===")
		fmt.Printf("Captured: %d\n", atomic.LoadUint64(&counterCaptured))
		fmt.Printf("Analyzed: %d\n", atomic.LoadUint64(&counterAnalyzed))
		fmt.Printf("Shown: %d\n", atomic.LoadUint64(&counterShown))
		fmt.Printf("Alerts: %d\n", atomic.LoadUint64(&counterAlerts))
		fmt.Printf("Exported: %d\n", atomic.LoadUint64(&counterExported))
		fmt.Printf("Dropped: %d\n", atomic.LoadUint64(&counterDropped))
		fmt.Printf("Bytes: %s\n", humanBytes(atomic.LoadUint64(&counterBytes)))
		fmt.Println("=========================")
	}

	// ------------------------ End ------------------------

