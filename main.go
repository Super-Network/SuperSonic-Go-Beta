package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)
// lots of peopel so we need speed
const (
	ListenAddr      = "localhost:8080"
	FrontendPath    = "proxy.html"
  // maybe i should make user agent changeable
	UserAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
  MaxIdleConns        = 10000
	MaxIdleConnsPerHost = 1000
	IdleConnTimeout     = 180 * time.Second
	TLSHandshakeTimeout = 10 * time.Second
	ResponseHeaderTimeout = 30 * time.Second
	
	BufferSize = 32 * 1024 
	
	CookieHostKey = "__supersonic_host"
)

var (
	proxyClient *http.Client
	// reduces stuff when lot of stuff
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, BufferSize)
		},
	}
)

// this is where i start to not like go
func initEngine() {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 60 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          MaxIdleConns,
		MaxIdleConnsPerHost:   MaxIdleConnsPerHost,
		IdleConnTimeout:       IdleConnTimeout,
		TLSHandshakeTimeout:   TLSHandshakeTimeout,
		ResponseHeaderTimeout: ResponseHeaderTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:   true, // We handle injection manually
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}

	// Optimize
	_ = http2.ConfigureTransport(transport)

	proxyClient = &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 60 * time.Second,
	}
}

// main

func handleProxy(w http.ResponseWriter, r *http.Request) {
	// cleanup pls
	defer r.Body.Close()

	// url
	targetURLStr := r.URL.Query().Get("url")
	if targetURLStr == "" {
		targetURLStr = recoverTarget(r)
		if targetURLStr == "" {
			http.Error(w, "Supersonic Engine: No Target Provided", 400)
			return
		}
	}

	targetURLStr = cleanTargetURL(targetURLStr)
	target, err := url.Parse(targetURLStr)
	if err != nil || target.Host == "" {
		http.Error(w, "Supersonic Engine: Invalid Target", 400)
		return
	}

	// always persist when things get hard 
	persistHost(w, target)

	// i request 
	req, _ := http.NewRequest(r.Method, target.String(), r.Body)
	prepareUpstreamHeaders(r.Header, req.Header, target)

	// gogogogo
	resp, err := proxyClient.Do(req)
	if err != nil {
		log.Printf("[Worker Error] %s: %v", target.Host, err)
		http.Error(w, "Network Error", 502)
		return
	}
	defer resp.Body.Close()

	// redirect 
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		rewriteRedirect(w, r, resp, target)
		return
	}

	// cookie and header
	processCookies(w, resp.Cookies())
	prepareDownstreamHeaders(w, resp.Header)

	// Delivery for jhonny
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		deliverWithInjection(w, resp.Body)
	} else {
// always recycle
    w.WriteHeader(resp.StatusCode)
		pipe(w, resp.Body)
	}
}

// preformance stuff

// moves bytes
func pipe(dst io.Writer, src io.Reader) {
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	io.CopyBuffer(dst, src, buf)
}

func deliverWithInjection(w http.ResponseWriter, body io.Reader) {
	// speed trust the process
	headBuf := make([]byte, 8192)
	n, _ := body.Read(headBuf)
	chunk := headBuf[:n]

	script := getEngineScript()
	
	w.WriteHeader(http.StatusOK)
	
	headIdx := bytes.Index(chunk, []byte("<head>"))
	if headIdx != -1 {
		w.Write(chunk[:headIdx+6])
		io.WriteString(w, script)
		w.Write(chunk[headIdx+6:])
	} else {
		io.WriteString(w, script)
		w.Write(chunk)
	}
	
	// continue pls
	pipe(w, body)
}

func recoverTarget(r *http.Request) string {
	referer := r.Header.Get("Referer")
	if strings.Contains(referer, "/proxy?url=") {
		u, _ := url.Parse(referer)
		base := u.Query().Get("url")
		if base != "" {
			return constructAbs(base, r.URL)
		}
	}
	if c, err := r.Cookie(CookieHostKey); err == nil {
		return constructAbs(c.Value, r.URL)
	}
	return ""
}

func constructAbs(baseStr string, leak *url.URL) string {
	base, _ := url.Parse(baseStr)
	res := base.Scheme + "://" + base.Host + leak.Path
	if leak.RawQuery != "" { res += "?" + leak.RawQuery }
	return res
}

func cleanTargetURL(u string) string {
	for strings.Contains(u, "/proxy?url=") {
		p := strings.Split(u, "/proxy?url=")
		u = p[len(p)-1]
		u, _ = url.QueryUnescape(u)
	}
	return u
}

func prepareUpstreamHeaders(src, dst http.Header, target *url.URL) {
	for k, vv := range src {
		l := strings.ToLower(k)
		if l == "host" || l == "origin" || l == "referer" || l == "accept-encoding" || strings.HasPrefix(l, "sec-") {
			continue
		}
		for _, v := range vv { dst.Add(k, v) }
	}
	dst.Set("Accept-Encoding", "identity")
	dst.Set("Host", target.Host)
	dst.Set("Referer", target.Scheme+"://"+target.Host+"/")
	dst.Set("User-Agent", UserAgent)
}

func prepareDownstreamHeaders(w http.ResponseWriter, h http.Header) {
	for k, vv := range h {
		l := strings.ToLower(k)
		if l == "content-security-policy" || l == "x-frame-options" || l == "content-length" || l == "content-encoding" || l == "location" || l == "strict-transport-security" || strings.Contains(l, "report-only") {
			continue
		}
		for _, v := range vv { w.Header().Add(k, v) }
	}
}
// yum
func processCookies(w http.ResponseWriter, cookies []*http.Cookie) {
	for _, c := range cookies {
		c.Domain = ""
		c.Path = "/"
		c.Secure = false
		http.SetCookie(w, c)
	}
}

func persistHost(w http.ResponseWriter, target *url.URL) {
	http.SetCookie(w, &http.Cookie{
		Name:  CookieHostKey,
		Value: target.Scheme + "://" + target.Host,
		Path:  "/",
		Expires: time.Now().Add(12 * time.Hour),
	})
}

func rewriteRedirect(w http.ResponseWriter, r *http.Request, resp *http.Response, target *url.URL) {
	loc := resp.Header.Get("Location")
	if loc == "" { return }
	lUrl, _ := url.Parse(loc)
	if !lUrl.IsAbs() { lUrl = target.ResolveReference(lUrl) }
	http.Redirect(w, r, "/proxy?url="+url.QueryEscape(lUrl.String()), resp.StatusCode)
}
// this is why you dont use it im working on making it into the html
func getEngineScript() string {
	return `<script>
(function() {
    if (window.__SS_ACT__) return; window.__SS_ACT__ = true;
    var PB = window.location.origin + '/proxy?url=';
    var params = new URLSearchParams(window.location.search);
    var TB = params.get('url') || window.location.href;
    if (TB.startsWith(PB)) TB = decodeURIComponent(TB.substring(PB.length));

    function wrap(u) {
        if (!u || typeof u !== 'string' || u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('javascript:')) return u;
        if (u.startsWith(PB) || u.startsWith('/proxy?url=')) return u;
        try { return PB + encodeURIComponent(new URL(u, TB).href); } catch(e) { return u; }
    }

    function sync(u) {
        try {
            var abs = new URL(u, TB).href;
            if (abs.startsWith(PB)) abs = decodeURIComponent(abs.substring(PB.length));
            if (abs === TB) return; TB = abs;
            if (window.top !== window.self) window.top.postMessage({ type: 'url-change', url: abs }, '*');
        } catch(e) {}
    }

    // concurency
    var sh = [[HTMLImageElement,'src'],[HTMLScriptElement,'src'],[HTMLIFrameElement,'src'],[HTMLLinkElement,'href'],[HTMLAnchorElement,'href'],[HTMLFormElement,'action'],[HTMLSourceElement,'src'],[HTMLVideoElement,'src'],[HTMLAudioElement,'src']];
    sh.forEach(function(i){
        var p = i[0].prototype, a = i[1], d = Object.getOwnPropertyDescriptor(p, a);
        if(!d||!d.set) return;
        Object.defineProperty(p, a, { get: function(){return d.get.call(this);}, set: function(v){return d.set.call(this, wrap(v));}, configurable:true });
    });

    var of = window.fetch; window.fetch = function(i, n){ if(typeof i === 'string') i = wrap(i); else if(i instanceof Request) Object.defineProperty(i,'url',{value:wrap(i.url)}); return of(i, n); };
    var ox = XMLHttpRequest.prototype.open; XMLHttpRequest.prototype.open = function(m, u, ...a){ return ox.apply(this, [m, wrap(u), ...a]); };
    
    var H = window.history, op = H.pushState, or = H.replaceState;
    H.pushState = (s,t,u) => { sync(u); return op.call(H,s,t,wrap(u)); };
    H.replaceState = (s,t,u) => { sync(u); return or.call(H,s,t,wrap(u)); };

    if ('serviceWorker' in navigator) {
        Object.defineProperty(navigator, 'serviceWorker', { get: function() { return { register: () => new Promise(()=>{}), getRegistration: () => Promise.resolve(null), getRegistrations: () => Promise.resolve([]), addEventListener: () => {}, removeEventListener: () => {} }; } });
    }
// got a little confusing 
    document.addEventListener('click', function(e){ var a = e.target.closest('a'); if(a && a.href && !a.href.startsWith('javascript:')){ e.preventDefault(); window.location.href = wrap(a.getAttribute('href')); } }, true);
    document.addEventListener('submit', function(e){ var f = e.target; if(f.action){ if((f.method||'GET').toUpperCase()==='GET'){ e.preventDefault(); var u = new URL(f.getAttribute('action'), TB).href; var qs = new URLSearchParams(new FormData(f)).toString(); window.location.href = wrap(u+(u.includes('?')?'&':'?')+qs); } else { f.action = wrap(f.getAttribute('action')); } } }, true);

    sync(TB);
})();
</script>`
}

// boot

func main() {
	initEngine()
// mux
	mux := http.NewServeMux()
	
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			handleProxy(w, r)
			return
		}
		if _, err := os.Stat(FrontendPath); err == nil {
			http.ServeFile(w, r, FrontendPath)
		} else {
			http.Error(w, "Supersonic Frontend Missing", 500)
		}
	})

	mux.HandleFunc("/proxy", handleProxy)

	server := &http.Server{
		Addr:         ListenAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("[Active on http://%s WHY ARE YOU USING THIS ITS BETA", ListenAddr)
  // hopefully this helps
	log.Printf("Max Connections: %d | Buffer Size: %d KB", MaxConnections, BufferSize/1024)
	
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Critical Failure with engine: %v", err)
	}
}
