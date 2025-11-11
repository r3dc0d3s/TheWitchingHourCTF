package main

import (
	"html"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"unicode"
)

type PageData struct {
	Output        string
	Error         string
	ValidatedHost string
	Debug         string
}

func main() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/checker", handleChecker)
	http.HandleFunc("/check", handleCheck)

	log.Println("Server starting on :5000")
	log.Fatal(http.ListenAndServe(":5000", nil))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := `
		<!DOCTYPE html>
		<html>
		<head>
			<meta url="/checker">
		</head>
		<body>
		</body>
		</html>`
	t, _ := template.New("index").Parse(tmpl)
	data := PageData{}
	t.Execute(w, data)
}

func handleChecker(w http.ResponseWriter, r *http.Request) {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
	<title>Product Availability Checker - Enterprise Security Edition</title>
	<style>
		body {
			font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
			background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
			margin: 0;
			padding: 20px;
		}
		.container {
			max-width: 800px;
			margin: 50px auto;
			background: white;
			padding: 40px;
			border-radius: 15px;
			box-shadow: 0 15px 35px rgba(0,0,0,0.3);
		}
		h1 {
			color: #1e3c72;
			text-align: center;
			margin-bottom: 10px;
		}
		.subtitle {
			text-align: center;
			color: #666;
			margin-bottom: 30px;
		}
		.form-group {
			margin-bottom: 20px;
		}
		label {
			display: block;
			margin-bottom: 8px;
			color: #333;
			font-weight: bold;
		}
		input[type="text"] {
			width: 100%;
			padding: 12px;
			border: 2px solid #ddd;
			border-radius: 5px;
			box-sizing: border-box;
			font-size: 14px;
		}
		button {
			width: 100%;
			padding: 14px;
			background: #1e3c72;
			color: white;
			border: none;
			border-radius: 5px;
			font-size: 16px;
			cursor: pointer;
			transition: background 0.3s;
		}
		button:hover {
			background: #2a5298;
		}
		.output {
			margin-top: 30px;
			background: #f8f9fa;
			border: 1px solid #dee2e6;
			border-radius: 5px;
			padding: 20px;
		}
		.output pre {
			margin: 0;
			white-space: pre-wrap;
			word-wrap: break-word;
			font-family: 'Courier New', monospace;
			color: #333;
		}
		.error {
			background: #f8d7da;
			border: 1px solid #f5c6cb;
			color: #721c24;
			padding: 15px;
			border-radius: 5px;
			margin-bottom: 20px;
		}
		.info-box {
			background: #d1ecf1;
			border: 1px solid #bee5eb;
			color: #0c5460;
			padding: 15px;
			border-radius: 5px;
			margin-bottom: 20px;
		}
		.info-box strong {
			display: block;
			margin-bottom: 5px;
		}
	</style>
</head>
<body>
	<div class="container">
		<h1>🔒 Product Availability Checker</h1>
		<p class="subtitle">Enterprise Security Edition - Protected by Advanced WAF</p>

		<div class="info-box">
			<strong>Available Product Servers:</strong>
			<ul>
				<li>product1.shop.local (10.0.0.1)</li>
				<li>product2.shop.local (10.0.0.2)</li>
				<li>product3.shop.local (10.0.0.3)</li>
			</ul>
			Enter a server hostname or IP address to ping and check availability.
			<br><br>
			<strong>🛡️ Security Notice:</strong> This system is protected by our advanced Web Application Firewall (WAF) with multi-layer validation, encoding detection, and control character filtering.
		</div>

		<form method="POST" action="/check">
			<div class="form-group">
				<label for="host">Server Hostname or IP:</label>
				<input type="text" id="host" name="host" placeholder="e.g., 10.0.0.1 or google.com" required>
			</div>
			<button type="submit">Check Availability</button>
		</form>
	</div>
</body>
</html>
`
	t, _ := template.New("index").Parse(tmpl)
	data := PageData{}
	t.Execute(w, data)
}

func handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	data := PageData{}
	if err := r.ParseForm(); err != nil {
		data.Error = "Failed to parse form"
		renderPage(w, data)
		return
	}
	validatedHost := r.FormValue("host")
	executionHost := getExecutionHost(r)
	if validatedHost == "" {
		data.Error = "Please provide a hostname or IP address"
		renderPage(w, data)
		return
	}
	if !isValidHost(validatedHost) {
		data.Error = "Invalid hostname format detected by security filter"
		data.ValidatedHost = html.EscapeString(validatedHost)
		data.Debug = "Your input was sanitized and validated. Suspicious patterns blocked."
		renderPage(w, data)
		return
	}

	data.ValidatedHost = html.EscapeString(validatedHost)
	cmd := exec.Command("sh", "-c", "ping -c 3 "+executionHost)
	output, err := cmd.CombinedOutput()
	if err != nil {
		data.Output = string(output)
		if data.Output == "" {
			data.Error = "Ping failed: " + err.Error()
		}
	} else {
		data.Output = string(output)
	}

	renderPage(w, data)
}
func getExecutionHost(r *http.Request) string {
	bodyBytes := make([]byte, r.ContentLength)
	r.Body.Read(bodyBytes)
	r.Body.Close()

	bodyStr := string(bodyBytes)
	params, _ := url.ParseQuery(bodyStr)
	rawHost := params.Get("host")
	decoded, err := url.QueryUnescape(rawHost)
	if err != nil {
		return rawHost
	}
	return decoded
}

func isValidHost(host string) bool {
	dangerousChars := []string{
		";", "&", "|", "`", "$", "(", ")", "<", ">", "\\",
		"{", "}", "[", "]", "'", "\"", "*", "?", "!",
	}

	for _, char := range dangerousChars {
		if strings.Contains(host, char) {
			log.Printf("[BLOCKED] Dangerous character detected: %s in %s", char, host)
			return false
		}
	}
	encodedSequences := []string{
		"%09",
		"%26",
		"%7c",
		"%3b",
		"%24",
	}

	hostLower := strings.ToLower(host)
	for _, seq := range encodedSequences {
		if strings.Contains(hostLower, seq) {
			log.Printf("[BLOCKED] Encoded sequence detected: %s in %s", seq, host)
			return false
		}
	}

	for _, ch := range host {
		if unicode.IsControl(ch) {
			log.Printf("[BLOCKED] Control character detected: U+%04X in %s", ch, host)
			return false
		}
	}

	if strings.ContainsAny(host, "\u2028\u2029\u0085") {
		log.Printf("[BLOCKED] Unicode line separator detected in %s", host)
		return false
	}

	validPattern := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	if !validPattern.MatchString(host) {
		log.Printf("[BLOCKED] Invalid hostname pattern: %s", host)
		return false
	}

	if len(host) > 253 || len(host) < 1 {
		log.Printf("[BLOCKED] Invalid hostname length: %d", len(host))
		return false
	}

	log.Printf("[ALLOWED] Host passed all validation: %s", host)
	return true
}

func renderPage(w http.ResponseWriter, data PageData) {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
	<title>Product Availability Checker - Enterprise Security Edition</title>
	<style>
		body {
			font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
			background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
			margin: 0;
			padding: 20px;
		}
		.container {
			max-width: 800px;
			margin: 50px auto;
			background: white;
			padding: 40px;
			border-radius: 15px;
			box-shadow: 0 15px 35px rgba(0,0,0,0.3);
		}
		h1 {
			color: #1e3c72;
			text-align: center;
			margin-bottom: 10px;
		}
		.subtitle {
			text-align: center;
			color: #666;
			margin-bottom: 30px;
		}
		.form-group {
			margin-bottom: 20px;
		}
		label {
			display: block;
			margin-bottom: 8px;
			color: #333;
			font-weight: bold;
		}
		input[type="text"] {
			width: 100%;
			padding: 12px;
			border: 2px solid #ddd;
			border-radius: 5px;
			box-sizing: border-box;
			font-size: 14px;
		}
		button {
			width: 100%;
			padding: 14px;
			background: #1e3c72;
			color: white;
			border: none;
			border-radius: 5px;
			font-size: 16px;
			cursor: pointer;
			transition: background 0.3s;
		}
		button:hover {
			background: #2a5298;
		}
		.output {
			margin-top: 30px;
			background: #f8f9fa;
			border: 1px solid #dee2e6;
			border-radius: 5px;
			padding: 20px;
		}
		.output pre {
			margin: 0;
			white-space: pre-wrap;
			word-wrap: break-word;
			font-family: 'Courier New', monospace;
			color: #333;
		}
		.error {
			background: #f8d7da;
			border: 1px solid #f5c6cb;
			color: #721c24;
			padding: 15px;
			border-radius: 5px;
			margin-bottom: 20px;
		}
		.info-box {
			background: #d1ecf1;
			border: 1px solid #bee5eb;
			color: #0c5460;
			padding: 15px;
			border-radius: 5px;
			margin-bottom: 20px;
		}
		.info-box strong {
			display: block;
			margin-bottom: 5px;
		}
		.back-link {
			display: inline-block;
			margin-top: 20px;
			color: #1e3c72;
			text-decoration: none;
		}
		.back-link:hover {
			text-decoration: underline;
		}
		.validated-box {
			background: #d4edda;
			border: 1px solid #c3e6cb;
			color: #155724;
			padding: 15px;
			border-radius: 5px;
			margin-bottom: 20px;
		}
		.debug-box {
			background: #fff3cd;
			border: 1px solid #ffc107;
			color: #856404;
			padding: 15px;
			border-radius: 5px;
			margin-bottom: 20px;
		}
	</style>
</head>
<body>
	<div class="container">
		<h1>🔒 Product Availability Checker</h1>
		<p class="subtitle">Enterprise Security Edition - Protected by Advanced WAF</p>

		<div class="info-box">
			<strong>Available Product Servers:</strong>
			<ul>
				<li>product1.shop.local (10.0.0.1)</li>
				<li>product2.shop.local (10.0.0.2)</li>
				<li>product3.shop.local (10.0.0.3)</li>
			</ul>
			Enter a server hostname or IP address to ping and check availability.
			<br><br>
			<strong>🛡️ Security Notice:</strong> This system is protected by our advanced Web Application Firewall (WAF) with multi-layer validation, encoding detection, and control character filtering.
		</div>

		{{ if .Error }}
		<div class="error">{{ .Error }}</div>
		{{ end }}

		{{ if .Debug }}
		<div class="debug-box">
			<strong>🚨 Security Alert:</strong> {{ .Debug }}
		</div>
		{{ end }}

		{{ if .ValidatedHost }}
		<div class="validated-box">
			<strong>✅ Validated Input:</strong> <code>{{ .ValidatedHost }}</code><br>
			<small>Your input passed all security checks and has been sanitized.</small>
		</div>
		{{ end }}

		<form method="POST" action="/check">
			<div class="form-group">
				<label for="host">Server Hostname or IP:</label>
				<input type="text" id="host" name="host" placeholder="e.g., 10.0.0.1 or google.com" required>
			</div>
			<button type="submit">Check Availability</button>
		</form>

		{{ if .Output }}
		<div class="output">
			<strong>Ping Results:</strong>
			<pre>{{ .Output }}</pre>
		</div>
		{{ end }}
	</div>
</body>
</html>
`
	t, _ := template.New("page").Parse(tmpl)
	t.Execute(w, data)
}
