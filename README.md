# Dirbust for Burp Suite

Dirbust is a Burp Suite extension that replicates the feature set of Dirbuster/Dirsearch/Gobuster directly inside Burp. It performs fast directory and file discovery using Burp’s own HTTP stack so all requests remain visible across Proxy/Logger/Repeater.

> Built for testers who want dirbusting directly in Burp without leaving.

<img width="1565" height="1015" alt="image" src="https://github.com/Anon-Exploiter/dirbust/blob/main/images/dirbust_01.gif?raw=true" />


---

## Why?

Most clients keep their Citrix VDIs or Remote Desktops tightly restricted, allowing only a small set of approved tools. BurpSuite usually makes the list, but installing anything else, including Python on Windows or WSL for running dirsearch, is almost always blocked.

I built this to get around that limitation. You simply run dirbust inside BurpSuite itself, target any URL or endpoint, choose your custom or dirsearch-style wordlists, set the extensions, and start the scan.

---

## ✨ Features

| Feature | Details |
|---|---|
| **Full Dirbust workflow** | Supports target URL, extensions, wordlists, recursion depth, custom threads/timeouts/delays, HTTP methods, data, cookies, headers, user-agent overrides, excludes, etc. |
| **Dirbust banner output** | Banner summary identical to CLI tools plus colored result lines (status-based) with wordlist metadata. |
| **Recursive discovery** | Optional recursion into discovered directories with custom recursion status set. |
| **Filters & exclusions** | Include/exclude status codes, sizes, text matches, and recursion status handling. |
| **Rate / delay** | Per-request delay, rate limit, retry logic, and follow-redirect toggles. |
| **Dirsearch templating** | CLI-style override box that accepts traditional Dirsearch arguments and merges them with UI selections. |
| **Absolute request lines** | Optional toggle to send full absolute URLs in the request line for legacy servers/proxies that require it. |
| **Wordlist persistence** | Automatically remembers the last wordlist path between Burp sessions. |
| **Burp context menu** | Right-click any Burp request and “Send to Dirbust” to auto-fill target, cookies, headers, UA, and body without manual copy/paste. |
| **Undo support** | All text areas and fields support Ctrl+Z / Ctrl+Y undo/redo. |
| **Clear results** | Right-click the output to clear the current run. |
| **Split UI** | Two-column form layout with adjustable splitter for results. |
| **Colorized statuses** | Informational=yellow, Success=green, Redirect=blue, Client errors=red, Server errors=orange. |

---

## Installation

1. Clone or download this repository.
2. Launch Burp Suite (community or professional edition).
3. Navigate to `Extender` → `Extensions`.
4. Click `Add`, select `Extension Type: Python`, and choose `dirbust.py`.
5. Ensure Jython 2.7+ is configured in Burp’s extender options.
6. Grab a copy of [Dirsearch's dictionary](https://raw.githubusercontent.com/maurosoria/dirsearch/refs/heads/master/db/dicc.txt) as the extension is most effective with it

Once loaded, a new `Dirbust` tab will appear in the Burp UI.

---

## Usage

1. **Target Section**  
   - `Target URL`: Base URL (e.g. `https://example.com/`).  
   - `Wordlist path`: Local file path (browse button supported and persisted).  
   - `Extensions`: Comma-separated extensions, `%EXT%` placeholders supported inside wordlist entries.

2. **Request Options**  
   - HTTP method (GET/POST/HEAD).  
   - Custom headers, cookies, POST data, CLI arguments (Dirsearch-compatible).  
   - User-Agent override, recursion toggle, follow-redirect toggle.  
   - Absolute URLs toggle to send full `scheme://host/path` in the request line for legacy servers that require it.

3. **Burp shortcut**  
   - Right-click any request in Proxy/Logger/Repeater and choose “Send to Dirbust” to populate target URL, method, headers (minus Host), cookies, User-Agent, and body automatically.

3. **Performance & Filters**  
   - Threads, timeout, retries, delay, recursion depth.  
   - Exclude status codes / sizes / text.  

4. **Running a Scan**  
   - Click `Start` to begin.  
   - Watch the banner + results output; or clear the list.

5. **UI**  
   - Results area supports dynamic resizing via the splitter between the form and output sections.

---

## ⚙️ CLI Argument Merge

On top of the given options, the “CLI arguments“ textarea accepts Dirsearch-style flags and merges them with the UI selections. Supported flags:

```bash
-u / --url                  Target URL
-w / --wordlist             Wordlist path
-e / --extensions           Comma-separated extensions or %EXT% replacements
-t / --threads              Number of threads
-r / --recursive            Enable recursion
--max-depth                 Limit recursion depth
--include-status            Include only these HTTP status codes (comma-separated)
--exclude-status            Exclude these status codes (comma-separated)
--exclude-sizes             Exclude by response size (comma-separated)
--exclude-text              Exclude if body contains string (repeatable)
-m / --http-method          HTTP method (GET/POST/HEAD/etc.)
-H / --header               Add custom header (repeatable, e.g. “X-Test: value”)
--cookie                    Set Cookie header
--user-agent                Override User-Agent
--data                      Request body (for POST/PUT)
--follow-redirects          Follow redirect responses when scanning
--absolute-url              Send absolute URL in the request line (for legacy servers/proxies)
--timeout                   Request timeout (seconds)
--retries                   Retry count per request
--delay                     Delay between requests (seconds)
--rate                      Requests per second throttle
--auto-calibrate            Enable auto-calibration mode
--recursion-status          Status codes that trigger recursion
--retry-on-status           Status codes that trigger retries
```

Paste any combination of these flags exactly as you would in CLI dirsearch/gobuster and they will override or augment the current UI settings. Sample usage:

```bash
--data 'a=bcd' --exclude-text 'oranges'
```

---

## Testing

- Verified inside Burp Suite Professional with Jython 2.7.3.
- Works through Burp’s proxy so all traffic is captured in Logger/Proxy/Repeater.
- Compatible with HTTPS targets and custom ports.

---

## Notes & Security

- Requests are issued via Burp’s API; ensure you have permission to test the target.
- Wordlist and output parsing are local only. No network calls beyond what you configure.
- Input sanitisation is handled by Burp’s APIs; however, always verify wordlists and CLI arguments from external sources.

---

## License

Distributed under the MIT License. See `LICENSE` or the repository for details.

---

## Acknowledgments

- Functionality in this project draws directly from Dirsearch, with output formatting inspired by Gobuster. All rights to the original tools remain with their respective authors.
- AI as this has been heavily vibe coded.

For bugs, feature requests, or contributions, please open an issue or pull request! Happy busting!
