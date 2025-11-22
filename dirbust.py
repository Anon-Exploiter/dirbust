# -*- coding: utf-8 -*-
"""
Burp Suite extension that emulates the core functionality of Dirsearch/Gobuster.

The extension exposes a configuration UI so every Dirbust option can be set
from Burp (either via dedicated controls or by pasting a CLI-style argument
string).  It scans for directories and files using Burp's HTTP stack so that
requests remain fully visible in Proxy/Logger/Repeater.
"""

from __future__ import print_function

import argparse
import os
import shlex
import threading
import time
import traceback
import unicodedata

try:
    import Queue
except ImportError:
    import queue as Queue

from burp import IBurpExtender
from burp import ITab
from burp import IExtensionStateListener
from java.awt import BorderLayout
from java.awt import Color
from java.awt import Dimension
from java.awt import FlowLayout
from java.awt import GridBagConstraints
from java.awt import GridBagLayout
from java.awt import Insets
from java.io import File
from java.lang import Runnable
from javax.swing import AbstractAction
from javax.swing import BorderFactory
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing import JComboBox
from javax.swing import JFileChooser
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JPopupMenu
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JSpinner
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import JTextPane
from javax.swing import KeyStroke
from javax.swing import SpinnerNumberModel
from javax.swing import SwingUtilities
from javax.swing.text import SimpleAttributeSet
from javax.swing.text import StyleConstants
from javax.swing.undo import CannotRedoException
from javax.swing.undo import CannotUndoException
from javax.swing.undo import UndoManager

try:
    from urllib import quote
    from urlparse import urlparse
except ImportError:
    from urllib.parse import quote, urlparse


class _SwingRunnable(Runnable):
    def __init__(self, fn):
        self.fn = fn

    def run(self):
        self.fn()


DEFAULT_EXTENSIONS = [
    "php",
    "asp",
    "aspx",
    "jsp",
    "html",
    "js",
    "txt",
]
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
)


def safe_int_list(value):
    """Convert a comma-separated list of integers to a set."""
    if not value:
        return set()
    items = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            items.append(int(part))
        except ValueError:
            pass
    return set(items)


def safe_list(value):
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def strip_invisible(text):
    """Remove zero-width / format characters that often break Burp inputs."""
    if not text:
        return ""
    try:
        return "".join(
            ch for ch in text if unicodedata.category(ch) != "Cf"
        )
    except Exception:
        return text


def normalize_wordlist_entry(text):
    """Strip control/format characters from wordlist lines."""
    if not text:
        return ""
    cleaned = strip_invisible(text)
    try:
        cleaned = "".join(
            ch
            for ch in cleaned
            if unicodedata.category(ch)[0] != "C"
        )
    except Exception:
        pass
    return cleaned.strip()


class QuietArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that raises instead of exiting."""

    def error(self, message):
        raise ValueError(message)


class DirbustConfig(object):
    """Container for Dirbust-compatible options."""

    def __init__(self):
        self.target_url = ""
        self.wordlist_path = ""
        self.extensions = []
        self.threads = 25
        self.recursive = False
        self.max_depth = 3
        self.include_status = set()
        self.exclude_status = set([403, 404])
        self.exclude_sizes = set()
        self.exclude_texts = []
        self.method = "GET"
        self.headers = []
        self.cookies = ""
        self.user_agent = DEFAULT_USER_AGENT
        self.data = ""
        self.follow_redirects = False
        self.timeout = 10.0
        self.retries = 1
        self.delay = 0.0
        self.rate = 0
        self.recursive_status = set([200, 204, 301, 302, 307])
        self.auto_calibrate = False
        self.retry_on_status = set([429, 500, 502, 503, 504])

    @classmethod
    def from_cli(cls, cli_string):
        parser = QuietArgumentParser(
            prog="burp-dirbust", add_help=False
        )
        parser.add_argument("-u", "--url")
        parser.add_argument("-w", "--wordlist")
        parser.add_argument("-e", "--extensions")
        parser.add_argument("-t", "--threads", type=int)
        parser.add_argument("-r", "--recursive", action="store_true")
        parser.add_argument("--max-depth", type=int)
        parser.add_argument("--include-status")
        parser.add_argument("--exclude-status")
        parser.add_argument("--exclude-sizes")
        parser.add_argument(
            "--exclude-text", dest="exclude_text", action="append"
        )
        parser.add_argument("-m", "--http-method", dest="method")
        parser.add_argument("-H", "--header", action="append")
        parser.add_argument("--cookie")
        parser.add_argument("--user-agent")
        parser.add_argument("--data")
        parser.add_argument("--follow-redirects", action="store_true")
        parser.add_argument("--timeout", type=float)
        parser.add_argument("--retries", type=int)
        parser.add_argument("--delay", type=float)
        parser.add_argument("--rate", type=int)
        parser.add_argument("--auto-calibrate", action="store_true")
        parser.add_argument("--recursion-status")
        parser.add_argument("--retry-on-status")
        args = parser.parse_args(shlex.split(cli_string))
        config = cls()
        if args.url:
            config.target_url = strip_invisible(args.url).strip()
        if args.wordlist:
            config.wordlist_path = strip_invisible(args.wordlist).strip()
        if args.extensions:
            config.extensions = safe_list(args.extensions)
        if args.threads:
            config.threads = max(1, args.threads)
        if args.recursive:
            config.recursive = True
        if args.max_depth:
            config.max_depth = max(1, args.max_depth)
        if args.include_status:
            config.include_status = safe_int_list(args.include_status)
        if args.exclude_status:
            config.exclude_status = safe_int_list(args.exclude_status)
        if args.exclude_sizes:
            config.exclude_sizes = safe_int_list(args.exclude_sizes)
        if args.exclude_text:
            config.exclude_texts = args.exclude_text
        if args.method:
            config.method = args.method.upper()
        if args.header:
            config.headers = []
            for header in args.header:
                parts = header.split(":", 1)
                if len(parts) == 2:
                    config.headers.append(
                        (parts[0].strip(), parts[1].strip())
                    )
        if args.cookie:
            config.cookies = args.cookie
        if args.user_agent:
            config.user_agent = args.user_agent
        if args.data:
            config.data = args.data
        if args.follow_redirects:
            config.follow_redirects = True
        if args.timeout:
            config.timeout = max(1.0, args.timeout)
        if args.retries:
            config.retries = max(0, args.retries)
        if args.delay:
            config.delay = max(0.0, args.delay)
        if args.rate:
            config.rate = max(0, args.rate)
        if args.auto_calibrate:
            config.auto_calibrate = True
        if args.recursion_status:
            config.recursive_status = safe_int_list(
                args.recursion_status
            )
        if args.retry_on_status:
            config.retry_on_status = safe_int_list(
                args.retry_on_status
            )
        return config

    def merge(self, other):
        """Merge values from another config if they were provided."""
        for name in self.__dict__:
            if not hasattr(other, name):
                continue
            value = getattr(other, name)
            if value is None:
                continue
            if (
                isinstance(value, (list, tuple, set, dict))
                and not value
            ):
                continue
            if isinstance(value, (str,)) and value == "":
                continue
            setattr(self, name, value)


class DirbustScanner(object):
    """Worker manager that performs dictionary brute force."""

    def __init__(
        self, callbacks, ui_callback, finished_callback=None
    ):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.ui_callback = ui_callback
        self.finished_callback = finished_callback
        self._threads = []
        self._queue = Queue.Queue()
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._running = False
        self._visited = set()
        self.config = None
        self._wordlist_entries = []
        self._completion_thread = None

    def log(self, message, color=None):
        if self.ui_callback:
            try:
                self.ui_callback(message, color)
            except TypeError:
                self.ui_callback(message)
        else:
            print(message)

    def configure(self, config):
        self.config = config

    def start(self):
        if self.is_running():
            raise RuntimeError("Dirbust scan already running")
        self._set_running(True)
        try:
            if not self.config:
                raise ValueError("Scanner not configured")
            if not self.config.target_url:
                raise ValueError("Target URL is required")
            if not self.config.wordlist_path:
                raise ValueError("Wordlist path is required")
            entry_cache = [] if self.config.recursive else None
            wordlist_iter = self._load_wordlist(
                self.config.wordlist_path
            )
            if wordlist_iter is None:
                raise ValueError("Wordlist is empty or unreadable")
            parsed = urlparse(self.config.target_url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid target URL")
            self._setup_target(parsed)
            self._stop_event.clear()
            self._threads = []
            self._queue = Queue.Queue()
            self._visited = set()
            has_entries = False
            for entry in self._generate_entries(
                wordlist_iter, entry_cache
            ):
                has_entries = True
                path = self._build_path(entry)
                self._queue.put((path, 0))
            if not has_entries:
                raise ValueError("Wordlist is empty or unreadable")
            self._wordlist_entries = entry_cache or tuple()
            for _ in range(self.config.threads):
                thread = threading.Thread(
                    target=self._worker, name="Dirbust-worker"
                )
                thread.daemon = True
                thread.start()
                self._threads.append(thread)
            # self.log(
            #     "Scan started with %d entries and %d threads"
            #     % (self._queue.qsize(), self.config.threads)
            # )

            separator = "=" * 63
            fields = [
                ("[+] URL:", self.config.target_url or "-"),
                ("[+] Method:", self.config.method),
                (
                    "[+] Excluded Codes:",
                    ", ".join(
                        [
                            str(x)
                            for x in sorted(
                                self.config.exclude_status
                            )
                        ]
                    )
                    or "-",
                ),
                ("[+] Threads:", str(self.config.threads)),
                ("[+] Timeout:", "%ss" % int(self.config.timeout)),
                ("[+] Wordlist:", self.config.wordlist_path or "-"),
                ("[+] User Agent:", self.config.user_agent or "-"),
            ]
            header_lines = [
                separator,
                "Dirbust v0.0.1 by @syed__umar",
                separator,
            ]
            header_lines.extend(
                [
                    "{label} {value}".format(
                        label=label,
                        value=value,
                    )
                    for label, value in fields
                ]
            )
            header_lines.append(separator)
            header_lines.append(
                "%s Starting Dirbust"
                % time.strftime("%Y/%m/%d %H:%M:%S")
            )
            header_lines.append(separator)
            for line in header_lines:
                self.log(line)

            self._completion_thread = threading.Thread(
                target=self._wait_for_completion,
                name="Dirbust-monitor",
            )
            self._completion_thread.daemon = True
            self._completion_thread.start()
        except Exception:
            self._set_running(False)
            raise

    def log_scan_footer(self):
        separator = "=" * 63
        self.log(separator)
        self.log("%s Finished" % (time.strftime("%Y/%m/%d %H:%M:%S")))
        self.log(separator)

    def stop(self):
        if not self.is_running():
            return
        self._stop_event.set()
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except Queue.Empty:
                break
        for thread in self._threads:
            thread.join(0.2)
        self._threads = []
        self._set_running(False)
        self.log_scan_footer()

    def _wait_for_completion(self):
        try:
            self._queue.join()
            if self._stop_event.is_set():
                return
            self.log_scan_footer()
            self._mark_finished()
        except Exception:
            self._handle_thread_exception("Dirbust monitor")
            self._mark_finished()

    def _load_wordlist(self, path):
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            self.log("Wordlist %s does not exist" % path)
            return None

        def iterator():
            with open(path, "rb") as handle:
                for raw in handle:
                    try:
                        line = raw.decode("utf-8")
                    except Exception:
                        try:
                            line = raw.decode("latin-1")
                        except Exception:
                            line = raw
                    if not line:
                        continue
                    line = normalize_wordlist_entry(line)
                    if not line or line.startswith("#"):
                        continue
                    yield line

        return iterator()

    def _setup_target(self, parsed_url):
        self.scheme = parsed_url.scheme
        self.host = parsed_url.hostname
        self.port = parsed_url.port
        if not self.port:
            if self.scheme == "https":
                self.port = 443
            else:
                self.port = 80
        self.base_path = parsed_url.path or "/"
        if not self.base_path.endswith("/"):
            self.base_path += "/"
        self.use_https = self.scheme == "https"
        self.host_header = parsed_url.netloc
        self.base_url = "%s://%s" % (self.scheme, self.host_header)
        self.service = self.helpers.buildHttpService(
            self.host, self.port, self.scheme
        )

    def _generate_entries(self, wordlist, cache=None):
        extensions = self.config.extensions or DEFAULT_EXTENSIONS
        seen = set()
        for raw_word in wordlist:
            base_word = raw_word
            base_word = base_word.lstrip("/")
            candidates = []
            if "%EXT%" in base_word:
                for ext in extensions:
                    candidates.append(base_word.replace("%EXT%", ext))
            else:
                candidates.append(base_word)
                stripped = base_word.rstrip("/")
                if "." not in stripped:
                    for ext in extensions:
                        candidates.append("%s.%s" % (stripped, ext))
                if "." not in stripped and not base_word.endswith(
                    "/"
                ):
                    candidates.append(stripped + "/")
            for candidate in candidates:
                normalized = candidate.strip()
                if normalized.startswith("/"):
                    normalized = normalized[1:]
                if not normalized:
                    continue
                if normalized not in seen:
                    seen.add(normalized)
                    if cache is not None:
                        cache.append(normalized)
                    yield normalized

    def _worker(self):
        while not self._stop_event.is_set():
            try:
                item, depth = self._queue.get(timeout=0.1)
            except Queue.Empty:
                continue
            try:
                self._process_item(item, depth)
            except Exception:
                self._handle_thread_exception("Dirbust worker")
            finally:
                self._queue.task_done()
                if self.config.delay:
                    time.sleep(self.config.delay)

    def _process_item(self, path, depth):
        if self.config.rate:
            # crude rate limiting by sleeping
            time.sleep(1.0 / max(1, self.config.rate))
        if path in self._visited:
            return
        with self._lock:
            self._visited.add(path)
        request_bytes = self._build_request(path)
        if not request_bytes:
            return
        attempt = 0
        response = None
        while attempt <= self.config.retries:
            try:
                response = self.callbacks.makeHttpRequest(
                    self.service, request_bytes
                )
                break
            except Exception as exc:
                attempt += 1
                if attempt > self.config.retries:
                    self.log(
                        "Request failed for %s: %s" % (path, exc)
                    )
                    return
                time.sleep(0.5)
        raw_response = response.getResponse()
        if raw_response is None:
            return
        analyzed = self.helpers.analyzeResponse(raw_response)
        status = analyzed.getStatusCode()
        body_offset = analyzed.getBodyOffset()
        length = len(raw_response) - body_offset
        body_bytes = raw_response[body_offset:]
        body_text = self.helpers.bytesToString(body_bytes)
        if self._should_skip(status, length, body_text):
            return
        message = self._format_result(status, length, path)
        self.log(message, self._status_color(status))
        if self.config.recursive and depth < self.config.max_depth:
            if (
                status in self.config.recursive_status
                or path.endswith("/")
            ):
                self._enqueue_recursion(path, depth + 1)
        if self.config.follow_redirects and status in (
            301,
            302,
            303,
            307,
            308,
        ):
            location = self._extract_location(analyzed.getHeaders())
            redirected = self._resolve_location(location)
            if redirected:
                self._queue.put((redirected, depth))

    def _enqueue_recursion(self, directory_path, depth):
        base = directory_path
        if not base.endswith("/"):
            base += "/"
        for entry in self._wordlist_entries:
            if entry.startswith("/"):
                relative = entry[1:]
            else:
                relative = entry
            new_path = base + relative
            self._queue.put((new_path, depth))

    def _should_skip(self, status, length, body_text):
        if (
            self.config.include_status
            and status not in self.config.include_status
        ):
            return True
        if (
            self.config.exclude_status
            and status in self.config.exclude_status
        ):
            return True
        if (
            self.config.exclude_sizes
            and length in self.config.exclude_sizes
        ):
            return True
        if self.config.exclude_texts:
            for needle in self.config.exclude_texts:
                if needle and needle in body_text:
                    return True
        return False

    def _build_path(self, item):
        if item.startswith("http://") or item.startswith("https://"):
            parsed = urlparse(item)
            return parsed.path or "/"
        if item.startswith("/"):
            return item
        base = self.base_path
        if not base.endswith("/"):
            base += "/"
        return base + quote(item, safe="/")

    def _resolve_location(self, location):
        if not location:
            return None
        location = location.strip()
        if location.startswith("http://") or location.startswith(
            "https://"
        ):
            parsed = urlparse(location)
            if parsed.hostname != self.host:
                return None
            return parsed.path or "/"
        if location.startswith("/"):
            return location
        return self._build_path(location)

    @staticmethod
    def _extract_location(headers):
        for header in headers:
            lower = header.lower()
            if lower.startswith("location:"):
                return header.split(":", 1)[1].strip()
        return None

    def _format_result(self, status, length, path):
        timestamp = time.strftime("[%H:%M:%S]")
        status_str = ("%d" % status).rjust(3)
        length_str = self._human_size(length).rjust(7)
        full_url = self._full_url(path)
        return "%s %s - %s - %s" % (
            timestamp,
            status_str,
            length_str,
            full_url,
        )

    def _full_url(self, path):
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return "%s%s" % (self.base_url, path)

    def _status_color(self, status):
        if 100 <= status <= 199:
            return Color(255, 215, 0)  # yellow
        if 200 <= status <= 299:
            return Color(0, 128, 0)  # green
        if 300 <= status <= 399:
            return Color(0, 102, 204)  # blue
        if 400 <= status <= 499:
            return Color(178, 34, 34)  # red
        if 500 <= status <= 599:
            return Color(255, 140, 0)  # orange
        return Color(0, 0, 0)

    @staticmethod
    def _human_size(size):
        if size >= 1024 * 1024:
            value = size / float(1024 * 1024)
            return "%.1fMB" % value
        if size >= 1024:
            value = size / 1024.0
            return "%.1fKB" % value
        return "%dB" % size

    def _build_request(self, path):
        try:
            request_lines = [
                "%s %s HTTP/1.1" % (self.config.method, path)
            ]
            request_lines.append("Host: %s" % self.host_header)
            headers = dict(self.config.headers)
            if "User-Agent" not in headers:
                headers["User-Agent"] = self.config.user_agent
            if "Connection" not in headers:
                headers["Connection"] = "close"
            if self.config.cookies:
                headers["Cookie"] = self.config.cookies
            for key, value in headers.items():
                request_lines.append("%s: %s" % (key, value))
            request = "\r\n".join(request_lines) + "\r\n\r\n"
            if self.config.data:
                request += self.config.data
            return self.helpers.stringToBytes(request)
        except Exception as exc:
            self.log(
                "Failed to build request for %s: %s" % (path, exc)
            )
            return None

    def _handle_thread_exception(self, context):
        stack = traceback.format_exc()
        message = "%s encountered an unexpected error.\n%s" % (
            context,
            stack,
        )
        try:
            self.callbacks.printError(message)
        except Exception:
            pass
        self.log(
            "%s encountered an unexpected error. "
            "See the Extender error tab for details." % context
        )

    def _mark_finished(self):
        self._set_running(False)
        if self.finished_callback:
            self.finished_callback()

    def _set_running(self, state):
        with self._state_lock:
            self._running = state

    def is_running(self):
        with self._state_lock:
            return self._running


class DirbustPanel(JPanel):
    """Swing UI that exposes Dirbust-like configuration."""

    def __init__(self, extender, saved_wordlist=""):
        JPanel.__init__(self)
        self.extender = extender
        self.saved_wordlist = saved_wordlist or ""
        self.setLayout(BorderLayout(5, 5))
        self._undo_managers = []
        self._init_components()

    def _init_components(self):
        self.last_wordlist_directory = None
        if self.saved_wordlist:
            parent = os.path.dirname(self.saved_wordlist)
            if parent:
                self.last_wordlist_directory = parent
        self.target_field = JTextField("", 24)
        self.wordlist_field = JTextField(self.saved_wordlist, 24)
        self.wordlist_browse = JButton("Browse...")
        self.extensions_field = JTextField(
            ",".join(DEFAULT_EXTENSIONS), 24
        )
        self.method_combo = JComboBox(["GET", "HEAD", "POST"])
        self.recursive_box = JCheckBox("Recursive", False)
        self.follow_redirects_box = JCheckBox(
            "Follow redirects", False
        )
        self.exclude_status_field = JTextField("403,404", 24)
        self.timeout_spinner = JSpinner(
            SpinnerNumberModel(10.0, 1.0, 300.0, 1.0)
        )
        self.thread_spinner = JSpinner(
            SpinnerNumberModel(25, 1, 128, 1)
        )
        self.retry_spinner = JSpinner(SpinnerNumberModel(1, 0, 10, 1))
        self.delay_spinner = JSpinner(
            SpinnerNumberModel(0.0, 0.0, 60.0, 0.25)
        )
        self.depth_spinner = JSpinner(SpinnerNumberModel(3, 1, 10, 1))
        self.headers_area = JTextArea(4, 40)
        self.cookies_field = JTextField("", 24)
        self.user_agent_field = JTextField(DEFAULT_USER_AGENT, 24)
        self.data_area = JTextArea(3, 40)
        self.cli_args_area = JTextArea(4, 40)
        self.log_area = JTextPane()
        self.log_area.setEditable(False)
        self.log_popup = JPopupMenu()
        self.log_popup.add(self._ClearLogAction(self))
        self.log_area.setComponentPopupMenu(self.log_popup)
        self.wordlist_browse.addActionListener(self._browse_wordlist)
        self._enable_undo(self.target_field)
        self._enable_undo(self.wordlist_field)
        self._enable_undo(self.extensions_field)
        self._enable_undo(self.exclude_status_field)
        self._enable_undo(self.cookies_field)
        self._enable_undo(self.user_agent_field)
        self._enable_undo(self.headers_area)
        self._enable_undo(self.data_area)
        self._enable_undo(self.cli_args_area)

        left_form = JPanel(GridBagLayout())
        right_form = JPanel(GridBagLayout())
        left_row = [1]
        right_row = [0]

        def add_row(
            target, row_holder, label, component, expand=False
        ):
            label_constraints = GridBagConstraints()
            label_constraints.gridx = 0
            label_constraints.gridy = row_holder[0]
            label_constraints.anchor = GridBagConstraints.WEST
            label_constraints.insets = Insets(4, 4, 4, 4)
            target.add(JLabel(label), label_constraints)

            value_constraints = GridBagConstraints()
            value_constraints.gridx = 1
            value_constraints.gridy = row_holder[0]
            value_constraints.insets = Insets(4, 4, 4, 4)
            value_constraints.weightx = 1.0 if expand else 0.0
            value_constraints.fill = (
                GridBagConstraints.HORIZONTAL
                if expand
                else GridBagConstraints.NONE
            )
            target.add(component, value_constraints)
            row_holder[0] += 1

        wordlist_panel = JPanel(GridBagLayout())
        wl_constraints = GridBagConstraints()
        wl_constraints.insets = Insets(0, 0, 0, 4)
        wl_constraints.gridx = 0
        wl_constraints.gridy = 0
        wl_constraints.weightx = 1.0
        wl_constraints.fill = GridBagConstraints.HORIZONTAL
        wordlist_panel.add(self.wordlist_field, wl_constraints)
        wl_constraints = GridBagConstraints()
        wl_constraints.gridx = 1
        wl_constraints.gridy = 0
        wl_constraints.weightx = 0.0
        wl_constraints.fill = GridBagConstraints.NONE
        wordlist_panel.add(self.wordlist_browse, wl_constraints)

        add_row(
            left_form, left_row, "Target URL", self.target_field, True
        )
        add_row(
            left_form, left_row, "Wordlist path", wordlist_panel, True
        )
        add_row(
            left_form,
            left_row,
            "Extensions",
            self.extensions_field,
            True,
        )
        add_row(left_form, left_row, "HTTP method", self.method_combo)
        add_row(
            left_form,
            left_row,
            "Exclude status",
            self.exclude_status_field,
        )
        add_row(left_form, left_row, "Threads", self.thread_spinner)
        add_row(left_form, left_row, "Timeout", self.timeout_spinner)
        add_row(left_form, left_row, "Retries", self.retry_spinner)
        add_row(left_form, left_row, "Delay", self.delay_spinner)
        add_row(left_form, left_row, "Max depth", self.depth_spinner)
        add_row(
            right_form, right_row, "Cookies", self.cookies_field, True
        )
        add_row(
            right_form,
            right_row,
            "User-Agent",
            self.user_agent_field,
            True,
        )
        self.headers_scroll = JScrollPane(self.headers_area)
        self.data_scroll = JScrollPane(self.data_area)
        self.cli_scroll = JScrollPane(self.cli_args_area)
        self._initialize_component_sizes()
        add_row(
            right_form,
            right_row,
            "Headers (k: v)",
            self.headers_scroll,
            True,
        )
        add_row(
            right_form, right_row, "POST data", self.data_scroll, True
        )
        add_row(
            right_form,
            right_row,
            "CLI arguments",
            self.cli_scroll,
            True,
        )
        options_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        options_panel.add(self.recursive_box)
        options_panel.add(self.follow_redirects_box)
        add_row(right_form, right_row, "Options", options_panel)

        button_panel = JPanel()
        self.start_button = JButton("Start")
        self.stop_button = JButton("Stop")
        self.stop_button.setEnabled(False)
        button_panel.add(self.start_button)
        button_panel.add(self.stop_button)

        upper_panel = JPanel()
        upper_panel.setLayout(BorderLayout())
        forms_panel = JPanel(GridBagLayout())
        left_constraints = GridBagConstraints()
        left_constraints.gridx = 0
        left_constraints.gridy = 0
        left_constraints.weightx = 0.5
        left_constraints.insets = Insets(0, 0, 0, 30)
        left_constraints.anchor = GridBagConstraints.NORTHWEST
        left_constraints.fill = GridBagConstraints.HORIZONTAL
        forms_panel.add(left_form, left_constraints)

        right_constraints = GridBagConstraints()
        right_constraints.gridx = 1
        right_constraints.gridy = 0
        right_constraints.weightx = 0.5
        right_constraints.insets = Insets(0, 30, 0, 0)
        right_constraints.anchor = GridBagConstraints.NORTHEAST
        right_constraints.fill = GridBagConstraints.HORIZONTAL
        forms_panel.add(right_form, right_constraints)

        form_wrapper = JPanel(FlowLayout(FlowLayout.CENTER, 0, 10))
        form_wrapper.add(forms_panel)
        button_container = JPanel(
            FlowLayout(FlowLayout.CENTER, 10, 5)
        )
        button_container.add(button_panel)
        content_panel = JPanel(BorderLayout())
        content_panel.add(form_wrapper, BorderLayout.CENTER)
        content_panel.add(button_container, BorderLayout.SOUTH)
        upper_panel.add(content_panel, BorderLayout.CENTER)
        upper_panel.setMinimumSize(Dimension(0, 0))

        log_panel = JPanel()
        log_panel.setLayout(BorderLayout())
        log_panel.setBorder(
            BorderFactory.createTitledBorder("Results")
        )
        log_panel.add(JScrollPane(self.log_area), BorderLayout.CENTER)

        splitter = JSplitPane(
            JSplitPane.VERTICAL_SPLIT, upper_panel, log_panel
        )
        splitter.setResizeWeight(0.5)
        splitter.setOneTouchExpandable(True)
        self.add(splitter, BorderLayout.CENTER)

        self.start_button.addActionListener(self._start_clicked)
        self.stop_button.addActionListener(self._stop_clicked)

    def log(self, message, color=None):
        def append():
            try:
                doc = self.log_area.getStyledDocument()
                attrs = SimpleAttributeSet()
                StyleConstants.setForeground(
                    attrs, color or Color.BLACK
                )
                doc.insertString(
                    doc.getLength(), message + "\n", attrs
                )
                self.log_area.setCaretPosition(doc.getLength())
            except Exception:
                pass

        SwingUtilities.invokeLater(_SwingRunnable(append))

    def _collect_headers(self):
        headers = []
        for line in self.headers_area.getText().splitlines():
            if not line.strip():
                continue
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers.append((key.strip(), value.strip()))
        return headers

    def _build_config(self):
        config = DirbustConfig()
        config.target_url = strip_invisible(
            self.target_field.getText()
        ).strip()
        config.wordlist_path = strip_invisible(
            self.wordlist_field.getText()
        ).strip()
        self.extender.persist_wordlist(config.wordlist_path)
        config.extensions = safe_list(self.extensions_field.getText())
        config.method = self.method_combo.getSelectedItem()
        config.exclude_status = safe_int_list(
            self.exclude_status_field.getText()
        )
        config.threads = int(self.thread_spinner.getValue())
        config.timeout = float(self.timeout_spinner.getValue())
        config.retries = int(self.retry_spinner.getValue())
        config.delay = float(self.delay_spinner.getValue())
        config.max_depth = int(self.depth_spinner.getValue())
        config.cookies = strip_invisible(
            self.cookies_field.getText()
        ).strip()
        config.user_agent = strip_invisible(
            self.user_agent_field.getText()
        ).strip()
        config.headers = self._collect_headers()
        config.data = self.data_area.getText()
        config.recursive = self.recursive_box.isSelected()
        config.follow_redirects = (
            self.follow_redirects_box.isSelected()
        )
        cli_args = self.cli_args_area.getText().strip()
        if cli_args:
            try:
                cli_config = DirbustConfig.from_cli(cli_args)
                config.merge(cli_config)
            except Exception as exc:
                self.log("Failed to parse CLI arguments: %s" % exc)
        return config

    def _start_clicked(self, _event):
        try:
            config = self._build_config()
        except Exception as exc:
            self.log("Cannot start scan: %s" % exc)
            return
        self.extender.start_scan(config)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def _stop_clicked(self, _event):
        self.extender.stop_scan()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def scan_finished(self):
        def reset():
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)

        SwingUtilities.invokeLater(_SwingRunnable(reset))

    def _browse_wordlist(self, _event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Select wordlist")
        current_path = self.wordlist_field.getText().strip()
        directory_set = False
        if self.last_wordlist_directory and os.path.isdir(
            self.last_wordlist_directory
        ):
            chooser.setCurrentDirectory(
                File(self.last_wordlist_directory)
            )
            directory_set = True
        elif current_path:
            candidate = File(current_path)
            if candidate.isDirectory():
                chooser.setCurrentDirectory(candidate)
                directory_set = True
            elif candidate.getParentFile() is not None:
                chooser.setSelectedFile(candidate)
                chooser.setCurrentDirectory(candidate.getParentFile())
                directory_set = True
        if not directory_set:
            chooser.setCurrentDirectory(File(os.path.expanduser("~")))
        parent = self.extender.get_burp_frame() or self
        result = chooser.showOpenDialog(parent)
        if result == JFileChooser.APPROVE_OPTION:
            selected = chooser.getSelectedFile()
            if selected:
                path = selected.getAbsolutePath()
                self.wordlist_field.setText(strip_invisible(path))
                self.extender.persist_wordlist(path)
                parent_path = selected.getParent()
                if parent_path:
                    self.last_wordlist_directory = parent_path

    def _enable_undo(self, component):
        manager = UndoManager()
        document = component.getDocument()
        if document is not None:
            document.addUndoableEditListener(manager)

        class _UndoAction(AbstractAction):
            def __init__(self, undo=True):
                AbstractAction.__init__(self)
                self.undo = undo

            def actionPerformed(self, _event):
                try:
                    if self.undo and manager.canUndo():
                        manager.undo()
                    elif not self.undo and manager.canRedo():
                        manager.redo()
                except (CannotUndoException, CannotRedoException):
                    pass

        component.getInputMap().put(
            KeyStroke.getKeyStroke("control Z"), "Undo"
        )
        component.getActionMap().put("Undo", _UndoAction(True))
        component.getInputMap().put(
            KeyStroke.getKeyStroke("control Y"), "Redo"
        )
        component.getActionMap().put("Redo", _UndoAction(False))
        self._undo_managers.append(manager)

    class _ClearLogAction(AbstractAction):
        def __init__(self, panel):
            AbstractAction.__init__(self, "Clear results")
            self.panel = panel

        def actionPerformed(self, _event):
            self.panel._clear_log()

    def _initialize_component_sizes(self):
        for field in (
            self.target_field,
            self.wordlist_field,
            self.extensions_field,
            self.exclude_status_field,
            self.cookies_field,
            self.user_agent_field,
        ):
            self._lock_field_width(field)
        for spinner in (
            self.thread_spinner,
            self.timeout_spinner,
            self.retry_spinner,
            self.delay_spinner,
            self.depth_spinner,
        ):
            self._lock_spinner_width(spinner)
        for scroll in (
            self.headers_scroll,
            self.data_scroll,
            self.cli_scroll,
        ):
            self._lock_scrollpane(scroll)

    def _lock_field_width(self, field):
        size = field.getPreferredSize()
        field.setMinimumSize(size)
        field.setMaximumSize(size)

    def _lock_spinner_width(self, spinner, width=60):
        size = spinner.getPreferredSize()
        fixed = Dimension(width, size.height)
        spinner.setPreferredSize(fixed)
        spinner.setMinimumSize(fixed)
        spinner.setMaximumSize(fixed)

    def _lock_scrollpane(self, scroll):
        size = scroll.getPreferredSize()
        scroll.setMinimumSize(size)

    def _clear_log(self):
        try:
            doc = self.log_area.getStyledDocument()
            doc.remove(0, doc.getLength())
        except Exception:
            self.log_area.setText("")


class BurpExtender(IBurpExtender, ITab, IExtensionStateListener):
    """Entry point for Burp Suite."""

    def __init__(self):
        self.callbacks = None
        self.helpers = None
        self.panel = None
        self.scanner = None
        self._burp_frame = None

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Dirbust")
        callbacks.registerExtensionStateListener(self)
        try:
            self._burp_frame = callbacks.getBurpFrame()
        except Exception:
            self._burp_frame = None
        saved_wordlist = (
            callbacks.loadExtensionSetting("dirbust.wordlist_path")
            or ""
        )
        self.panel = DirbustPanel(self, saved_wordlist)
        self.scanner = DirbustScanner(
            callbacks, self.panel.log, self.panel.scan_finished
        )
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Dirbust"

    def getUiComponent(self):
        return self.panel

    def extensionUnloaded(self):
        if self.scanner:
            self.scanner.stop()

    def start_scan(self, config):
        def _run():
            try:
                self.scanner.configure(config)
                self.scanner.start()
            except Exception as exc:
                message = "Cannot start scan: %s" % exc
                if self.callbacks:
                    try:
                        self.callbacks.printError(message)
                    except Exception:
                        pass
                if self.panel:
                    self.panel.log(message)
                    self.panel.scan_finished()

        launcher = threading.Thread(
            target=_run, name="Dirbust-launcher"
        )
        launcher.daemon = True
        launcher.start()

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            if self.panel:
                self.panel.scan_finished()

    def persist_wordlist(self, path):
        if not self.callbacks:
            return
        if path:
            self.callbacks.saveExtensionSetting(
                "dirbust.wordlist_path", path
            )
        else:
            self.callbacks.saveExtensionSetting(
                "dirbust.wordlist_path", None
            )

    def get_burp_frame(self):
        return self._burp_frame
