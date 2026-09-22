import base64
import curses
import glob
import os
import re
import shutil
import subprocess
import threading

VINEFLOWER = "vineflower.jar"
APP_TITLE = "q3c decompiler"

BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
PEM_END = "-----END CERTIFICATE-----"

SUSPICIOUS_KEYWORDS = [
    "runtime.exec",
    "processbuilder",
    "base64",
    "cipher",
    "class.forname",
    "reflect",
    "native",
    "cmd.exe",
    "powershell",
    "/bin/sh",
    "xor",
    "aes",
    "rc4",
    "md5",
    "sha1",
    "keylog",
    "inject",
    "backdoor",
    "socket(",
    "datagramsocket",
    "httpurlconnection",
    "urlconnection",
]
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s\"']+")


def is_suspicious(line):
    lower = line.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower:
            return True
    if URL_RE.search(line) or IP_RE.search(line):
        return True
    return False


def find_jars():
    return sorted(glob.glob("*.jar"))


def safe_addstr(stdscr, y, x, text, attr=0):
    h, w = stdscr.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w:
        return
    max_len = w - x
    if max_len <= 0:
        return
    try:
        stdscr.addstr(y, x, text[:max_len], attr)
    except curses.error:
        pass


def draw_frame(stdscr, title):
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    safe_addstr(stdscr, 0, 0, " " * w, curses.color_pair(1))
    safe_addstr(stdscr, 0, max(0, (w - len(title)) // 2), title, curses.color_pair(1))
    return h, w


def draw_footer(stdscr, text):
    h, w = stdscr.getmaxyx()
    safe_addstr(stdscr, h - 1, 0, " " * (w - 1), curses.color_pair(1))
    safe_addstr(stdscr, h - 1, 1, text, curses.color_pair(1))


def text_input(stdscr, prompt, default=""):
    curses.curs_set(1)
    buf = list(default)
    while True:
        h, w = draw_frame(stdscr, APP_TITLE)
        safe_addstr(stdscr, 3, 2, prompt)
        box_y = 5
        safe_addstr(stdscr, box_y - 1, 2, "-" * (w - 4))
        entered = "".join(buf)
        safe_addstr(stdscr, box_y, 2, entered)
        draw_footer(stdscr, "Enter: confirm   Esc: cancel   Backspace: delete")
        stdscr.move(box_y, min(2 + len(entered), w - 3))
        stdscr.refresh()

        key = stdscr.getch()
        if key in (curses.KEY_ENTER, 10, 13):
            curses.curs_set(0)
            return "".join(buf).strip()
        elif key == 27:
            curses.curs_set(0)
            return None
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            if buf:
                buf.pop()
        elif 32 <= key <= 126:
            buf.append(chr(key))


def select_jar(stdscr):
    jars = find_jars()
    options = jars + ["[ type a path manually ]"]
    idx = 0
    while True:
        h, w = draw_frame(stdscr, APP_TITLE)
        safe_addstr(stdscr, 2, 2, "Select a jar file:")
        for i, opt in enumerate(options):
            y = 4 + i
            if y >= h - 2:
                break
            marker = "> " if i == idx else "  "
            attr = curses.color_pair(2) if i == idx else curses.A_NORMAL
            safe_addstr(stdscr, y, 2, marker + opt, attr)
        draw_footer(stdscr, "Up/Down: move   Enter: select   q: quit")
        stdscr.refresh()

        key = stdscr.getch()
        if key in (curses.KEY_UP, ord("k")):
            idx = (idx - 1) % len(options)
        elif key in (curses.KEY_DOWN, ord("j")):
            idx = (idx + 1) % len(options)
        elif key in (curses.KEY_ENTER, 10, 13):
            if options[idx] == "[ type a path manually ]":
                path = text_input(stdscr, "Path to jar file:")
                if path:
                    return path
            else:
                return options[idx]
        elif key in (ord("q"), 27):
            return None


def run_decompile(stdscr, jar, output):
    os.makedirs(output, exist_ok=True)

    log_lines = []
    log_lock = threading.Lock()
    done_flag = {"done": False, "code": None}

    def reader():
        proc = subprocess.Popen(
            ["java", "-jar", VINEFLOWER, jar, output],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in proc.stdout:
            with log_lock:
                log_lines.append(line.rstrip("\n"))
                if len(log_lines) > 500:
                    del log_lines[0]
        proc.wait()
        with log_lock:
            done_flag["done"] = True
            done_flag["code"] = proc.returncode

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    spinner = "|/-\\"
    spin_i = 0
    stdscr.nodelay(True)
    scroll = 0

    while True:
        h, w = draw_frame(stdscr, "Decompiling")
        with log_lock:
            lines = list(log_lines)
            finished = done_flag["done"]
            code = done_flag["code"]

        visible = h - 6
        if scroll > max(0, len(lines) - visible):
            scroll = max(0, len(lines) - visible)
        shown = lines[scroll:scroll + visible]

        for i, line in enumerate(shown):
            safe_addstr(stdscr, 3 + i, 2, line)

        status = "Running " + spinner[spin_i % len(spinner)]
        if finished:
            status = "Finished, exit code %s" % code
        safe_addstr(stdscr, 1, 2, status)

        draw_footer(stdscr, "Up/Down: scroll   any other key: continue once finished")
        stdscr.refresh()

        key = stdscr.getch()
        if key == curses.KEY_UP:
            scroll = max(0, scroll - 1)
        elif key == curses.KEY_DOWN:
            scroll += 1
        elif finished and key != -1:
            break

        if key == -1:
            curses.napms(80)
        spin_i += 1

    stdscr.nodelay(False)
    return done_flag["code"]


def extract_strings(stdscr, jar, output):
    draw_frame(stdscr, "Extracting Strings")
    safe_addstr(stdscr, 3, 2, "Reading %s ..." % jar)
    stdscr.refresh()

    with open(jar, "rb") as f:
        data = f.read()

    found = re.findall(rb"[\x20-\x7E]{4,}", data)
    decoded_lines = [s.decode("utf-8", errors="ignore") for s in found]

    out_path = os.path.join(output, "strings.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        for s in decoded_lines:
            f.write(s + "\n")

    return decoded_lines, out_path


def printable_ratio(data):
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data)


def format_decoded_block(data):
    if printable_ratio(data) > 0.85:
        return "text", data.decode("utf-8", errors="replace")
    return "binary, %d bytes" % len(data), data[:256].hex()


def try_b64decode(token):
    stripped = token.rstrip("=")
    pad = (-len(stripped)) % 4
    if pad == 3:
        return None
    candidate = stripped + ("=" * pad)
    try:
        return base64.b64decode(candidate, validate=True)
    except Exception:
        return None


def parse_der_cert(data):
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-text"],
            input=data, capture_output=True, timeout=5,
        )
        if proc.returncode == 0 and proc.stdout:
            return proc.stdout.decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def parse_pem_cert(pem_text):
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-text"],
            input=pem_text.encode("utf-8", errors="ignore"), capture_output=True, timeout=5,
        )
        if proc.returncode == 0 and proc.stdout:
            return proc.stdout.decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def reconstruct_pem_blocks(decoded_lines):
    blocks = []
    current = None
    for line in decoded_lines:
        stripped = line.strip()
        if PEM_BEGIN in stripped and current is None:
            current = [stripped]
        elif current is not None:
            current.append(stripped)
            if PEM_END in stripped:
                blocks.append("\n".join(current))
                current = None
    return blocks


def scan_base64_and_certs(decoded_lines, output, openssl_ok):
    seen = set()
    entries = []
    cert_hits = 0

    for line in decoded_lines:
        for m in BASE64_TOKEN_RE.finditer(line):
            token = m.group(0)
            if token in seen:
                continue
            seen.add(token)
            data = try_b64decode(token)
            if not data:
                continue
            kind, content = format_decoded_block(data)
            cert_text = None
            if openssl_ok and data[:1] == b"\x30":
                cert_text = parse_der_cert(data)
                if cert_text:
                    cert_hits += 1
            entries.append((token, kind, content, cert_text))

    pem_blocks = reconstruct_pem_blocks(decoded_lines)
    pem_results = []
    for pem_text in pem_blocks:
        cert_text = parse_pem_cert(pem_text) if openssl_ok else None
        if cert_text:
            cert_hits += 1
        pem_results.append((pem_text, cert_text))

    path = os.path.join(output, "base64.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("Base64 strings found and decoded: %d\n" % len(entries))
        f.write("X.509 certificates found: %d\n" % cert_hits)
        if not openssl_ok:
            f.write("openssl was not found on this system, certificate details were skipped\n")
        f.write("=" * 70 + "\n\n")

        for i, (token, kind, content, cert_text) in enumerate(entries, 1):
            f.write("[%d] encoded, %d chars:\n%s\n" % (i, len(token), token))
            f.write("decoded, %s:\n%s\n" % (kind, content))
            if cert_text:
                f.write("\n--- X.509 certificate detected, decoded details ---\n")
                f.write(cert_text)
                f.write("--- end certificate ---\n")
            f.write("-" * 70 + "\n\n")

        if pem_results:
            f.write("PEM certificate blocks reconstructed from resource strings:\n\n")
            for i, (pem_text, cert_text) in enumerate(pem_results, 1):
                f.write("[PEM %d]\n%s\n" % (i, pem_text))
                if cert_text:
                    f.write("\n--- X.509 certificate detected, decoded details ---\n")
                    f.write(cert_text)
                    f.write("--- end certificate ---\n")
                f.write("-" * 70 + "\n\n")

    return len(entries), cert_hits, path


def analyze_base64(stdscr, decoded_lines, output):
    draw_frame(stdscr, "Decoding Base64 and X.509")
    safe_addstr(stdscr, 3, 2, "Scanning %d strings ..." % len(decoded_lines))
    stdscr.refresh()
    openssl_ok = shutil.which("openssl") is not None
    return scan_base64_and_certs(decoded_lines, output, openssl_ok)


def show_summary(stdscr, jar, output, string_count, b64_count, cert_count):
    h, w = draw_frame(stdscr, APP_TITLE)
    lines = [
        "Jar file: %s" % jar,
        "Output folder: %s" % output,
        "Strings extracted: %d" % string_count,
        "Base64 strings decoded: %d" % b64_count,
        "X.509 certificates found: %d" % cert_count,
        "",
        "strings.txt and base64.txt were written into the output folder.",
    ]
    for i, line in enumerate(lines):
        safe_addstr(stdscr, 3 + i, 2, line)
    draw_footer(stdscr, "press any key to open the browser")
    stdscr.refresh()
    stdscr.getch()


def list_dir(path):
    try:
        names = os.listdir(path)
    except OSError:
        return []
    dirs = []
    files = []
    for name in names:
        full = os.path.join(path, name)
        if os.path.isdir(full):
            dirs.append(name)
        else:
            files.append(name)
    dirs.sort(key=str.lower)
    files.sort(key=str.lower)
    return [(d, True) for d in dirs] + [(f, False) for f in files]


def read_text_file(path, max_lines=4000):
    try:
        with open(path, "rb") as f:
            data = f.read(2_000_000)
    except OSError:
        return ["(cannot read file)"]
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + ["... truncated ..."]
    return lines


def draw_list_column(stdscr, x, y, w, h, entries, cursor, active, dim_select_name=None):
    if not entries:
        safe_addstr(stdscr, y, x, "(empty)", curses.A_DIM)
        return
    scroll = 0
    if cursor >= h:
        scroll = cursor - h + 1
    for i in range(h):
        idx = i + scroll
        if idx >= len(entries):
            break
        name, is_dir = entries[idx]
        label = name + ("/" if is_dir else "")
        attr = curses.color_pair(3) if is_dir else curses.A_NORMAL
        if active and idx == cursor:
            attr = curses.color_pair(2)
        elif (not active) and dim_select_name is not None and name == dim_select_name:
            attr = curses.color_pair(5)
        safe_addstr(stdscr, y + i, x, label, attr)


def draw_preview_text(stdscr, x, y, w, h, lines):
    for i in range(h):
        if i >= len(lines):
            break
        line = lines[i]
        attr = curses.color_pair(4) if is_suspicious(line) else curses.A_NORMAL
        safe_addstr(stdscr, y + i, x, line, attr)


def view_file_fullscreen(stdscr, path):
    lines = read_text_file(path, max_lines=20000)
    scroll = 0
    search_term = ""
    while True:
        h, w = stdscr.getmaxyx()
        stdscr.erase()
        safe_addstr(stdscr, 0, 0, " " * w, curses.color_pair(1))
        title = os.path.basename(path)
        safe_addstr(stdscr, 0, max(0, (w - len(title)) // 2), title, curses.color_pair(1))

        body_h = h - 2
        for i in range(body_h):
            idx = scroll + i
            if idx >= len(lines):
                break
            line = lines[idx]
            attr = curses.color_pair(4) if is_suspicious(line) else curses.A_NORMAL
            safe_addstr(stdscr, 1 + i, 0, "%5d  %s" % (idx + 1, line), attr)

        draw_footer(stdscr, "j/k scroll  gg/G top/bottom  / search  n next  q/h back")
        stdscr.refresh()

        key = stdscr.getch()
        if key in (ord("q"), ord("h"), 27):
            return
        elif key in (ord("j"), curses.KEY_DOWN):
            scroll = min(max(0, len(lines) - body_h), scroll + 1)
        elif key in (ord("k"), curses.KEY_UP):
            scroll = max(0, scroll - 1)
        elif key == curses.KEY_NPAGE:
            scroll = min(max(0, len(lines) - body_h), scroll + body_h)
        elif key == curses.KEY_PPAGE:
            scroll = max(0, scroll - body_h)
        elif key == ord("g"):
            key2 = stdscr.getch()
            if key2 == ord("g"):
                scroll = 0
        elif key == ord("G"):
            scroll = max(0, len(lines) - body_h)
        elif key == ord("/"):
            term = text_input(stdscr, "Search:")
            if term:
                search_term = term
                for i in range(scroll + 1, len(lines)):
                    if search_term.lower() in lines[i].lower():
                        scroll = i
                        break
        elif key == ord("n") and search_term:
            for i in range(scroll + 1, len(lines)):
                if search_term.lower() in lines[i].lower():
                    scroll = i
                    break


def strings_overlay(stdscr, strings_path):
    try:
        with open(strings_path, "r", encoding="utf-8", errors="ignore") as f:
            all_lines = [l.rstrip("\n") for l in f]
    except OSError:
        all_lines = []

    filter_term = ""
    filtered = all_lines
    cursor = 0
    scroll = 0

    while True:
        h, w = stdscr.getmaxyx()
        stdscr.erase()
        safe_addstr(stdscr, 0, 0, " " * w, curses.color_pair(1))
        label = filter_term if filter_term else "all"
        title = "STRINGS: %s (%d/%d)" % (label, len(filtered), len(all_lines))
        safe_addstr(stdscr, 0, 1, title, curses.color_pair(1))

        body_h = h - 2
        if filtered:
            cursor = max(0, min(cursor, len(filtered) - 1))
        else:
            cursor = 0
        if cursor < scroll:
            scroll = cursor
        if cursor >= scroll + body_h:
            scroll = cursor - body_h + 1

        for i in range(body_h):
            idx = scroll + i
            if idx >= len(filtered):
                break
            line = filtered[idx]
            attr = curses.color_pair(4) if is_suspicious(line) else curses.A_NORMAL
            if idx == cursor:
                attr = curses.color_pair(2)
            safe_addstr(stdscr, 1 + i, 0, line, attr)

        draw_footer(stdscr, "j/k move  / filter  c clear filter  q/h back")
        stdscr.refresh()

        key = stdscr.getch()
        if key in (ord("q"), ord("h"), 27):
            return
        elif key in (ord("j"), curses.KEY_DOWN):
            if filtered:
                cursor = min(len(filtered) - 1, cursor + 1)
        elif key in (ord("k"), curses.KEY_UP):
            cursor = max(0, cursor - 1)
        elif key == ord("/"):
            term = text_input(stdscr, "Filter strings:")
            if term is not None:
                filter_term = term
                filtered = [l for l in all_lines if term.lower() in l.lower()] if term else all_lines
                cursor = 0
                scroll = 0
        elif key == ord("c"):
            filter_term = ""
            filtered = all_lines
            cursor = 0
            scroll = 0


def draw_browser(stdscr, root, jar_name, strings_path):
    cur_rel = ""
    cursor_by_dir = {}
    search_term = ""

    while True:
        cur_abs = os.path.join(root, cur_rel) if cur_rel else root
        entries = list_dir(cur_abs)
        cursor = cursor_by_dir.get(cur_rel, 0)
        if entries:
            cursor = max(0, min(cursor, len(entries) - 1))
        else:
            cursor = 0
        cursor_by_dir[cur_rel] = cursor

        h, w = stdscr.getmaxyx()
        stdscr.erase()
        safe_addstr(stdscr, 0, 0, " " * w, curses.color_pair(1))
        title = "%s : %s" % (APP_TITLE, jar_name)
        safe_addstr(stdscr, 0, max(0, (w - len(title)) // 2), title, curses.color_pair(1))

        path_display = "/" + cur_rel if cur_rel else "/"
        safe_addstr(stdscr, 1, 1, path_display, curses.A_BOLD)

        left_w = max(10, w * 25 // 100)
        mid_w = max(15, w * 35 // 100)
        right_x = left_w + mid_w + 2
        right_w = max(10, w - right_x)

        body_y = 2
        body_h = h - 3

        parent_rel = os.path.dirname(cur_rel) if cur_rel else None
        if cur_rel:
            parent_abs = os.path.join(root, parent_rel) if parent_rel else root
            parent_entries = list_dir(parent_abs)
            draw_list_column(
                stdscr, 0, body_y, left_w, body_h, parent_entries, -1, False,
                dim_select_name=os.path.basename(cur_rel),
            )
        else:
            safe_addstr(stdscr, body_y, 0, "(root)", curses.color_pair(3))

        draw_list_column(stdscr, left_w + 1, body_y, mid_w, body_h, entries, cursor, True)

        if entries:
            sel_name, sel_is_dir = entries[cursor]
            sel_abs = os.path.join(cur_abs, sel_name)
            if sel_is_dir:
                preview_entries = list_dir(sel_abs)
                draw_list_column(stdscr, right_x, body_y, right_w, body_h, preview_entries, -1, False)
            else:
                lines = read_text_file(sel_abs, max_lines=body_h + 50)
                draw_preview_text(stdscr, right_x, body_y, right_w, body_h, lines)
        else:
            safe_addstr(stdscr, body_y, right_x, "(empty)", curses.A_DIM)

        draw_footer(stdscr, "j/k move  h/l back/open  / search  s strings  b base64  r rerun  q quit")
        stdscr.refresh()

        key = stdscr.getch()
        if key in (ord("j"), curses.KEY_DOWN):
            if entries:
                cursor_by_dir[cur_rel] = min(len(entries) - 1, cursor + 1)
        elif key in (ord("k"), curses.KEY_UP):
            cursor_by_dir[cur_rel] = max(0, cursor - 1)
        elif key == ord("g"):
            key2 = stdscr.getch()
            if key2 == ord("g"):
                cursor_by_dir[cur_rel] = 0
        elif key == ord("G"):
            if entries:
                cursor_by_dir[cur_rel] = len(entries) - 1
        elif key in (ord("h"), curses.KEY_LEFT):
            if cur_rel:
                cur_rel = parent_rel or ""
        elif key in (ord("l"), curses.KEY_RIGHT, curses.KEY_ENTER, 10, 13):
            if entries:
                sel_name, sel_is_dir = entries[cursor]
                if sel_is_dir:
                    cur_rel = os.path.join(cur_rel, sel_name) if cur_rel else sel_name
                else:
                    view_file_fullscreen(stdscr, os.path.join(cur_abs, sel_name))
        elif key == ord("/"):
            term = text_input(stdscr, "Search filename:")
            if term:
                search_term = term.lower()
                for i, (name, _) in enumerate(entries):
                    if search_term in name.lower():
                        cursor_by_dir[cur_rel] = i
                        break
        elif key == ord("n") and search_term:
            start = cursor + 1
            order = list(range(start, len(entries))) + list(range(0, start))
            for i in order:
                if search_term in entries[i][0].lower():
                    cursor_by_dir[cur_rel] = i
                    break
        elif key == ord("s"):
            strings_overlay(stdscr, strings_path)
        elif key == ord("b"):
            base64_path = os.path.join(root, "base64.txt")
            if os.path.exists(base64_path):
                view_file_fullscreen(stdscr, base64_path)
        elif key == ord("r"):
            return "rerun"
        elif key == ord("q"):
            return "quit"


def app(stdscr):
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_GREEN)
    curses.init_pair(3, curses.COLOR_CYAN, -1)
    curses.init_pair(4, curses.COLOR_RED, -1)
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)

    while True:
        jar = select_jar(stdscr)
        if not jar:
            return

        default_out = os.path.splitext(os.path.basename(jar))[0] + "_out"
        output = text_input(stdscr, "Output folder:", default_out)
        if not output:
            continue

        run_decompile(stdscr, jar, output)
        decoded_lines, strings_path = extract_strings(stdscr, jar, output)
        b64_count, cert_count, _ = analyze_base64(stdscr, decoded_lines, output)
        show_summary(stdscr, jar, output, len(decoded_lines), b64_count, cert_count)

        result = draw_browser(stdscr, output, jar, strings_path)
        if result != "rerun":
            return


def main():
    if not os.path.exists(VINEFLOWER):
        print("Missing %s in the current directory." % VINEFLOWER)
        return
    curses.wrapper(app)


if __name__ == "__main__":
    main()
