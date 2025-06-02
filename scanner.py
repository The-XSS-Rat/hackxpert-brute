import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import requests
from urllib.parse import urljoin

# Scanning Engine (runs completely independently of any GUI)

def load_wordlist(path):
    """
    Read non‐blank, non‐# lines from a file and return as a list of words.
    """
    words = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                words.append(line)
    except Exception as e:
        raise RuntimeError(f"Failed to load wordlist '{path}': {e}")
    return words

def resolve_subdomain(fullname, timeout, delay_ms, pause_event, stop_event, log_queue):
    """
    Attempt to resolve a hostname via DNS A record.
    Honors pause_event, stop_event, and delay_ms.
    Returns list of IPs or None. Logs errors to log_queue.
    """
    if stop_event.is_set():
        return None
    while pause_event.is_set() and not stop_event.is_set():
        time.sleep(0.1)
    if stop_event.is_set():
        return None
    if delay_ms > 0:
        time.sleep(delay_ms / 1000.0)
    try:
        answers = dns.resolver.resolve(fullname, "A", lifetime=timeout)
        return [rdata.address for rdata in answers]
    except Exception as e:
        log_queue.put(f"[!] DNS error for {fullname}: {e}")
        return None

def check_url(url, timeout, delay_ms, pause_event, stop_event, log_queue):
    """
    Send HTTP GET to url. Honors pause_event, stop_event, and delay_ms.
    Returns status code or None. Logs errors to log_queue.
    """
    if stop_event.is_set():
        return None
    while pause_event.is_set() and not stop_event.is_set():
        time.sleep(0.1)
    if stop_event.is_set():
        return None
    if delay_ms > 0:
        time.sleep(delay_ms / 1000.0)
    try:
        r = requests.get(url, timeout=timeout, verify=False)
        return r.status_code
    except Exception as e:
        log_queue.put(f"[!] HTTP error for {url}: {e}")
        return None

def is_directory(status_code, url):
    """
    Heuristic: 200 on trailing slash → directory;
    301/302/403 on non‐slash → directory.
    """
    if status_code is None:
        return False
    if url.endswith("/") and status_code == 200:
        return True
    if not url.endswith("/") and status_code in (301, 302, 403):
        return True
    return False

def dns_bruteforce_incremental(domain, sub_words, threads, timeout,
                               delay_ms, pause_event, stop_event, log_queue,
                               on_host_found, dns_progress_cb=None):
    """
    Brute‐force subdomains in 1000‐word chunks. As soon as a valid host is found,
    call on_host_found(hostname). Also log to log_queue and call dns_progress_cb.
    """
    lock = threading.Lock()
    total = len(sub_words)
    chunk_size = 1000
    start_time = time.time()
    processed = 0

    def worker(prefix):
        if stop_event.is_set():
            return
        hostname = f"{prefix}.{domain}"
        ips = resolve_subdomain(hostname, timeout, delay_ms, pause_event, stop_event, log_queue)
        if ips:
            with lock:
                on_host_found(hostname)
            log_queue.put(f"[+] {hostname} → {', '.join(ips)}")

    for chunk_start in range(0, total, chunk_size):
        if stop_event.is_set():
            break
        chunk_end = min(chunk_start + chunk_size, total)
        chunk = sub_words[chunk_start:chunk_end]
        log_queue.put(f"[⋯] DNS: processing {chunk_start+1}–{chunk_end} of {total}…")
        with ThreadPoolExecutor(max_workers=threads) as exe:
            futures = [exe.submit(worker, w) for w in chunk]
            for _ in as_completed(futures):
                if stop_event.is_set():
                    break
        processed = chunk_end
        elapsed = time.time() - start_time
        per_item = elapsed / processed if processed else 0
        remaining = total - processed
        rem_secs = per_item * remaining
        hrs, rem = divmod(int(rem_secs), 3600)
        mins, secs = divmod(rem, 60)
        eta_str = f"{hrs:02d}:{mins:02d}:{secs:02d}"
        log_queue.put(f"[⋯] DNS: completed {processed}/{total}. ETA: {eta_str}")
        if dns_progress_cb:
            dns_progress_cb(processed, total)
        while pause_event.is_set() and not stop_event.is_set():
            time.sleep(0.1)

def discover_paths_for_host(host, domain_id, dir_words, exts, maxdepth, threads,
                            timeout, delay_ms, pause_event, stop_event, log_queue,
                            host_progress_cb, db_conn, insert_directory_fn, insert_file_fn):
    """
    Recursively scan for directories/files for a single host. Insert results into DB.
    Each new directory triggers insertion into directories table; each file into files table.
    """
    discovered = set()
    lock = threading.Lock()

    def recurse(current_url, depth):
        if depth < 0 or stop_event.is_set():
            return
        total_words = len(dir_words)
        processed_words = 0

        def worker(word):
            nonlocal processed_words
            if stop_event.is_set():
                return
            while pause_event.is_set() and not stop_event.is_set():
                time.sleep(0.1)
            if stop_event.is_set():
                return
            # Directory check
            dir_url = urljoin(current_url, f"{word}/")
            status = check_url(dir_url, timeout, delay_ms, pause_event, stop_event, log_queue)
            if is_directory(status, dir_url):
                with lock:
                    if dir_url not in discovered:
                        discovered.add(dir_url)
                        log_queue.put(f"    [+] Dir: {dir_url}")
                        insert_directory_fn(db_conn, domain_id, dir_url)
                        recurse(dir_url, depth - 1)
            # File checks
            for ext in exts:
                if stop_event.is_set():
                    return
                file_url = urljoin(current_url, f"{word}{ext}")
                status_f = check_url(file_url, timeout, delay_ms, pause_event, stop_event, log_queue)
                if status_f == 200:
                    with lock:
                        if file_url not in discovered:
                            discovered.add(file_url)
                            log_queue.put(f"    [+] File: {file_url}")
                            insert_file_fn(db_conn, domain_id, file_url)
            processed_words += 1
            if host_progress_cb:
                host_progress_cb(processed_words, total_words)

        with ThreadPoolExecutor(max_workers=threads) as exe:
            futures = [exe.submit(worker, w) for w in dir_words]
            for _ in as_completed(futures):
                if stop_event.is_set():
                    break

    root_url = f"https://{host}/"
    status = check_url(root_url, timeout, delay_ms, pause_event, stop_event, log_queue)
    if not status or status >= 500:
        root_url = f"http://{host}/"
        status = check_url(root_url, timeout, delay_ms, pause_event, stop_event, log_queue)
    if not status or status >= 500:
        log_queue.put(f"[-] Cannot reach {host}. Skipping directory scan.")
        return

    log_queue.put(f"[+] Scanning {host} (depth {maxdepth})…")
    if host_progress_cb:
        host_progress_cb(0, len(dir_words))
    recurse(root_url, maxdepth)
    if host_progress_cb:
        host_progress_cb(len(dir_words), len(dir_words))
    count = len(discovered)
    if count:
        log_queue.put(f"    [+] Found {count} items under {host}.")
    else:
        log_queue.put(f"    [-] No items under {host}.")
