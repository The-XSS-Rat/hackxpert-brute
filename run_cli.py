import sys
import threading
import time
import os
import argparse
from queue import Queue
from scanner import dns_bruteforce_incremental, discover_paths_for_host, load_wordlist
from database import (
    init_database, insert_domain, insert_subdomain,
    insert_directory, insert_file
)

class ConsoleQueue:
    def put(self, msg):
        print(msg)

def run_cli():
    parser = argparse.ArgumentParser(
        description="Recon Tool CLI: DNS brute-force + directory discovery + file checks"
    )
    parser.add_argument("--domain", "-d", required=True,
                        help="Base domain (e.g. example.com)")
    parser.add_argument("--subwordlist", "-s", required=False,
                        help="Path to subdomain wordlist (.txt/.lst)")
    parser.add_argument("--dirwordlist", "-w", required=False,
                        help="Path to directory/file wordlist (.txt/.lst)")
    parser.add_argument("--extensions", "-e", default="",
                        help="Comma-separated file extensions, e.g. .php,.html")
    parser.add_argument("--maxdepth", "-m", type=int, default=3,
                        help="Max recursion depth (default: 3)")
    parser.add_argument("--threads", "-t", type=int, default=20,
                        help="Number of threads (default: 20)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="Timeout in seconds (default: 5.0)")
    parser.add_argument("--delay", type=int, default=0,
                        help="Delay between requests in ms (default: 0)")
    parser.add_argument("--no-dns", action="store_true",
                        help="Disable DNS brute-force stage")
    parser.add_argument("--no-dir", action="store_true",
                        help="Disable directory discovery stage")
    parser.add_argument("--no-content", action="store_true",
                        help="Disable file/content checks")

    args = parser.parse_args()
    if not args.no_dns:
        if not args.subwordlist or not os.path.isfile(args.subwordlist):
            parser.error("Valid --subwordlist required unless --no-dns set.")
    if not args.no_dir:
        if not args.dirwordlist or not os.path.isfile(args.dirwordlist):
            parser.error("Valid --dirwordlist required unless --no-dir set.")

    exts = [e.strip() for e in args.extensions.split(",") if e.strip()]
    pause_event = threading.Event()
    stop_event = threading.Event()
    db_conn = init_database()

    domain_params = {
        "maxdepth":   args.maxdepth,
        "threads":    args.threads,
        "timeout":    args.timeout,
        "delay_ms":   args.delay,
        "do_dns":     not args.no_dns,
        "do_dir":     not args.no_dir,
        "do_content": not args.no_content
    }
    domain_id = insert_domain(db_conn, args.domain, domain_params)

    if not args.no_dns:
        sub_words = load_wordlist(args.subwordlist)
        def on_host_found(host):
            print(f"[+] Host found: {host}")
            insert_subdomain(db_conn, domain_id, host)
            insert_domain(db_conn, host, domain_params)
            if not args.no_dir:
                threading.Thread(
                    target=discover_paths_for_host,
                    args=(
                        host,
                        domain_id,
                        load_wordlist(args.dirwordlist),
                        exts,
                        args.maxdepth,
                        args.threads,
                        args.timeout,
                        args.delay,
                        pause_event,
                        stop_event,
                        Queue(),
                        None,
                        db_conn,
                        insert_directory,
                        insert_file
                    ),
                    daemon=True
                ).start()
        dns_bruteforce_incremental(
            args.domain,
            sub_words,
            args.threads,
            args.timeout,
            args.delay,
            pause_event,
            stop_event,
            Queue(),
            on_host_found=on_host_found
        )
    else:
        on_host_found(args.domain)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping scan.")
        stop_event.set()
