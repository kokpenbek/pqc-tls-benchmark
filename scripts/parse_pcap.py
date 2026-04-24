"""
Export per-connection TCP/TLS/application latency decomposition from a decrypted PCAP into a CSV file for classical vs hybrid comparison.

Example usage:
    python parse_pcap.py capture.pcap -k tls_keys.log --variant 1
    python parse_final.py capture.pcap -k tls_keys.log --variant 2
"""
import argparse
import csv
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

VARIANT_MAP = {
    "1": "classic",
    "2": "hybrid",
}

# Defines the exact CSV column order for exported layered timing results.
CSV_COLUMNS = [
    "variant",
    "conn",
    "tcp_hs",
    "tcp_tls",
    "tls_hs",
    "tls_app",
    "app_resp",
]

def run_tshark(pcap_file, keylog_file=None, display_filter=None):
    """Runs tshark on the input capture with optional TLS key log support, returns parsed rows as dictionaries."""
    cmd = [
        "tshark",
        "-r", pcap_file,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=\t",
        "-E", "quote=n",
        "-E", "occurrence=f",
        "-e", "frame.number",
        "-e", "frame.time_relative",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "tcp.stream",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
        "-e", "tls.handshake.type",
        "-e", "http.request",
        "-e", "http.response",
        "-e", "http.request.method",
        "-e", "http.response.code",
        "-e", "_ws.col.Info",
    ]

    if keylog_file:
        cmd.extend(["-o", f"tls.keylog_file:{keylog_file}"])

    cmd.extend(["-Y", display_filter if display_filter else "tcp"])

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise RuntimeError("tshark failed")

    rows = []
    reader = csv.DictReader(proc.stdout.splitlines(), delimiter="\t")
    for row in reader:
        rows.append(row)

    return rows


def s(row, key):
    v = row.get(key, "")
    return v.strip() if v else ""


def f(row, key):
    try:
        return float(s(row, key))
    except Exception:
        return None


def is_true_value(v):
    v = (v or "").strip().lower()
    return v in {"1", "true", "yes"}


def has_tls_handshake_type(row, wanted_type):
    raw = s(row, "tls.handshake.type")
    if not raw:
        return False
    parts = [x.strip() for x in raw.split(",") if x.strip()]
    return str(wanted_type) in parts


def is_syn(row):
    """Identifies a TCP SYN packet"""
    return is_true_value(s(row, "tcp.flags.syn")) and not is_true_value(s(row, "tcp.flags.ack"))


def is_synack(row):
    """Identifies a TCP ACK packet"""
    return is_true_value(s(row, "tcp.flags.syn")) and is_true_value(s(row, "tcp.flags.ack"))


def is_ack_only(row):
    """Identifies a pure TCP ACK packet"""
    return (not is_true_value(s(row, "tcp.flags.syn"))) and is_true_value(s(row, "tcp.flags.ack"))


def is_http_request(row):
    return is_true_value(s(row, "http.request")) or s(row, "http.request.method") != ""


def is_http_response(row):
    return is_true_value(s(row, "http.response")) or s(row, "http.response.code") != ""


def same_direction(row, src_ip, src_port, dst_ip, dst_port):
    return (
        s(row, "ip.src") == src_ip and
        s(row, "tcp.srcport") == src_port and
        s(row, "ip.dst") == dst_ip and
        s(row, "tcp.dstport") == dst_port
    )


def delta(start_row, end_row):
    """Computes the latency difference between two packets"""
    if not start_row or not end_row:
        return None
    a = f(start_row, "frame.time_relative")
    b = f(end_row, "frame.time_relative")
    if a is None or b is None:
        return None
    return round((b - a) * 1000.0, 6)


def find_tcp_handshake(rows):
    syn = None
    synack = None
    ack = None

    client_ip = None
    client_port = None
    server_ip = None
    server_port = None

    for row in rows:
        if syn is None and is_syn(row):
            syn = row
            client_ip = s(row, "ip.src")
            client_port = s(row, "tcp.srcport")
            server_ip = s(row, "ip.dst")
            server_port = s(row, "tcp.dstport")
            continue

        if syn is not None and synack is None:
            if is_synack(row) and same_direction(row, server_ip, server_port, client_ip, client_port):
                synack = row
                continue

        if synack is not None and ack is None:
            if is_ack_only(row) and same_direction(row, client_ip, client_port, server_ip, server_port):
                ack = row
                break

    return syn, synack, ack, client_ip, client_port, server_ip, server_port


def analyze_stream(rows):
    """Extracts the five layered timing measurements for one TCP stream"""
    rows = sorted(rows, key=lambda r: f(r, "frame.time_epoch") or 0.0)

    syn, synack, ack, client_ip, client_port, server_ip, server_port = find_tcp_handshake(rows)

    client_hello = None
    client_finished = None
    app_request = None
    app_response = None

    if client_ip is None:
        for row in rows:
            if has_tls_handshake_type(row, 1):
                client_hello = row
                client_ip = s(row, "ip.src")
                client_port = s(row, "tcp.srcport")
                server_ip = s(row, "ip.dst")
                server_port = s(row, "tcp.dstport")
                break

    if client_ip is None:
        return None

    if client_hello is None:
        for row in rows:
            if has_tls_handshake_type(row, 1) and same_direction(row, client_ip, client_port, server_ip, server_port):
                client_hello = row
                break

    for row in rows:
        if same_direction(row, client_ip, client_port, server_ip, server_port):
            info = s(row, "_ws.col.Info").lower()
            if has_tls_handshake_type(row, 20) or "finished" in info:
                client_finished = row
                break

    for row in rows:
        if client_finished is None:
            break
        t_row = f(row, "frame.time_relative")
        t_fin = f(client_finished, "frame.time_relative")
        if t_row is None or t_fin is None or t_row < t_fin:
            continue
        if same_direction(row, client_ip, client_port, server_ip, server_port) and is_http_request(row):
            app_request = row
            break

    for row in rows:
        if app_request is None:
            break
        t_row = f(row, "frame.time_relative")
        t_req = f(app_request, "frame.time_relative")
        if t_row is None or t_req is None or t_row < t_req:
            continue
        if same_direction(row, server_ip, server_port, client_ip, client_port) and is_http_response(row):
            app_response = row
            break

    parses = {
        "tcp_hs": delta(syn, ack),
        "tcp_tls": delta(ack, client_hello),
        "tls_hs": delta(client_hello, client_finished),
        "tls_app": delta(client_finished, app_request),
        "app_resp": delta(app_request, app_response),
    }

    return parses


def validate_variant_or_exit(variant_arg):
    if variant_arg is None:
        print("Error: you must provide --variant 1 or --variant 2", file=sys.stderr)
        sys.exit(1)

    variant_arg = str(variant_arg).strip()
    if variant_arg not in VARIANT_MAP:
        print("Error: --variant must be 1 or 2", file=sys.stderr)
        sys.exit(1)

    return VARIANT_MAP[variant_arg]


def write_csv(filename, variant_name, parsed_rows):
    with open(str(filename), "w", newline="") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        for idx, parses in enumerate(parsed_rows, start=1):
            writer.writerow({
                "variant": variant_name,
                "conn": idx,
                "tcp_hs": parses["tcp_hs"],
                "tcp_tls": parses["tcp_tls"],
                "tls_hs": parses["tls_hs"],
                "tls_app": parses["tls_app"],
                "app_resp": parses["app_resp"],
            })


def main():
    parser = argparse.ArgumentParser(
        description="Export layered TCP/TLS timing measurements to CSV"
    )
    parser.add_argument("pcap", help="Path to pcap/pcapng")
    parser.add_argument("-k", "--keylog", help="Path to SSLKEYLOGFILE", default=None)
    parser.add_argument("-f", "--filter", help="Optional tshark display filter", default="tcp")
    parser.add_argument("--stream", type=int, help="Analyze only one tcp.stream", default=None)
    parser.add_argument(
        "--variant",
        help="1 = classic, 2 = hybrid",
        required=False,
    )
    args = parser.parse_args()

    variant_name = validate_variant_or_exit(args.variant)

    script_dir = Path(__file__).resolve().parent
    output_dir = script_dir.parent / "results" / "layered_analysis"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / f"{variant_name}_layered.csv"

    rows = run_tshark(args.pcap, keylog_file=args.keylog, display_filter=args.filter)

    streams = defaultdict(list)
    for row in rows:
        stream_id = s(row, "tcp.stream")
        if stream_id != "":
            streams[stream_id].append(row)

    if args.stream is not None:
        stream_key = str(args.stream)
        if stream_key not in streams:
            print(f"Error: tcp.stream {stream_key} not found", file=sys.stderr)
            sys.exit(1)
        streams = {stream_key: streams[stream_key]}

    parsed_rows = []
    for _, stream_rows in sorted(streams.items(), key=lambda x: int(x[0])):
        parses = analyze_stream(stream_rows)
        if parses is None:
            continue

        if all(parses[k] is not None for k in ["tcp_hs", "tcp_tls", "tls_hs", "tls_app", "app_resp"]):
            parsed_rows.append(parses)

    if not parsed_rows:
        print("Error: no fully valid streams found to export", file=sys.stderr)
        sys.exit(1)

    write_csv(output_file, variant_name, parsed_rows)
    print(f"Exported {len(parsed_rows)} connections to {output_file}")


if __name__ == "__main__":
    main()
