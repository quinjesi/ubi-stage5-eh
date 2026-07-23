import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Union

class MalformedOutputError(ValueError):
    pass

class MissingFieldError(ValueError):
    pass


def parse_nmap_xml(raw: str) -> List[Dict[str, Any]]:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        raise MalformedOutputError("MALFORMED_TOOL_OUTPUT") from e

    records = []
    if root.tag == "host":
        hosts = [root]
    else:
        hosts = root.findall("host")

    for host in hosts:
        addr_elem = host.find("address")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr")
        if not ip:
            continue

        for port_elem in host.findall(".//port"):
            port = port_elem.get("portid")
            if port is None:
                continue
            protocol = port_elem.get("protocol", "tcp")
            state_elem = port_elem.find("state")
            state = state_elem.get("state") if state_elem is not None else ""
            service_elem = port_elem.find("service")
            service = service_elem.get("name") if service_elem is not None else ""

            records.append({
                "host": ip,
                "port": int(port),
                "transport": protocol,
                "service": service,
                "state": state
            })
    return records


def parse_naabu_json(raw: Union[str, dict]) -> List[Dict[str, Any]]:
    if isinstance(raw, dict):
        data = raw
    else:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise MalformedOutputError("MALFORMED_TOOL_OUTPUT") from e

    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = data
    else:
        raise MalformedOutputError("MALFORMED_TOOL_OUTPUT")

    records = []
    for item in items:
        host = item.get("host")
        ip = item.get("ip")
        port = item.get("port")
        protocol = item.get("protocol")
        if host is None or ip is None or port is None or protocol is None:
            raise MissingFieldError("REQUIRED_FIELD_MISSING")
        records.append({
            "host": host,
            "ip": ip,
            "port": port,
            "transport": protocol
        })
    return records


def parse_httpx_json(raw: Union[str, dict]) -> List[Dict[str, Any]]:
    if isinstance(raw, dict):
        data = raw
    else:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise MalformedOutputError("MALFORMED_TOOL_OUTPUT") from e

    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = data
    else:
        raise MalformedOutputError("MALFORMED_TOOL_OUTPUT")

    records = []
    for item in items:
        url = item.get("url")
        status = item.get("status_code")
        if url is None or status is None:
            raise MissingFieldError("REQUIRED_FIELD_MISSING")
        from urllib.parse import urlparse
        parsed = urlparse(url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname
        port = parsed.port
        if port is None:
            port = 443 if scheme == "https" else 80
        records.append({
            "scheme": scheme,
            "host": host,
            "port": port,
            "status": status,
            "title": item.get("title", ""),
            "tech": item.get("tech", [])
        })
    return records


def parse_line(raw: str) -> List[Dict[str, Any]]:
    records = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if not parts:
            continue
        ip_port = parts[0]
        if ':' not in ip_port:
            raise MalformedOutputError("MALFORMED_TOOL_OUTPUT")
        ip, port_str = ip_port.split(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            raise MalformedOutputError("MALFORMED_TOOL_OUTPUT")
        service = parts[1] if len(parts) > 1 else ""
        product = parts[2] if len(parts) > 2 else ""
        records.append({
            "ip": ip,
            "port": port,
            "service": service,
            "product": product
        })
    return records


def parse(kind: str, raw: Union[str, dict]) -> List[Dict[str, Any]]:
    if kind == "nmap_xml":
        return parse_nmap_xml(raw)
    elif kind == "naabu_json":
        return parse_naabu_json(raw)
    elif kind == "httpx_json":
        return parse_httpx_json(raw)
    elif kind == "line":
        return parse_line(raw)
    else:
        raise ValueError(f"Unknown parser kind: {kind}")
