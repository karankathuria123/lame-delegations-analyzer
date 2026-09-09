import logging
import socket
import struct

logger = logging.getLogger(__name__)


DNS_TIMEOUT_SEC: float = 5.0
DNS_QTYPE_SOA: int = 6
DNS_CLASS_IN: int = 1
_QUERY_ID: int = 0x1A2B

# Hostname Resolution Function
def resolve_hostname(hostname: str) -> tuple[bool, str]:
    hostname = hostname.rstrip(".")
    if not hostname:
        return False, "Empty hostname"

    prev_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT_SEC)
        socket.getaddrinfo(hostname, None)
        return True, "Resolves"
    except socket.gaierror as e:
        return False, f"Resolution error: {e}"
    except OSError as e:
        return False, f"OS error: {e}"
    finally:
        socket.setdefaulttimeout(prev_timeout)


# Raw DNS Query Function

def _encode_dns_name(name: str) -> bytes:
    encoded = b""
    for label in name.rstrip(".").split("."):
        label_bytes = label.encode("ascii")
        encoded += struct.pack("B", len(label_bytes)) + label_bytes
    encoded += b"\x00"  # Null byte to terminate the name
    return encoded


def _build_dns_query(name: str, qtype: int) -> bytes:
    header = struct.pack(">HHHHHH", _QUERY_ID, 0x0100, 1, 0, 0, 0)  # Standard query
    question = _encode_dns_name(name) + struct.pack(">HH", qtype, DNS_CLASS_IN)
    return header + question


def query_soa_authoritative(ns_host: str, zone_name: str) -> tuple[bool, str]:
    ns_host = ns_host.rstrip(".")
    zone_name = zone_name.rstrip(".")

    # Step 1: Resolve NS hostname to IP
    try:
        addr_infos = socket.getaddrinfo(ns_host, 53, socket.AF_INET, socket.SOCK_DGRAM)
        ns_ip = addr_infos[0][4][0]
    except (socket.gaierror, IndexError) as e:
        return False, f"Failed to resolve NS hostname {ns_host}: {e}"

    # Step 2: Build DNS query for SOA record
    query_packet = _build_dns_query(zone_name, DNS_QTYPE_SOA)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(DNS_TIMEOUT_SEC)

    try:
        sock.sendto(query_packet, (ns_ip, 53))
        response, _ = sock.recvfrom(512)  # Standard DNS packet size
    except socket.timeout:
        return False, f"Timeout querying NS {ns_host} for SOA of {zone_name}"
    except OSError as e:
        return False, f"OS error querying NS {ns_host} for SOA of {zone_name}: {e}"
    finally:
        sock.close()

    # Step 3: Parse the DNS response header
    if len(response) < 12:
        return False, "Invalid DNS response (too short)"

    flags = struct.unpack(">H", response[2:4])[0]
    aa_flag = bool(flags & 0x0400)  # Authoritative Answer flag
    rcode = flags & 0x000F  # Response code

    # rcode 0 noerror and 3 nxdomain are valid responses, but we only care about authoritative answers. Anything else is suspicious.
    if rcode not in (0, 3):
        return False, f"Unexpected DNS response code {rcode} from NS {ns_host} for SOA of {zone_name}"

    if aa_flag:
        return True, f"Authoritative (AA=1, RCODE={rcode}), ns_ip={ns_ip}"
    return False, f"Not authoritative (AA=0, RCODE={rcode}), ns_ip={ns_ip}"