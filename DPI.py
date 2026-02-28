
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import json


PORT_MAP = {
    20  : "FTP-DATA",
    21  : "FTP",
    22  : "SSH",
    23  : "TELNET",
    25  : "SMTP",
    53  : "DNS",
    67  : "DHCP",
    68  : "DHCP",
    80  : "HTTP",
    110 : "POP3",
    143 : "IMAP",
    443 : "TLS/HTTPS",
    445 : "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT"
}

# PAYLOAD SIGNATURES 
# We check if the payload STARTS WITH these bytes/strings
# This catches apps running on non-standard ports
# these are checked against decoded text payload
TEXT_SIGNATURES = [
    ("GET ",     "HTTP"),
    ("POST ",    "HTTP"),
    ("PUT ",     "HTTP"),
    ("DELETE ",  "HTTP"),
    ("HEAD ",    "HTTP"),
    ("HTTP/1",   "HTTP"),
    ("HTTP/2",   "HTTP"),
    ("SSH-",     "SSH"),
    ("220 ",     "FTP/SMTP"), 
    ("EHLO",     "SMTP"),
    ("HELO",     "SMTP"),
    ("USER ",    "FTP"),
    ("PASS ",    "FTP"),
    ("DNS",      "DNS"),
]

# these are checked against raw bytes (binary protocols)
BYTE_SIGNATURES = [
    (b"\x16\x03\x00", "TLS"),   # TLS 1.0
    (b"\x16\x03\x01", "TLS"),   # TLS 1.1
    (b"\x16\x03\x02", "TLS"),   # TLS 1.2
    (b"\x16\x03\x03", "TLS"),   # TLS 1.3
    (b"\x16\x03\x04", "TLS"),
    (b"SSH-",         "SSH"),
    (b"PK\x03\x04",  "ZIP"),
]


# IDENTIFY PROTOCOL

def identify_protocol(src_port, dst_port, text_payload, raw_payload):

    # ── Step 1: Check destination port 
    if dst_port in PORT_MAP:
        return PORT_MAP[dst_port]

    # ── Step 2: Check source port
    if src_port in PORT_MAP:
        return PORT_MAP[src_port]

    # ── Step 3: Check text payload signatures ─
    if text_payload:
        for signature, proto_name in TEXT_SIGNATURES:
            if text_payload.startswith(signature):
                return proto_name

    # ── Step 4: Check byte signatures 
    if raw_payload:
        for byte_sig, proto_name in BYTE_SIGNATURES:
            if raw_payload.startswith(byte_sig):
                return proto_name

    # ── Step 5: Give up gracefully ────────────
    return "UNKNOWN"

# EXTRACT PAYLOAD
──────────────────────────────────────

def extract_payload(packet):

    if Raw not in packet:
        return None, None          # no payload at all

    raw_bytes = bytes(packet[Raw].load)

    try:
        # try to decode as readable text
        text = raw_bytes.decode("utf-8", errors="strict")
        return text, raw_bytes     # return both text and raw
    except UnicodeDecodeError:
        # it's binary — return None for text, keep raw bytes
        return None, raw_bytes

# COLOR HELPER

COLORS = {
    "HTTP"      : "\033[92m",    # green
    "TLS/HTTPS" : "\033[94m",    # blue
    "DNS"       : "\033[93m",    # yellow
    "FTP"       : "\033[95m",    # magenta
    "SSH"       : "\033[91m",    # red
    "SMTP"      : "\033[96m",    # cyan
    "UNKNOWN"   : "\033[90m",    # grey
}
RESET = "\033[0m"

def colorize(text, protocol):
    color = COLORS.get(protocol, "\033[97m")  
    return f"{color}{text}{RESET}"



def parse_packet(packet):

    packet_data = {
        "timestamp"    : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip"       : None,
        "dst_ip"       : None,
        "src_port"     : None,
        "dst_port"     : None,
        "protocol"     : "UNKNOWN",
        "app_protocol" : "UNKNOWN",    # NEW — this is what Phase 2 adds
        "flags"        : None,
        "payload_text" : None,
        "payload_type" : None          # NEW — "text" or "binary"
    }

    if Ether in packet:
        packet_data["src_mac"] = packet[Ether].src
        packet_data["dst_mac"] = packet[Ether].dst

    if IP in packet:
        packet_data["src_ip"] = packet[IP].src
        packet_data["dst_ip"] = packet[IP].dst
        packet_data["ttl"]    = packet[IP].ttl
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        packet_data["protocol"] = proto_map.get(packet[IP].proto, "OTHER")

    if TCP in packet:
        packet_data["src_port"] = packet[TCP].sport
        packet_data["dst_port"] = packet[TCP].dport
        packet_data["flags"]    = str(packet[TCP].flags)

    elif UDP in packet:
        packet_data["src_port"] = packet[UDP].sport
        packet_data["dst_port"] = packet[UDP].dport

    # ── Extract payload ────────────────────────
    text_payload, raw_payload = extract_payload(packet)

    if text_payload:
        packet_data["payload_text"] = text_payload
        packet_data["payload_type"] = "text"
    elif raw_payload:
        packet_data["payload_text"] = raw_payload.hex()
        packet_data["payload_type"] = "binary"

    # Identify application protocol 
    # THIS is the new thing Phase 2 adds
    packet_data["app_protocol"] = identify_protocol(
        packet_data["src_port"],
        packet_data["dst_port"],
        text_payload,
        raw_payload
    )

    display_packet(packet_data)
    log_to_file(packet_data)



# Pretty print the packet info to terminal


def display_packet(data):
    proto = data["app_protocol"]

    print("\n" + "─" * 60)
    print(colorize(f"  [{proto}]", proto) + f"  {data['timestamp']}")
    print(f"  FROM : {data['src_ip']}:{data['src_port']}")
    print(f"  TO   : {data['dst_ip']}:{data['dst_port']}")
    print(f"  TYPE : {data['protocol']} | APP: {proto} | PAYLOAD: {data['payload_type']}")

    if data.get("flags"):
        print(f"  FLAGS: {data['flags']}")

    if data.get("payload_text") and data["payload_type"] == "text":
        preview = data["payload_text"][:150].replace("\n", " ").replace("\r", "")
        print(f"  DATA : {preview}")

    print("─" * 60)


# Save each packet as a line in a log file


def log_to_file(data):
    with open("packet_log.json", "a") as f:
        f.write(json.dumps(data) + "\n")



#program starts


if __name__ == "__main__":
    import subprocess

    print("\nAvailable interfaces:")
    result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True)
    for i in result.stdout.strip().split("\n"):
        parts = i.split(": ")
        if len(parts) >= 2:
            print(f"  → {parts[1]}")

    interface = input("\nEnter interface: ").strip()
    count     = int(input("How many packets? (0 = infinite): ").strip())

    print(f"\nStarting on '{interface}'... Ctrl+C to stop.\n")

    sniff(
        iface = interface,
        prn   = parse_packet,
        count = count if count > 0 else 0,
        store = False
    )
