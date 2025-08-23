import re
from typing import Optional, Tuple

# نمونه خط:  from tcp:5.212.119.136:48290 accepted tcp:www.google.com:443 [VIP -> IPv4] email: 38418.A2CgZz
RX = re.compile(
    r'from\s+(?:tcp:|udp:)?'
    r'(?:\[(?P<ipv6>[0-9a-fA-F:]+)\]|(?P<ipv4>\d{1,3}(?:\.\d{1,3}){3})):(?P<port>\d+)'
    r'.*?\baccepted\b.*?\[(?P<bracket>[^\]]+)\].*?\bemail:\s*(?P<email>\S+)',
    re.IGNORECASE
)

def inbound_from_br(s:str)->str:
    s = s.split("->",1)[0].split(">>",1)[0].strip()
    return s or "default"

def parse_line(line:str)->Tuple[Optional[str],Optional[str],Optional[str]]:
    m=RX.search(line)
    if not m: return None, None, None
    ip = m.group("ipv4") or m.group("ipv6")
    email = m.group("email")
    inbound = inbound_from_br(m.group("bracket"))
    return email, ip, inbound
