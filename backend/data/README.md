# Data Directory

Sample PCAP files for testing and demonstration.

## Files

| File | Contents | Expected alerts |
| --- | --- | --- |
| `normal_traffic.pcap` | 31 benign packets: HTTP, HTTPS, DNS, ICMP from one client | none |
| `suspicious_traffic.pcap` | 345 packets: simulated port scan (40 ports) and a 300-packet burst, plus innocent DNS background traffic | 2 (port_scan, high_traffic_rate) |

Both files are **synthetic**, generated locally with Scapy.  No real
network traffic is captured and no live host is contacted.

## Regenerating them

From the `backend/` directory:

```powershell
python -m scripts.generate_demo_pcaps
```

The generator uses a fixed epoch base, so the output is reproducible.

## What not to commit here

- Large binary captures
- Real captures containing credentials, session tokens or other
  sensitive data
- Any capture from a network you are not authorised to observe
