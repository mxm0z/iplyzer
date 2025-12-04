<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/async-parallel-green?style=for-the-badge" alt="Async">
  <img src="https://img.shields.io/badge/license-MIT-orange?style=for-the-badge" alt="MIT License">
</p>

<h1 align="center">iplyzer</h1>

<p align="center">
  <b>Fast, async IP enrichment for threat intelligence</b><br>
  Query VirusTotal, Shodan, AbuseIPDB & FindIP in parallel
</p>

---

## Quick Start

```bash
pip install -r requirements.txt

# Add your API keys to config.json, then:
python iplyzer.py -i 8.8.8.8
```

## Features

| Feature | Description |
|---------|-------------|
| **Parallel Queries** | All 4 APIs queried simultaneously per IP |
| **Rich Output** | Beautiful terminal tables with status indicators |
| **Multiple Formats** | Terminal, CSV, or JSON export |
| **Rate Limiting** | Configurable to respect API limits |
| **Flexible Input** | Single IP, comma-separated, or file |
| **Error Resilient** | Continues even if some APIs fail |

## Usage

```bash
# Single IP → terminal output
python iplyzer.py -i 8.8.8.8

# Multiple IPs → CSV
python iplyzer.py -i "1.1.1.1,8.8.8.8" -o results.csv

# From file → JSON
python iplyzer.py -i targets.txt --json -o results.json

# Debug mode
python iplyzer.py -i 8.8.8.8 -v
```

### Options

```
-i, --ips       IP address, list, or file (required)
-o, --output    Output file path
-c, --config    Config file (default: config.json)
--json          Export as JSON instead of CSV
-v, --verbose   Debug logging
--version       Show version
```

## Example Output

```
                    IP Analysis Results: 8.8.8.8
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field                      ┃ Value                                    ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ City                       │ Mountain View                            │
│ Country                    │ United States                            │
│ Isp                        │ Google LLC                               │
│ Asn                        │ 15169                                    │
│ Open Ports                 │ 443/tcp 53/tcp                           │
│ Virustotal Community Score │ 527                                      │
│ Abuseipdb Reports          │ 159                                      │
└────────────────────────────┴──────────────────────────────────────────┘

API Status Summary:
  FindIP: OK
  VirusTotal: OK
  Shodan: OK
  AbuseIPDB: OK
```

## Configuration

Edit `config.json` with your API keys:

```json
{
    "request_rate_limit": 4,
    "ssl_verify": true,
    "findip": {
        "enabled": true,
        "api_key": "YOUR_KEY",
        "timeout": 30
    },
    "virustotal": {
        "enabled": true,
        "api_key": "YOUR_KEY",
        "timeout": 30
    },
    "shodan": {
        "enabled": true,
        "api_key": "YOUR_KEY",
        "timeout": 30
    },
    "abuseipdb": {
        "enabled": true,
        "api_key": "YOUR_KEY",
        "timeout": 30
    }
}
```

Set `"enabled": false` to disable any API you don't have keys for.

## API Sources

| Service | Data | Free Tier |
|---------|------|-----------|
| [FindIP](https://findip.net) | Geolocation, ISP, ASN | 10k/month |
| [VirusTotal](https://virustotal.com) | Threat detections, reputation | 500/day |
| [Shodan](https://shodan.io) | Open ports, services | Limited |
| [AbuseIPDB](https://abuseipdb.com) | Abuse reports, confidence score | 1k/day |

## Output Fields

| Field | Source |
|-------|--------|
| `city`, `country`, `coordinates` | FindIP |
| `isp`, `asn`, `organization` | FindIP |
| `user_type`, `connection_type` | FindIP |
| `virustotal_detections` | VirusTotal |
| `virustotal_community_score` | VirusTotal |
| `open_ports` | Shodan |
| `abuseipdb_reports` | AbuseIPDB |
| `abuseipdb_confidence_score` | AbuseIPDB |

## Requirements

- Python 3.11+
- httpx
- pydantic
- rich

## License

MIT

## Author

[@mxm0z](https://github.com/mxm0z)
