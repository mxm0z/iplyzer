# IPlyzer CLI Tool

A simple Command Line Interface (CLI) tool for analyzing IP addresses across multiple data sources. The **IPlyzer CLI Tool** provides in-depth information regarding given IP addresses, integrating with popular services such as **VirusTotal**, **Shodan**, **AbuseIPDB**, and **FindIP**. This tool is designed to aid in cybersecurity research, threat intelligence, and investigation of IP addresses, providing both a summary and detailed output as needed.

## Key Features

- **Multi-Source Integration**: Fetches IP details from multiple services such as **VirusTotal**, **Shodan**, **AbuseIPDB**, and **FindIP**.
- **Asynchronous Requests**: Makes use of Python's asyncio library to perform concurrent lookups, ensuring efficient data collection.
- **Flexible Output Options**:
  - Outputs parsed results directly in the terminal for single IPlyzer.
  - Generates CSV reports for bulk analysis, enabling easy sharing and further analysis.
- **Custom Rate Limiting**: Configure request rate limits to avoid hitting API request caps.
- **Customizable Configuration**: All API endpoints and keys are configurable via `config.json`, making the tool highly adaptable to individual use cases.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
  - [Command Line Arguments](#command-line-arguments)
  - [Example Commands](#example-commands)
- [Configuration](#configuration)
- [API Integrations](#api-integrations)
- [Output](#output)
- [Contributing](#contributing)
- [Contact](#contact)
- [License](#license)

## Installation

1. **Clone the Repository**:
   ```sh
   git clone https://github.com/mxm0z/iplyzer
   cd iplyzer
   ```

2. **Install Dependencies**:
   This project requires Python 3.7 or above. Use `pip` to install the necessary dependencies:
   ```sh
   pip install aiohttp requests
   ```

## Usage

The **IPlyzer CLI Tool** can be used to analyze IP addresses either from a file or from command line arguments.

### Command Line Arguments
- `-i, --ips`: List of IP addresses or a path to a file containing IPs (one per line). This argument is **required**.
- `-c, --config`: Path to the configuration JSON file containing API keys and endpoints. Defaults to `config.json`.
- `-o, --output`: Output CSV file name for bulk analysis. If not specified, it generates a file named `report_{random}.csv`.

### Example Commands

1. **Analyze a Single IP Address**:
   ```sh
   python iplyzer.py -i 8.8.8.8
   ```
   This will output the parsed result directly to the terminal.

2. **Analyze Multiple IPs from a File**:
   ```sh
   python iplyzer.py -i ip_list.txt -o output_report.csv
   ```
   This will save the analysis results to `output_report.csv`.

## Configuration

The tool requires API keys for multiple services, specified in a `config.json` file. Below is an example configuration:

```json
{
    "request_rate_limit": 4,
    "findip": {
        "enabled": true,
        "api_key": "YOUR_FINDIP_API_KEY",
        "endpoint": "https://api.findip.net/{}/?token={}"
    },
    "virustotal": {
        "enabled": true,
        "api_key": "YOUR_VIRUSTOTAL_API_KEY",
        "endpoint": "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    },
    "shodan": {
        "enabled": true,
        "api_key": "YOUR_SHODAN_API_KEY",
        "endpoint": "https://api.shodan.io/shodan/host/{ip}"
    },
    "abuseipdb": {
        "enabled": true,
        "api_key": "YOUR_ABUSEIPDB_API_KEY",
        "endpoint": "https://api.abuseipdb.com/api/v2/check"
    }
}
```

Ensure you replace the placeholder `YOUR_API_KEY` with actual API keys.

## API Integrations

1. **VirusTotal**: Provides detailed analysis and detection information from multiple security vendors.
2. **Shodan**: Offers insights into open ports and potential services running on the IP.
3. **AbuseIPDB**: Lists the number of times the IP has been reported for abuse, along with a confidence score.
4. **FindIP**: Provides geographical information, ISP, ASN, and user type.

## Output

- For **single IP** analysis, the results are printed directly in the terminal, providing quick insights.
- For **multiple IPs**, the results are saved to a CSV file. The CSV contains columns such as IP, City, Country, ISP, ASN, VirusTotal Detections, Open Ports, AbuseIPDB Reports, etc.

## Contributing

Contributions are welcome! If you would like to contribute to this project:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-branch-name`).
3. Commit your changes (`git commit -m 'Add a feature'`).
4. Push to the branch (`git push origin feature-branch-name`).
5. Open a Pull Request.

## Contact

If you have any questions, feel free to reach out:

- **GitHub**: [mxm0z](https://github.com/mxm0z)
- **Email**: gthb.c50d7@passmail.net
