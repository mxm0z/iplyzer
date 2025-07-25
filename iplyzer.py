import asyncio
import aiohttp
import json
import csv
import argparse
import os
import random
import string
from typing import List, Dict

class IPAnalysisTool:
    def __init__(self, config):
        """
        Initialize the tool with the configuration for APIs.
        """
        print("Initializing IPAnalysisTool with configuration.")
        self.config = config
        self.request_rate_limit = config.get("request_rate_limit", 4)
        self.time_between_requests = 60 / self.request_rate_limit
        print(f"Request rate limit set to {self.request_rate_limit} requests per minute.")

    def validate_ip(self, ip_list: List[str]) -> List[str]:
        """
        Validate IP addresses and return a clean list of valid IPs.
        """
        print("Validating IP addresses...")
        import ipaddress
        valid_ips = []
        for ip in ip_list:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                print(f"Invalid IP address: {ip}")
        print(f"Validated IPs: {valid_ips}")
        return valid_ips

    async def fetch_data(self, session, url, params=None, headers=None):
        """
        Asynchronous HTTP GET request handler.
        """
        print(f"Fetching data from URL: {url} with params: {params} and headers: {headers}")
        try:
            async with session.get(url, params=params, headers=headers, ssl=False) as response:
                if response.status == 200:
                    print(f"Successfully fetched data from {url}")
                else:
                    print(f"Failed to fetch data from {url}, Status Code: {response.status}")
                return await response.json()
        except Exception as e:
            print(f"Error fetching data from {url}: {e}")
            return None

    async def query_findip(self, session, ip: str):
        """
        Query FindIP API for the given IP address.
        """
        if not self.config.get("findip", {}).get("enabled", False):
            print("FindIP is not enabled in the configuration.")
            return None

        api_key = self.config["findip"]["api_key"]
        endpoint = self.config["findip"]["endpoint"].format(ip, api_key)
        print(f"Querying FindIP for IP: {ip}")

        return await self.fetch_data(session, endpoint)

    async def query_virustotal(self, session, ip: str):
        """
        Query VirusTotal API for the given IP address.
        """
        if not self.config.get("virustotal", {}).get("enabled", False):
            print("VirusTotal is not enabled in the configuration.")
            return None

        api_key = self.config["virustotal"]["api_key"]
        endpoint = self.config["virustotal"]["endpoint"].format(ip=ip)
        headers = {"x-apikey": api_key}
        print(f"Querying VirusTotal for IP: {ip}")

        return await self.fetch_data(session, endpoint, headers=headers)

    async def query_shodan(self, session, ip: str):
        """
        Query Shodan API for the given IP address.
        """
        if not self.config.get("shodan", {}).get("enabled", False):
            print("Shodan is not enabled in the configuration.")
            return None

        api_key = self.config["shodan"]["api_key"]
        endpoint = self.config["shodan"]["endpoint"].format(ip=ip)
        params = {"key": api_key}
        print(f"Querying Shodan for IP: {ip}")

        return await self.fetch_data(session, endpoint, params)

    async def query_abuseipdb(self, session, ip: str):
        """
        Query AbuseIPDB for the given IP address.
        """
        if not self.config.get("abuseipdb", {}).get("enabled", False):
            print("AbuseIPDB is not enabled in the configuration.")
            return None

        api_key = self.config["abuseipdb"]["api_key"]
        endpoint = self.config["abuseipdb"]["endpoint"]
        headers = {"Key": api_key}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        print(f"Querying AbuseIPDB for IP: {ip}")

        return await self.fetch_data(session, endpoint, params=params, headers=headers)

    async def analyze_ip(self, ip: str) -> Dict:
        """
        Analyze a single IP address using all enabled data sources.
        """
        print(f"Analyzing IP: {ip}")
        async with aiohttp.ClientSession() as session:
            findip = await self.query_findip(session, ip)
            virustotal = await self.query_virustotal(session, ip)
            shodan = await self.query_shodan(session, ip)
            abuseipdb = await self.query_abuseipdb(session, ip)

        combined_result = {
            "ip": ip
        }

        # Extract specific fields from FindIP
        if findip:
            print(f"Extracting FindIP data for IP: {ip}")
            combined_result.update({
                "city": findip.get("city", {}).get("names", {}).get("en"),
                "country": findip.get("country", {}).get("names", {}).get("en"),
                "isp": findip.get("traits", {}).get("isp"),
                "asn": findip.get("traits", {}).get("autonomous_system_number"),
                "organization": findip.get("traits", {}).get("autonomous_system_organization"),
                "coordinates": f"{findip.get('location', {}).get('latitude')}, {findip.get('location', {}).get('longitude')}",
                "user_type": findip.get("traits", {}).get("user_type"),
                "connection_type": findip.get("traits", {}).get("connection_type"),
                "postal_code": findip.get("postal", {}).get("code")
            })

        # Extract specific fields from VirusTotal
        if virustotal and "data" in virustotal:
            print(f"Extracting VirusTotal data for IP: {ip}")
            vt_attributes = virustotal["data"].get("attributes", {})
            combined_result.update({
                "virustotal_detections": vt_attributes.get("last_analysis_stats", {}).get("malicious"),
                "virustotal_community_score": vt_attributes.get("reputation"),
                "virustotal_analysis_link": f"https://www.virustotal.com/gui/ip-address/{ip}"
            })

        # Extract specific fields from Shodan
        if shodan:
            print(f"Extracting Shodan data for IP: {ip}")
            open_ports = shodan.get("ports", [])
            combined_result["open_ports"] = " ".join([f"{port}/tcp" for port in open_ports])

        # Extract specific fields from AbuseIPDB
        if abuseipdb and "data" in abuseipdb:
            print(f"Extracting AbuseIPDB data for IP: {ip}")
            abuse_data = abuseipdb["data"]
            combined_result.update({
                "abuseipdb_reports": abuse_data.get("totalReports"),
                "abuseipdb_confidence_score": abuse_data.get("abuseConfidenceScore")
            })

        return combined_result

    def save_report(self, results: List[Dict], output_file: str):
        """
        Save the analysis results to a CSV file.
        """
        print(f"Saving report to file: {output_file}")
        with open(output_file, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([
                "IP", "City", "Country", "ISP", "ASN", "Organization", "Coordinates", "User Type", "Connection Type", "Postal Code", "VT Detections", "VT Score", "VT Link", "Open Ports", "AbuseIPDB Reports", "AbuseIPDB Score"
            ])
            for result in results:
                writer.writerow([
                    result["ip"],
                    result.get("city", "N/A"),
                    result.get("country", "N/A"),
                    result.get("isp", "N/A"),
                    result.get("asn", "N/A"),
                    result.get("organization", "N/A"),
                    result.get("coordinates", "N/A"),
                    result.get("user_type", "N/A"),
                    result.get("connection_type", "N/A"),
                    result.get("postal_code", "N/A"),
                    result.get("virustotal_detections", "N/A"),
                    result.get("virustotal_community_score", "N/A"),
                    result.get("virustotal_analysis_link", "N/A"),
                    result.get("open_ports", "N/A"),
                    result.get("abuseipdb_reports", "N/A"),
                    result.get("abuseipdb_confidence_score", "N/A")
                ])
        print("Report saved successfully.")

    async def analyze_ips(self, ip_list: List[str]) -> List[Dict]:
        """
        Analyze a list of IP addresses asynchronously.
        """
        print("Starting IP analysis...")
        valid_ips = self.validate_ip(ip_list)
        results = []
        for ip in valid_ips:
            print(f"Analyzing IP: {ip}")
            results.append(await self.analyze_ip(ip))
            print(f"Sleeping for {self.time_between_requests} seconds to respect rate limit")
            await asyncio.sleep(self.time_between_requests)  # Respect rate limit for requests
        print("IP analysis completed.")
        return results

def load_config(config_file: str) -> Dict:
    """
    Load configuration for APIs from a JSON file.
    """
    print(f"Loading configuration from file: {config_file}")
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Configuration file not found: {config_file}")

    with open(config_file, "r") as file:
        config = json.load(file)
        print("Configuration loaded successfully.")
        return config

def parse_arguments():
    """
    Parse CLI arguments.
    """
    print("Parsing command line arguments.")
    parser = argparse.ArgumentParser(description="IP Analysis CLI Tool")
    parser.add_argument(
        "-i", "--ips", type=str, required=True,
        help="List of IP addresses or a file containing IPs (one per line)."
    )
    parser.add_argument(
        "-c", "--config", type=str, default="config.json",
        help="Path to the configuration JSON file (default: config.json)."
    )
    parser.add_argument(
        "-o", "--output", type=str, default=None,
        help="Output CSV file name (default: report_{random}.csv)."
    )
    return parser.parse_args()

def read_ip_list(ip_argument: str) -> List[str]:
    """
    Reads a list of IP addresses from either a provided string or a file.
    """
    print(f"Reading IP list from: {ip_argument}")
    if os.path.isfile(ip_argument):
        with open(ip_argument, "r") as file:
            ip_list = [line.strip() for line in file if line.strip()]
            print(f"Loaded IPs from file: {ip_list}")
            return ip_list
    else:
        ip_list = ip_argument.split(",")
        print(f"Loaded IPs from argument: {ip_list}")
        return ip_list

def generate_random_filename(prefix: str = "report_", extension: str = ".csv") -> str:
    """
    Generate a random filename with a given prefix and extension.
    """
    random_chars = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    filename = f"{prefix}{random_chars}{extension}"
    print(f"Generated random filename: {filename}")
    return filename

if __name__ == "__main__":
    args = parse_arguments()

    try:
        # Load configuration
        config = load_config(args.config)

        # Read IP list from file or command line argument
        ip_list = read_ip_list(args.ips)

        # Determine the output file name
        output_file = args.output if args.output else generate_random_filename()

        # Initialize and run analysis
        print("Initializing IP analysis tool.")
        tool = IPAnalysisTool(config)
        results = asyncio.run(tool.analyze_ips(ip_list))

        # Save the report or print the result
        if len(results) == 1:
            result = results[0]
            print("\nParsed Results for IP Analysis:")
            for key, value in result.items():
                print(f"{key}: {value}")
        else:
            tool.save_report(results, output_file)
            print(f"Analysis complete. Report saved to '{output_file}'.")
    except Exception as e:
        print(f"Error: {e}")
