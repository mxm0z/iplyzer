#!/usr/bin/env python3
"""
iplyzer - Modern IP Address Enrichment Tool

A production-quality CLI tool for enriching IP addresses using multiple
threat intelligence APIs including FindIP, VirusTotal, Shodan, and AbuseIPDB.
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import logging
import random
import string
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx
from pydantic import BaseModel, Field, ValidationError, field_validator
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

# Version
__version__ = "2.0.0"

# Configure console for rich output
console = Console()


# Custom Exceptions
class IPlyzerError(Exception):
    """Base exception for iplyzer errors."""

    pass


class ConfigurationError(IPlyzerError):
    """Raised when configuration is invalid."""

    pass


class APIError(IPlyzerError):
    """Raised when API request fails."""

    pass


# Pydantic Models for Configuration Validation
class APIConfig(BaseModel):
    """Base configuration for API endpoints."""

    enabled: bool = True
    api_key: str = Field(..., min_length=1)
    endpoint: str = Field(..., min_length=1)
    timeout: int = Field(default=30, ge=1, le=300)


class FindIPConfig(APIConfig):
    """FindIP API configuration."""

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, v: str) -> str:
        """Validate FindIP endpoint uses named format strings."""
        if "{ip}" not in v and "{}" in v:
            # Convert old positional format to named format
            return v.replace("{}/?token={}", "{ip}/?token={api_key}")
        return v


class VirusotalConfig(APIConfig):
    """VirusTotal API configuration."""

    pass


class ShodanConfig(APIConfig):
    """Shodan API configuration."""

    pass


class AbuseIPDBConfig(APIConfig):
    """AbuseIPDB API configuration."""

    max_age_days: int = Field(default=90, ge=1, le=365)


class Config(BaseModel):
    """Main configuration model."""

    request_rate_limit: int = Field(default=4, ge=1, le=100)
    ssl_verify: bool = Field(default=True)
    default_timeout: int = Field(default=30, ge=1, le=300)
    findip: Optional[FindIPConfig] = None
    virustotal: Optional[VirusotalConfig] = None
    shodan: Optional[ShodanConfig] = None
    abuseipdb: Optional[AbuseIPDBConfig] = None

    @field_validator("findip", "virustotal", "shodan", "abuseipdb", mode="before")
    @classmethod
    def skip_disabled_apis(cls, v: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
        """Skip validation for disabled APIs."""
        if v is None or not v.get("enabled", True):
            return None
        return v


@dataclass
class APIResult:
    """Result from an API query."""

    api_name: str
    success: bool
    data: Optional[dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class EnrichedIP:
    """Enriched IP address data."""

    ip: str
    city: Optional[str] = None
    country: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[int] = None
    organization: Optional[str] = None
    coordinates: Optional[str] = None
    user_type: Optional[str] = None
    connection_type: Optional[str] = None
    postal_code: Optional[str] = None
    virustotal_detections: Optional[int] = None
    virustotal_community_score: Optional[int] = None
    virustotal_analysis_link: Optional[str] = None
    open_ports: Optional[str] = None
    abuseipdb_reports: Optional[int] = None
    abuseipdb_confidence_score: Optional[int] = None
    api_results: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON/CSV export."""
        return {
            "ip": self.ip,
            "city": self.city or "N/A",
            "country": self.country or "N/A",
            "isp": self.isp or "N/A",
            "asn": self.asn or "N/A",
            "organization": self.organization or "N/A",
            "coordinates": self.coordinates or "N/A",
            "user_type": self.user_type or "N/A",
            "connection_type": self.connection_type or "N/A",
            "postal_code": self.postal_code or "N/A",
            "virustotal_detections": self.virustotal_detections or "N/A",
            "virustotal_community_score": self.virustotal_community_score or "N/A",
            "virustotal_analysis_link": self.virustotal_analysis_link or "N/A",
            "open_ports": self.open_ports or "N/A",
            "abuseipdb_reports": self.abuseipdb_reports or "N/A",
            "abuseipdb_confidence_score": self.abuseipdb_confidence_score or "N/A",
            "api_status": ", ".join(
                f"{api}: {status}" for api, status in self.api_results.items()
            ),
        }


class IPlyzer:
    """Modern IP enrichment tool with async API queries."""

    def __init__(self, config: Config):
        """Initialize IPlyzer with validated configuration."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.rate_limit_delay = 60.0 / config.request_rate_limit

    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            self.logger.warning(f"Invalid IP address: {ip}")
            return False

    async def _fetch_data(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """
        Asynchronous HTTP GET request handler.

        Args:
            client: httpx AsyncClient instance
            url: URL to fetch
            params: Query parameters
            headers: Request headers
            timeout: Request timeout in seconds

        Returns:
            JSON response data

        Raises:
            APIError: If request fails
        """
        try:
            response = await client.get(
                url, params=params, headers=headers, timeout=timeout
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            self.logger.error(f"HTTP error for {url}: {e.response.status_code}")
            raise APIError(f"HTTP {e.response.status_code}: {e.response.text}")
        except httpx.RequestError as e:
            self.logger.error(f"Request error for {url}: {e}")
            raise APIError(f"Request failed: {e}")
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON decode error for {url}: {e}")
            raise APIError(f"Invalid JSON response: {e}")

    async def query_findip(
        self, client: httpx.AsyncClient, ip: str
    ) -> APIResult:
        """Query FindIP API for the given IP address."""
        if not self.config.findip:
            return APIResult(api_name="FindIP", success=False, error="Disabled")

        try:
            endpoint = self.config.findip.endpoint.format(
                ip=ip, api_key=self.config.findip.api_key
            )
            self.logger.debug(f"Querying FindIP for IP: {ip}")

            data = await self._fetch_data(
                client, endpoint, timeout=self.config.findip.timeout
            )
            return APIResult(api_name="FindIP", success=True, data=data)
        except APIError as e:
            self.logger.error(f"FindIP query failed for {ip}: {e}")
            return APIResult(api_name="FindIP", success=False, error=str(e))

    async def query_virustotal(
        self, client: httpx.AsyncClient, ip: str
    ) -> APIResult:
        """Query VirusTotal API for the given IP address."""
        if not self.config.virustotal:
            return APIResult(api_name="VirusTotal", success=False, error="Disabled")

        try:
            endpoint = self.config.virustotal.endpoint.format(ip=ip)
            headers = {"x-apikey": self.config.virustotal.api_key}
            self.logger.debug(f"Querying VirusTotal for IP: {ip}")

            data = await self._fetch_data(
                client, endpoint, headers=headers, timeout=self.config.virustotal.timeout
            )
            return APIResult(api_name="VirusTotal", success=True, data=data)
        except APIError as e:
            self.logger.error(f"VirusTotal query failed for {ip}: {e}")
            return APIResult(api_name="VirusTotal", success=False, error=str(e))

    async def query_shodan(
        self, client: httpx.AsyncClient, ip: str
    ) -> APIResult:
        """Query Shodan API for the given IP address."""
        if not self.config.shodan:
            return APIResult(api_name="Shodan", success=False, error="Disabled")

        try:
            endpoint = self.config.shodan.endpoint.format(ip=ip)
            params = {"key": self.config.shodan.api_key}
            self.logger.debug(f"Querying Shodan for IP: {ip}")

            data = await self._fetch_data(
                client, endpoint, params=params, timeout=self.config.shodan.timeout
            )
            return APIResult(api_name="Shodan", success=True, data=data)
        except APIError as e:
            self.logger.error(f"Shodan query failed for {ip}: {e}")
            return APIResult(api_name="Shodan", success=False, error=str(e))

    async def query_abuseipdb(
        self, client: httpx.AsyncClient, ip: str
    ) -> APIResult:
        """Query AbuseIPDB for the given IP address."""
        if not self.config.abuseipdb:
            return APIResult(api_name="AbuseIPDB", success=False, error="Disabled")

        try:
            endpoint = self.config.abuseipdb.endpoint
            headers = {"Key": self.config.abuseipdb.api_key}
            params = {
                "ipAddress": ip,
                "maxAgeInDays": self.config.abuseipdb.max_age_days,
            }
            self.logger.debug(f"Querying AbuseIPDB for IP: {ip}")

            data = await self._fetch_data(
                client,
                endpoint,
                params=params,
                headers=headers,
                timeout=self.config.abuseipdb.timeout,
            )
            return APIResult(api_name="AbuseIPDB", success=True, data=data)
        except APIError as e:
            self.logger.error(f"AbuseIPDB query failed for {ip}: {e}")
            return APIResult(api_name="AbuseIPDB", success=False, error=str(e))

    def _extract_enrichment_data(
        self, ip: str, api_results: list[APIResult]
    ) -> EnrichedIP:
        """Extract and combine data from all API results."""
        enriched = EnrichedIP(ip=ip)

        for result in api_results:
            # Track API success/failure
            if result.success:
                enriched.api_results[result.api_name] = "OK"
            else:
                enriched.api_results[result.api_name] = f"FAILED: {result.error}"

            if not result.success or not result.data:
                continue

            # Extract FindIP data
            if result.api_name == "FindIP":
                data = result.data
                enriched.city = data.get("city", {}).get("names", {}).get("en")
                enriched.country = data.get("country", {}).get("names", {}).get("en")
                enriched.isp = data.get("traits", {}).get("isp")
                enriched.asn = data.get("traits", {}).get("autonomous_system_number")
                enriched.organization = data.get("traits", {}).get(
                    "autonomous_system_organization"
                )
                lat = data.get("location", {}).get("latitude")
                lon = data.get("location", {}).get("longitude")
                if lat and lon:
                    enriched.coordinates = f"{lat}, {lon}"
                enriched.user_type = data.get("traits", {}).get("user_type")
                enriched.connection_type = data.get("traits", {}).get("connection_type")
                enriched.postal_code = data.get("postal", {}).get("code")

            # Extract VirusTotal data
            elif result.api_name == "VirusTotal" and "data" in result.data:
                vt_attributes = result.data["data"].get("attributes", {})
                enriched.virustotal_detections = (
                    vt_attributes.get("last_analysis_stats", {}).get("malicious")
                )
                enriched.virustotal_community_score = vt_attributes.get("reputation")
                enriched.virustotal_analysis_link = (
                    f"https://www.virustotal.com/gui/ip-address/{ip}"
                )

            # Extract Shodan data
            elif result.api_name == "Shodan":
                open_ports = result.data.get("ports", [])
                if open_ports:
                    enriched.open_ports = " ".join(f"{port}/tcp" for port in open_ports)

            # Extract AbuseIPDB data
            elif result.api_name == "AbuseIPDB" and "data" in result.data:
                abuse_data = result.data["data"]
                enriched.abuseipdb_reports = abuse_data.get("totalReports")
                enriched.abuseipdb_confidence_score = abuse_data.get(
                    "abuseConfidenceScore"
                )

        return enriched

    async def analyze_ip(self, ip: str) -> EnrichedIP:
        """
        Analyze a single IP address using all enabled APIs in parallel.

        Args:
            ip: IP address to analyze

        Returns:
            EnrichedIP object with combined data from all sources
        """
        self.logger.info(f"Analyzing IP: {ip}")

        # Configure httpx client with SSL settings
        async with httpx.AsyncClient(verify=self.config.ssl_verify) as client:
            # Query all APIs in parallel
            tasks = [
                self.query_findip(client, ip),
                self.query_virustotal(client, ip),
                self.query_shodan(client, ip),
                self.query_abuseipdb(client, ip),
            ]

            api_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Convert exceptions to APIResult objects
            processed_results: list[APIResult] = []
            for i, result in enumerate(api_results):
                if isinstance(result, Exception):
                    api_name = ["FindIP", "VirusTotal", "Shodan", "AbuseIPDB"][i]
                    self.logger.error(f"Unexpected error in {api_name}: {result}")
                    processed_results.append(
                        APIResult(
                            api_name=api_name, success=False, error=f"Unexpected: {result}"
                        )
                    )
                else:
                    processed_results.append(result)

        return self._extract_enrichment_data(ip, processed_results)

    async def analyze_ips(self, ip_list: list[str]) -> list[EnrichedIP]:
        """
        Analyze a list of IP addresses with rate limiting.

        Args:
            ip_list: List of IP addresses to analyze

        Returns:
            List of EnrichedIP objects
        """
        # Validate IPs
        valid_ips = [ip for ip in ip_list if self.validate_ip(ip)]

        if not valid_ips:
            raise IPlyzerError("No valid IP addresses to analyze")

        self.logger.info(f"Analyzing {len(valid_ips)} IP address(es)")

        results: list[EnrichedIP] = []
        for i, ip in enumerate(valid_ips):
            result = await self.analyze_ip(ip)
            results.append(result)

            # Rate limiting between IPs (not needed for last IP)
            if i < len(valid_ips) - 1:
                self.logger.debug(
                    f"Rate limiting: sleeping for {self.rate_limit_delay:.2f} seconds"
                )
                await asyncio.sleep(self.rate_limit_delay)

        return results


def load_config(config_path: Path) -> Config:
    """
    Load and validate configuration from JSON file.

    Args:
        config_path: Path to configuration file

    Returns:
        Validated Config object

    Raises:
        ConfigurationError: If configuration is invalid
    """
    if not config_path.exists():
        raise ConfigurationError(f"Configuration file not found: {config_path}")

    try:
        with open(config_path) as f:
            config_data = json.load(f)
        return Config(**config_data)
    except json.JSONDecodeError as e:
        raise ConfigurationError(f"Invalid JSON in config file: {e}")
    except ValidationError as e:
        raise ConfigurationError(f"Invalid configuration: {e}")


def read_ip_list(ip_argument: str) -> list[str]:
    """
    Read IP addresses from file or command line argument.

    Args:
        ip_argument: File path or comma-separated IP list

    Returns:
        List of IP addresses
    """
    path = Path(ip_argument)
    if path.is_file():
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    else:
        return [ip.strip() for ip in ip_argument.split(",") if ip.strip()]


def generate_random_filename(prefix: str = "report_", extension: str = ".csv") -> str:
    """Generate a random filename with given prefix and extension."""
    random_chars = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}{random_chars}{extension}"


def display_single_result(enriched: EnrichedIP) -> None:
    """Display single IP analysis result in a rich table."""
    table = Table(title=f"IP Analysis Results: {enriched.ip}", show_header=True)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")

    # Display all fields
    for key, value in enriched.to_dict().items():
        if key != "ip":  # Skip IP as it's in the title
            table.add_row(key.replace("_", " ").title(), str(value))

    console.print(table)

    # Display API status summary
    console.print("\n[bold]API Status Summary:[/bold]")
    for api_name, status in enriched.api_results.items():
        if status == "OK":
            console.print(f"  [green]{api_name}: {status}[/green]")
        else:
            console.print(f"  [red]{api_name}: {status}[/red]")


def save_csv_report(results: list[EnrichedIP], output_path: Path) -> None:
    """Save analysis results to CSV file."""
    if not results:
        raise IPlyzerError("No results to save")

    fieldnames = list(results[0].to_dict().keys())

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result.to_dict())


def save_json_report(results: list[EnrichedIP], output_path: Path) -> None:
    """Save analysis results to JSON file."""
    if not results:
        raise IPlyzerError("No results to save")

    data = [result.to_dict() for result in results]

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def setup_logging(verbose: bool) -> None:
    """Configure logging with rich handler."""
    log_level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                rich_tracebacks=True, show_time=True, show_path=verbose, markup=True
            )
        ],
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="iplyzer - Modern IP Address Enrichment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single IP
  %(prog)s -i 8.8.8.8

  # Analyze multiple IPs from file
  %(prog)s -i ip_list.txt -o results.csv

  # Analyze with JSON output
  %(prog)s -i 1.1.1.1,8.8.8.8 --json -o results.json

  # Verbose logging
  %(prog)s -i 8.8.8.8 -v
        """,
    )

    parser.add_argument(
        "-i",
        "--ips",
        type=str,
        required=True,
        help="IP address(es) or file containing IPs (one per line)",
    )

    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default="config.json",
        help="Path to configuration JSON file (default: config.json)",
    )

    parser.add_argument(
        "-o", "--output", type=str, help="Output file name (auto-generated if not specified)"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format instead of CSV",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose/debug logging",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser.parse_args()


async def main() -> int:
    """Main entry point for the CLI tool."""
    args = parse_arguments()

    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    try:
        # Load configuration
        config_path = Path(args.config)
        logger.info(f"Loading configuration from: {config_path}")
        config = load_config(config_path)

        # Read IP list
        logger.info(f"Reading IP list from: {args.ips}")
        ip_list = read_ip_list(args.ips)
        logger.info(f"Found {len(ip_list)} IP address(es)")

        # Initialize and run analysis
        iplyzer = IPlyzer(config)
        results = await iplyzer.analyze_ips(ip_list)

        # Output results
        if len(results) == 1:
            # Single IP: display in terminal
            display_single_result(results[0])
        else:
            # Multiple IPs: save to file
            if args.output:
                output_path = Path(args.output)
            else:
                extension = ".json" if args.json else ".csv"
                output_path = Path(generate_random_filename(extension=extension))

            if args.json:
                save_json_report(results, output_path)
            else:
                save_csv_report(results, output_path)

            console.print(
                f"\n[green]Analysis complete![/green] Results saved to: {output_path}"
            )

        return 0

    except ConfigurationError as e:
        console.print(f"[red]Configuration Error:[/red] {e}", style="bold red")
        return 1
    except IPlyzerError as e:
        console.print(f"[red]Error:[/red] {e}", style="bold red")
        return 1
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        return 130
    except Exception as e:
        logger.exception("Unexpected error occurred")
        console.print(f"[red]Unexpected Error:[/red] {e}", style="bold red")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
