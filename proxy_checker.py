import asyncio
import argparse
import time
import json
from pathlib import Path
from typing import Optional, Dict, Any, List

import aiohttp
from aiohttp_socks import ProxyConnector
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn

console = Console()

TEST_ENDPOINT = "http://httpbin.org/ip"
JUDGE_ENDPOINT = "http://httpbin.org/headers"

class ProxyChecker:
    def __init__(self, timeout: float = 8.0, concurrency: int = 50, my_ip: str = ""):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)
        self.my_ip = my_ip
        self.working_proxies: List[Dict[str, Any]] = []

    async def get_my_ip(self) -> str:
        """Fetch external host IP to calculate anonymity score."""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get("https://api64.ipify.org?format=json") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("ip", "")
        except Exception:
            return ""

    def classify_anonymity(self, headers_data: dict, reported_ip: str) -> str:
        """
        Determines proxy anonymity:
        - Elite: Real IP is hidden and proxy headers are absent.
        - Anonymous: Real IP is hidden, but proxy headers are present.
        - Transparent: Real IP is forwarded.
        """
        headers = {k.lower(): v for k, v in headers_data.get("headers", {}).items()}
        forwarded_for = headers.get("x-forwarded-for", "")
        via = headers.get("via", "")
        proxy_conn = headers.get("proxy-connection", "")

        if self.my_ip and self.my_ip in forwarded_for:
            return "Transparent"
        if via or proxy_conn or forwarded_for:
            return "Anonymous"
        return "Elite"

    def normalize_proxy(self, proxy_str: str) -> str:
        """Ensure standard scheme formatting."""
        proxy_str = proxy_str.strip()
        if not (proxy_str.startswith("http://") or 
                proxy_str.startswith("https://") or 
                proxy_str.startswith("socks4://") or 
                proxy_str.startswith("socks5://")):
            return f"http://{proxy_str}"
        return proxy_str

    async def check_proxy(self, raw_proxy: str, progress, task_id) -> Optional[Dict[str, Any]]:
        proxy_url = self.normalize_proxy(raw_proxy)
        start_time = time.perf_counter()
        
        async with self.semaphore:
            try:
                connector = ProxyConnector.from_url(proxy_url)
                async with aiohttp.ClientSession(connector=connector, timeout=self.timeout) as session:
                    # Step 1: Basic IP fetch & latency
                    async with session.get(TEST_ENDPOINT) as resp:
                        if resp.status != 200:
                            progress.advance(task_id)
                            return None
                        ip_data = await resp.json()
                        reported_ip = ip_data.get("origin", "").split(",")[0].strip()

                    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

                    # Step 2: Anonymity level evaluation
                    anonymity = "Unknown"
                    try:
                        async with session.get(JUDGE_ENDPOINT) as headers_resp:
                            if headers_resp.status == 200:
                                headers_data = await headers_resp.json()
                                anonymity = self.classify_anonymity(headers_data, reported_ip)
                    except Exception:
                        anonymity = "Anonymous"

                    result = {
                        "proxy": raw_proxy.strip(),
                        "url": proxy_url,
                        "ip": reported_ip,
                        "latency_ms": latency_ms,
                        "anonymity": anonymity,
                        "protocol": proxy_url.split("://")[0].upper()
                    }
                    self.working_proxies.append(result)
                    progress.advance(task_id)
                    return result
            except Exception:
                progress.advance(task_id)
                return None

    async def run(self, proxy_list: List[str]):
        if not self.my_ip:
            console.print("[yellow]Discovering your public IP for anonymity detection...[/yellow]")
            self.my_ip = await self.get_my_ip()
            if self.my_ip:
                console.print(f"[green]✓ Public IP identified:[/green] {self.my_ip}")
            else:
                console.print("[dim yellow]! Could not auto-detect local public IP, proceeding with header inspection.[/dim yellow]")

        console.print(f"[cyan]Testing {len(proxy_list)} proxies with concurrency={self.concurrency}...[/cyan]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Scanning proxies...", total=len(proxy_list))
            tasks = [self.check_proxy(p, progress, task) for p in proxy_list if p.strip()]
            await asyncio.gather(*tasks)

        self.display_results()

    def display_results(self):
        table = Table(title="[bold green]Active Proxies Verified[/bold green]", show_header=True, header_style="bold magenta")
        table.add_column("Protocol", style="cyan", width=10)
        table.add_column("Proxy Address", style="bold white", width=30)
        table.add_column("External IP", style="dim", width=18)
        table.add_column("Latency", justify="right", style="green", width=12)
        table.add_column("Anonymity", justify="center", width=15)

        for p in sorted(self.working_proxies, key=lambda x: x["latency_ms"]):
            anon_style = "green" if p["anonymity"] == "Elite" else "yellow" if p["anonymity"] == "Anonymous" else "red"
            table.add_row(
                p["protocol"],
                p["proxy"],
                p["ip"],
                f"{p['latency_ms']} ms",
                f"[{anon_style}]{p['anonymity']}[/{anon_style}]"
            )

        console.print("\n")
        console.print(table)
        console.print(f"\n[bold green]✓ Done![/bold green] Found [bold]{len(self.working_proxies)}[/bold] working proxies.")

    def export(self, output_txt: Optional[str] = None, output_json: Optional[str] = None):
        if output_txt:
            with open(output_txt, "w", encoding="utf-8") as f:
                for item in self.working_proxies:
                    f.write(f"{item['proxy']}\n")
            console.print(f"[green]✓ Exported working list to:[/green] {output_txt}")

        if output_json:
            with open(output_json, "w", encoding="utf-8") as f:
                json.dump(self.working_proxies, f, indent=2)
            console.print(f"[green]✓ Exported detailed JSON to:[/green] {output_json}")


def main():
    parser = argparse.ArgumentParser(description="Async Fast Multi-Protocol Proxy Checker & Anonymity Judge")
    parser.add_argument("-f", "--file", default="proxies.txt", help="Path to text file containing proxies (default: proxies.txt)")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="Maximum concurrent requests (default: 50)")
    parser.add_argument("-t", "--timeout", type=float, default=8.0, help="Connection timeout in seconds (default: 8.0)")
    parser.add_argument("-o", "--output", default="working_proxies.txt", help="Output file for active proxies (default: working_proxies.txt)")
    parser.add_argument("--json", default="working_proxies.json", help="Output JSON file for full diagnostics")

    args = parser.parse_args()

    proxy_path = Path(args.file)
    if not proxy_path.exists():
        console.print(f"[red]Error: Input file '{args.file}' not found![/red]")
        return

    with open(proxy_path, "r", encoding="utf-8") as f:
        proxies = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not proxies:
        console.print("[yellow]No proxies found in file.[/yellow]")
        return

    checker = ProxyChecker(timeout=args.timeout, concurrency=args.concurrency)
    asyncio.run(checker.run(proxies))
    checker.export(output_txt=args.output, output_json=args.json)


if __name__ == "__main__":
    main()
