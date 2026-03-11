"""
AutoPoV CLI Tool
Command-line interface for AutoPoV vulnerability scanner
"""

import os
import sys
import json
import time
from typing import Optional, List

import click
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.syntax import Syntax

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

console = Console()

# Configuration
API_BASE_URL = os.getenv("AUTOPOV_API_URL", "http://localhost:8000/api")


def get_api_key() -> Optional[str]:
    """Get API key from environment or config file"""
    # Check environment
    api_key = os.getenv("AUTOPOV_API_KEY")
    if api_key:
        return api_key
    
    # Check config file
    config_path = os.path.expanduser("~/.autopov/config.json")
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = json.load(f)
            return config.get("api_key")
    
    return None


def save_api_key(api_key: str):
    """Save API key to config file"""
    config_dir = os.path.expanduser("~/.autopov")
    os.makedirs(config_dir, exist_ok=True)
    
    config_path = os.path.join(config_dir, "config.json")
    with open(config_path, 'w') as f:
        json.dump({"api_key": api_key}, f)


def make_api_request(
    method: str,
    endpoint: str,
    api_key: str,
    data: dict = None,
    files: dict = None
) -> dict:
    """Make API request with authentication"""
    url = f"{API_BASE_URL}{endpoint}"
    headers = {
        "Authorization": f"Bearer {api_key}"
    }
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers)
        elif method == "POST":
            if files:
                response = requests.post(url, headers=headers, data=data, files=files)
            else:
                headers["Content-Type"] = "application/json"
                response = requests.post(url, headers=headers, json=data)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        response.raise_for_status()
        return response.json()
    
    except requests.exceptions.RequestException as e:
        console.print(f"[red]API Error: {e}[/red]")
        sys.exit(1)


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """AutoPoV - Autonomous Proof-of-Vulnerability Framework"""
    pass


def get_supported_cwes(api_key: str) -> List[str]:
    """Fetch supported CWEs from backend"""
    try:
        response = make_api_request("GET", "/config", api_key)
        return response.get("supported_cwes", ["CWE-89", "CWE-119", "CWE-190", "CWE-416"])
    except:
        return ["CWE-89", "CWE-119", "CWE-190", "CWE-416"]


# Model provider mapping for OpenRouter
MODEL_PROVIDERS = {
    "1": ("OpenAI", "openai/gpt-5.4-pro"),
    "2": ("Claude", "anthropic/claude-sonnet-4.6"),
    "3": ("Gemini", "google/gemini-3.1-flash-lite-preview"),
    "4": ("Grok", "x-ai/grok-4.1-fast")
}


def select_model() -> str:
    """Display model selection menu and return selected model ID"""
    console.print("\n[bold cyan]Select AI Model Provider:[/bold cyan]")
    console.print("-" * 40)
    for key, (name, model_id) in MODEL_PROVIDERS.items():
        console.print(f"  [{key}] {name}")
    console.print("-" * 40)
    
    while True:
        choice = console.input("[bold]Enter choice (1-4): [/bold]").strip()
        if choice in MODEL_PROVIDERS:
            provider_name, model_id = MODEL_PROVIDERS[choice]
            console.print(f"[green]✓ Selected: {provider_name} ({model_id})[/green]\n")
            return model_id
        console.print("[red]Invalid choice. Please enter 1, 2, 3, or 4.[/red]")


@cli.command()
@click.argument("source")
@click.option("--model", "-m", default=None, help="Model to use (overrides interactive selection)")
@click.option("--cwe", "-c", multiple=True, default=None, help="CWEs to check (default: all supported)")
@click.option("--output", "-o", type=click.Choice(["json", "table", "pdf"]), default="table", help="Output format")
@click.option("--api-key", "-k", help="API key")
@click.option("--branch", "-b", help="Git branch")
@click.option("--wait/--no-wait", default=True, help="Wait for scan completion")
def scan(
    source: str,
    model: str,
    cwe: tuple,
    output: str,
    api_key: Optional[str],
    branch: Optional[str],
    wait: bool
):
    """Scan a codebase for vulnerabilities"""
    
    # Get API key
    if not api_key:
        api_key = get_api_key()
    
    if not api_key:
        console.print("[red]Error: API key required. Set AUTOPOV_API_KEY or use --api-key[/red]")
        sys.exit(1)
    
    # Select model if not provided via --model
    if model is None:
        model = select_model()
    
    # Use provided CWEs or fetch all supported from backend
    if cwe:
        cwes = list(cwe)
    else:
        cwes = get_supported_cwes(api_key)
        console.print(f"[blue]Scanning with {len(cwes)} CWE categories[/blue]")
    
    # Determine source type
    if source.startswith(("http://", "https://", "git@")):
        # Git repository
        console.print(f"[blue]Scanning Git repository: {source}[/blue]")
        
        response = make_api_request(
            "POST",
            "/scan/git",
            api_key,
            data={
                "url": source,
                "branch": branch,
                "model": model,
                "cwes": cwes
            }
        )
    
    elif os.path.isfile(source) and source.endswith(".zip"):
        # ZIP file
        console.print(f"[blue]Scanning ZIP file: {source}[/blue]")
        
        with open(source, "rb") as f:
            response = make_api_request(
                "POST",
                "/scan/zip",
                api_key,
                data={"model": model, "cwes": ",".join(cwes)},
                files={"file": f}
            )
    
    elif os.path.isdir(source):
        # Directory - create ZIP
        console.print(f"[blue]Scanning directory: {source}[/blue]")
        
        import shutil
        zip_path = f"/tmp/autopov_scan_{int(time.time())}.zip"
        shutil.make_archive(zip_path.replace(".zip", ""), 'zip', source)
        
        with open(zip_path, "rb") as f:
            response = make_api_request(
                "POST",
                "/scan/zip",
                api_key,
                data={"model": model, "cwes": ",".join(cwes)},
                files={"file": f}
            )
        
        os.remove(zip_path)
    
    else:
        console.print(f"[red]Error: Unknown source type: {source}[/red]")
        sys.exit(1)
    
    scan_id = response["scan_id"]
    console.print(f"[green]Scan created: {scan_id}[/green]")
    
    if wait:
        console.print("[blue]Waiting for scan to complete...[/blue]")
        console.print("[dim]Press Ctrl+C to stop monitoring (scan will continue)[/dim]\n")
        
        last_logs_count = 0
        last_findings_count = 0
        shown_findings = set()  # Track shown findings to avoid duplicates
        
        try:
            while True:
                status_response = make_api_request(
                    "GET",
                    f"/scan/{scan_id}",
                    api_key
                )
                
                status = status_response.get("status", "unknown")
                error = status_response.get("error")
                logs = status_response.get("logs", [])
                findings = status_response.get("findings", [])
                
                # Show new logs
                if logs and len(logs) > last_logs_count:
                    for log in logs[last_logs_count:]:
                        # Escape square brackets to prevent Rich markup errors
                        safe_log = log.replace("[", "\\[").replace("]", "\\]")
                        # Color code different types of logs
                        if "found" in log.lower() or "detected" in log.lower():
                            console.print(f"[green]✓ {safe_log}[/green]")
                        elif "error" in log.lower() or "failed" in log.lower():
                            console.print(f"[red]✗ {safe_log}[/red]")
                        elif "warning" in log.lower():
                            console.print(f"[yellow]⚠ {safe_log}[/yellow]")
                        elif "ingesting" in log.lower() or "cloning" in log.lower():
                            console.print(f"[blue]→ {safe_log}[/blue]")
                        else:
                            console.print(f"  {safe_log}")
                    last_logs_count = len(logs)
                
                # Show new findings immediately
                if findings and len(findings) > last_findings_count:
                    for finding in findings[last_findings_count:]:
                        finding_key = f"{finding.get('filepath')}:{finding.get('line_number')}:{finding.get('cwe_type')}"
                        if finding_key not in shown_findings:
                            shown_findings.add(finding_key)
                            cwe = finding.get('cwe_type', 'Unknown')
                            file = finding.get('filepath', 'Unknown')
                            line = finding.get('line_number', 0)
                            confidence = finding.get('confidence', 0)
                            
                            # Show finding with color based on confidence
                            if confidence >= 0.8:
                                console.print(f"[red]🔴 HIGH CONFIDENCE: {cwe} at {file}:{line} ({confidence:.0%})[/red]")
                            elif confidence >= 0.5:
                                console.print(f"[yellow]🟡 MEDIUM: {cwe} at {file}:{line} ({confidence:.0%})[/yellow]")
                            else:
                                console.print(f"[blue]🔵 LOW: {cwe} at {file}:{line} ({confidence:.0%})[/blue]")
                    
                    console.print(f"\n[dim]Total findings so far: {len(findings)}[/dim]\n")
                    last_findings_count = len(findings)
                
                # Show current status
                if status in ["failed", "completed"]:
                    console.print(f"\n[bold]Status: {status.upper()}[/bold]")
                    
                if status == "failed":
                    if error:
                        console.print(f"[red]Scan failed: {error}[/red]")
                    if logs:
                        console.print("\n[yellow]Last logs:[/yellow]")
                        for log in logs[-5:]:
                            console.print(f"  {log}")
                    return
                
                if status == "completed":
                    break
                
                time.sleep(2)
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Monitoring stopped. Scan is still running.[/yellow]")
            console.print(f"Use: autopov results {scan_id} --api-key {api_key}")
            return
        
        # Get results
        display_results(scan_id, api_key, output)
    else:
        console.print(f"Use 'autopov results {scan_id}' to check results")


@cli.command()
@click.argument("scan_id")
@click.option("--output", "-o", type=click.Choice(["json", "table", "pdf"]), default="table", help="Output format")
@click.option("--api-key", "-k", help="API key")
def results(scan_id: str, output: str, api_key: Optional[str]):
    """Get scan results"""
    
    if not api_key:
        api_key = get_api_key()
    
    if not api_key:
        console.print("[red]Error: API key required[/red]")
        sys.exit(1)
    
    display_results(scan_id, api_key, output)


def display_results(scan_id: str, api_key: str, output: str):
    """Display scan results"""
    
    response = make_api_request("GET", f"/scan/{scan_id}", api_key)
    
    if output == "json":
        console.print(json.dumps(response, indent=2))
    
    elif output == "table":
        result = response.get("result")
        error = response.get("error")
        status = response.get("status", "unknown")
        logs = response.get("logs", [])
        
        # Check if scan failed with an error
        if status == "failed" and error:
            console.print(f"[red]Scan failed: {error}[/red]")
            if logs:
                console.print("\n[yellow]Logs:[/yellow]")
                for log in logs:
                    console.print(f"  {log}")
            return
        
        if not result:
            console.print(f"[yellow]Scan status: {status}[/yellow]")
            if logs:
                console.print("\n[yellow]Logs:[/yellow]")
                for log in logs:
                    console.print(f"  {log}")
            return
        
        # Summary panel
        summary_text = f"""
Scan ID: {result['scan_id']}
Status: {result['status']}
Model: {result['model_name']}
Duration: {result['duration_s']:.2f}s
Cost: ${result['total_cost_usd']:.4f}

Total Findings: {result['total_findings']}
Confirmed: {result['confirmed_vulns']}
False Positives: {result['false_positives']}
Failed: {result['failed']}
        """
        console.print(Panel(summary_text, title="Scan Summary"))
        
        # Findings table - Show all findings with their status
        if result.get("findings"):
            # First show confirmed vulnerabilities
            confirmed_findings = [f for f in result["findings"] if f.get("final_status") == "confirmed"]
            if confirmed_findings:
                table = Table(title="Confirmed Vulnerabilities")
                table.add_column("CWE", style="cyan")
                table.add_column("File", style="green")
                table.add_column("Line", style="yellow")
                table.add_column("Confidence", style="magenta")
                
                for finding in confirmed_findings:
                    table.add_row(
                        finding.get("cwe_type", "N/A"),
                        finding.get("filepath", "N/A"),
                        str(finding.get("line_number", "N/A")),
                        f"{finding.get('confidence', 0):.2f}"
                    )
                
                console.print(table)
            
            # Show findings with errors or issues
            error_findings = [f for f in result["findings"] if f.get("final_status") != "confirmed" and f.get("llm_verdict") == "ERROR"]
            if error_findings:
                console.print("\n[yellow]Findings with Investigation Errors:[/yellow]")
                error_table = Table()
                error_table.add_column("CWE", style="cyan")
                error_table.add_column("File", style="green")
                error_table.add_column("Line", style="yellow")
                error_table.add_column("Error", style="red")
                
                for finding in error_findings:
                    error_msg = finding.get("llm_explanation", "Unknown error")[:50] + "..."
                    error_table.add_row(
                        finding.get("cwe_type", "N/A"),
                        finding.get("filepath", "N/A"),
                        str(finding.get("line_number", "N/A")),
                        error_msg
                    )
                
                console.print(error_table)
            
            # Show pending/skipped findings
            pending_findings = [f for f in result["findings"] if f.get("final_status") == "pending" and f.get("llm_verdict") != "ERROR"]
            if pending_findings:
                console.print(f"\n[dim]Pending/Skipped Findings: {len(pending_findings)}[/dim]")
                for finding in pending_findings[:5]:  # Show first 5
                    verdict = finding.get("llm_verdict", "UNKNOWN")
                    confidence = finding.get("confidence", 0)
                    console.print(f"  [dim]• {finding.get('cwe_type')} at {finding.get('filepath')}:{finding.get('line_number')} - Verdict: {verdict} ({confidence:.2f})[/dim]")
                if len(pending_findings) > 5:
                    console.print(f"  [dim]... and {len(pending_findings) - 5} more[/dim]")
    
    elif output == "pdf":
        # Download PDF report
        url = f"{API_BASE_URL}/report/{scan_id}?format=pdf"
        headers = {"Authorization": f"Bearer {api_key}"}
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        pdf_path = f"{scan_id}_report.pdf"
        with open(pdf_path, "wb") as f:
            f.write(response.content)
        
        console.print(f"[green]PDF report saved: {pdf_path}[/green]")


@cli.command()
@click.option("--limit", "-l", default=10, help="Number of results")
@click.option("--api-key", "-k", help="API key")
def history(limit: int, api_key: Optional[str]):
    """Show scan history"""
    
    if not api_key:
        api_key = get_api_key()
    
    if not api_key:
        console.print("[red]Error: API key required[/red]")
        sys.exit(1)
    
    response = make_api_request("GET", f"/history?limit={limit}", api_key)
    
    table = Table(title="Scan History")
    table.add_column("Scan ID", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Model", style="blue")
    table.add_column("Confirmed", style="yellow")
    table.add_column("Cost", style="magenta")
    
    for item in response.get("history", []):
        status_color = {
            "completed": "green",
            "failed": "red",
            "running": "blue"
        }.get(item.get("status"), "white")
        
        table.add_row(
            item.get("scan_id", "N/A")[:8] + "...",
            f"[{status_color}]{item.get('status', 'N/A')}[/{status_color}]",
            item.get("model_name", "N/A"),
            item.get("confirmed_vulns", "0"),
            f"${float(item.get('total_cost_usd', 0)):.4f}"
        )
    
    console.print(table)


@cli.command()
@click.argument("scan_id")
@click.option("--format", "-f", type=click.Choice(["json", "pdf"]), default="json", help="Report format")
@click.option("--api-key", "-k", help="API key")
def report(scan_id: str, format: str, api_key: Optional[str]):
    """Generate scan report"""
    
    if not api_key:
        api_key = get_api_key()
    
    if not api_key:
        console.print("[red]Error: API key required[/red]")
        sys.exit(1)
    
    url = f"{API_BASE_URL}/report/{scan_id}?format={format}"
    headers = {"Authorization": f"Bearer {api_key}"}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        filename = f"{scan_id}_report.{format}"
        with open(filename, "wb") as f:
            f.write(response.content)
        
        console.print(f"[green]Report saved: {filename}[/green]")
    
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.group()
def keys():
    """API key management"""
    pass


@keys.command("generate")
@click.option("--admin-key", "-a", help="Admin API key")
@click.option("--name", "-n", default="cli", help="Key name")
def generate_key(admin_key: Optional[str], name: str):
    """Generate new API key (admin only)"""
    
    if not admin_key:
        admin_key = os.getenv("AUTOPOV_ADMIN_KEY")
    
    if not admin_key:
        console.print("[red]Error: Admin key required[/red]")
        sys.exit(1)
    
    url = f"{API_BASE_URL}/keys/generate"
    headers = {
        "Authorization": f"Bearer {admin_key}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(url, headers=headers, params={"name": name})
        response.raise_for_status()
        data = response.json()
        
        api_key = data["key"]
        
        # Save to config
        save_api_key(api_key)
        
        console.print(Panel(
            f"[green]API Key: {api_key}[/green]\n\n"
            "This key has been saved to ~/.autopov/config.json",
            title="API Key Generated"
        ))
    
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@keys.command("list")
@click.option("--admin-key", "-a", help="Admin API key")
def list_keys(admin_key: Optional[str]):
    """List API keys (admin only)"""
    
    if not admin_key:
        admin_key = os.getenv("AUTOPOV_ADMIN_KEY")
    
    if not admin_key:
        console.print("[red]Error: Admin key required[/red]")
        sys.exit(1)
    
    url = f"{API_BASE_URL}/keys"
    headers = {"Authorization": f"Bearer {admin_key}"}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        table = Table(title="API Keys")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Created", style="yellow")
        table.add_column("Active", style="magenta")
        
        for key in data.get("keys", []):
            table.add_row(
                key.get("key_id", "N/A")[:8] + "...",
                key.get("name", "N/A"),
                key.get("created_at", "N/A"),
                "Yes" if key.get("is_active") else "No"
            )
        
        console.print(table)
    
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
def config():
    """Show configuration"""
    api_key = get_api_key()
    
    config_text = f"""
API URL: {API_BASE_URL}
API Key: {'*' * 10 if api_key else 'Not set'}
Config File: ~/.autopov/config.json
    """
    console.print(Panel(config_text, title="Configuration"))


if __name__ == "__main__":
    cli()
