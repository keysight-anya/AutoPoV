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
    files: dict = None,
    admin: bool = False,
    params: dict = None
) -> dict:
    """Make API request with authentication"""
    url = f"{API_BASE_URL}{endpoint}"
    headers = {
        "Authorization": f"Bearer {api_key}"
    }

    try:
        if method == "GET":
            response = requests.get(url, headers=headers, params=params)
        elif method == "POST":
            if files:
                response = requests.post(url, headers=headers, data=data, files=files, params=params)
            else:
                headers["Content-Type"] = "application/json"
                response = requests.post(url, headers=headers, json=data, params=params)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, params=params)
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
    """AutoPoV - Autonomous Proof-of-Vulnerability Agent Framework"""
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


# ──────────────────────────────────────────────────────────────────────────────
# scan command  (git / zip / directory)
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("source")
@click.option("--model", "-m", default=None, help="Model to use (overrides interactive selection)")
@click.option("--cwe", "-c", multiple=True, default=None, help="CWEs to check (default: all supported)")
@click.option("--output", "-o", type=click.Choice(["json", "table", "pdf"]), default="table", help="Output format")
@click.option("--api-key", "-k", help="API key")
@click.option("--branch", "-b", help="Git branch")
@click.option("--lite", is_flag=True, default=False, help="Lite scan (static analysis only, faster)")
@click.option("--wait/--no-wait", default=True, help="Wait for scan completion")
def scan(
    source: str,
    model: str,
    cwe: tuple,
    output: str,
    api_key: Optional[str],
    branch: Optional[str],
    lite: bool,
    wait: bool
):
    """Scan a Git repository, ZIP file, or local directory for vulnerabilities"""

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
                "cwes": cwes,
                "lite": lite
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
                data={"model": model, "cwes": ",".join(cwes), "lite": "true" if lite else "false"},
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
                data={"model": model, "cwes": ",".join(cwes), "lite": "true" if lite else "false"},
                files={"file": f}
            )

        os.remove(zip_path)

    else:
        console.print(f"[red]Error: Unknown source type: {source}[/red]")
        sys.exit(1)

    scan_id = response["scan_id"]
    console.print(f"[green]Scan created: {scan_id}[/green]")

    if wait:
        _monitor_and_display(scan_id, api_key, output)
    else:
        console.print(f"Use 'autopov results {scan_id}' to check results")


# ──────────────────────────────────────────────────────────────────────────────
# paste command  (scan pasted / piped code)
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--language", "-l", default="python",
              type=click.Choice(["python", "javascript", "c", "cpp", "java", "go", "rust"]),
              help="Language of the pasted code")
@click.option("--filename", "-f", default=None, help="Virtual filename (e.g. main.py)")
@click.option("--model", "-m", default=None, help="Model to use (overrides interactive selection)")
@click.option("--cwe", "-c", multiple=True, default=None, help="CWEs to check (default: all supported)")
@click.option("--output", "-o", type=click.Choice(["json", "table", "pdf"]), default="table")
@click.option("--api-key", "-k", help="API key")
@click.option("--lite", is_flag=True, default=False, help="Lite scan (static only, faster)")
@click.option("--wait/--no-wait", default=True, help="Wait for scan completion")
def paste(
    language: str,
    filename: Optional[str],
    model: str,
    cwe: tuple,
    output: str,
    api_key: Optional[str],
    lite: bool,
    wait: bool
):
    """Scan code pasted from stdin

    \b
    Examples:
      cat vulnerable.py | autopov paste --language python
      autopov paste --language javascript --filename app.js < app.js
    """

    if not api_key:
        api_key = get_api_key()

    if not api_key:
        console.print("[red]Error: API key required. Set AUTOPOV_API_KEY or use --api-key[/red]")
        sys.exit(1)

    # Read code from stdin
    if sys.stdin.isatty():
        console.print("[yellow]Paste your code below. Press Ctrl+D (Unix) or Ctrl+Z (Windows) when done:[/yellow]")

    code = sys.stdin.read()
    if not code.strip():
        console.print("[red]Error: No code provided on stdin[/red]")
        sys.exit(1)

    if model is None:
        model = select_model()

    if cwe:
        cwes = list(cwe)
    else:
        cwes = get_supported_cwes(api_key)

    console.print(f"[blue]Scanning pasted {language} code ({len(code)} bytes)...[/blue]")

    response = make_api_request(
        "POST",
        "/scan/paste",
        api_key,
        data={
            "code": code,
            "language": language,
            "filename": filename or f"stdin.{language}",
            "model": model,
            "cwes": cwes,
            "lite": lite
        }
    )

    scan_id = response["scan_id"]
    console.print(f"[green]Scan created: {scan_id}[/green]")

    if wait:
        _monitor_and_display(scan_id, api_key, output)
    else:
        console.print(f"Use 'autopov results {scan_id}' to check results")


# ──────────────────────────────────────────────────────────────────────────────
# cancel command
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("scan_id")
@click.option("--api-key", "-k", help="API key")
def cancel(scan_id: str, api_key: Optional[str]):
    """Cancel a running scan"""

    if not api_key:
        api_key = get_api_key()

    if not api_key:
        console.print("[red]Error: API key required[/red]")
        sys.exit(1)

    response = make_api_request("POST", f"/scan/{scan_id}/cancel", api_key)
    console.print(f"[yellow]Scan {scan_id} cancelled: {response.get('message', 'done')}[/yellow]")


# ──────────────────────────────────────────────────────────────────────────────
# replay command
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("scan_id")
@click.option("--model", "-m", multiple=True, required=True,
              help="Model(s) to replay against. Repeat flag for multiple: -m model1 -m model2")
@click.option("--include-failed", is_flag=True, default=False,
              help="Include failed/unconfirmed findings in replay (default: confirmed only)")
@click.option("--max-findings", default=50, help="Maximum findings to replay (default: 50)")
@click.option("--api-key", "-k", help="API key")
def replay(
    scan_id: str,
    model: tuple,
    include_failed: bool,
    max_findings: int,
    api_key: Optional[str]
):
    """Replay a completed scan against one or more agent models for benchmarking

    \b
    Example:
      autopov replay <scan_id> -m anthropic/claude-3-opus -m openai/gpt-4o
    """

    if not api_key:
        api_key = get_api_key()

    if not api_key:
        console.print("[red]Error: API key required[/red]")
        sys.exit(1)

    models = list(model)
    console.print(f"[blue]Replaying scan {scan_id[:8]}... against {len(models)} model(s)[/blue]")

    response = make_api_request(
        "POST",
        f"/scan/{scan_id}/replay",
        api_key,
        data={
            "models": models,
            "include_failed": include_failed,
            "max_findings": max_findings
        }
    )

    replay_ids = response.get("replay_ids", [])
    console.print(f"[green]Replay started! {len(replay_ids)} replay scan(s) created:[/green]")

    table = Table(title="Replay Scans")
    table.add_column("Replay ID", style="cyan")
    table.add_column("Model", style="green")

    for rid, mod in zip(replay_ids, models):
        table.add_row(rid[:8] + "...", mod)

    console.print(table)
    console.print(f"\n[dim]Use 'autopov results <replay_id>' to check each replay result.[/dim]")
    console.print(f"[dim]Use 'autopov policy' to compare model performance after scans complete.[/dim]")


# ──────────────────────────────────────────────────────────────────────────────
# results command
# ──────────────────────────────────────────────────────────────────────────────

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


# ──────────────────────────────────────────────────────────────────────────────
# history command
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--limit", "-l", default=20, help="Number of results per page (default: 20)")
@click.option("--page", "-p", default=1, help="Page number (1-based, default: 1)")
@click.option("--api-key", "-k", help="API key")
def history(limit: int, page: int, api_key: Optional[str]):
    """Show scan history with pagination"""

    if not api_key:
        api_key = get_api_key()

    if not api_key:
        console.print("[red]Error: API key required[/red]")
        sys.exit(1)

    offset = (page - 1) * limit
    # Fetch one extra to detect if more pages exist
    response = make_api_request(
        "GET",
        f"/history",
        api_key,
        params={"limit": limit + 1, "offset": offset}
    )

    rows = response.get("history", [])
    has_more = len(rows) > limit
    rows = rows[:limit]

    table = Table(title=f"Scan History  (page {page})")
    table.add_column("Scan ID", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Model", style="blue")
    table.add_column("Confirmed", style="yellow")
    table.add_column("Cost", style="magenta")
    table.add_column("Date", style="dim")

    for item in rows:
        status = item.get("status", "N/A")
        status_color = {
            "completed": "green",
            "failed": "red",
            "running": "blue",
            "cancelled": "yellow"
        }.get(status, "white")

        date_str = item.get("start_time", "N/A")
        if date_str and date_str != "N/A":
            try:
                date_str = date_str[:10]
            except Exception:
                pass

        table.add_row(
            item.get("scan_id", "N/A")[:8] + "...",
            f"[{status_color}]{status}[/{status_color}]",
            item.get("model_name", "N/A"),
            str(item.get("confirmed_vulns", "0")),
            f"${float(item.get('total_cost_usd', 0)):.4f}",
            date_str
        )

    console.print(table)

    # Pagination hint
    pagination_parts = []
    if page > 1:
        pagination_parts.append(f"  ← autopov history --page {page - 1}")
    if has_more:
        pagination_parts.append(f"  autopov history --page {page + 1} →")
    if pagination_parts:
        console.print("[dim]" + "     ".join(pagination_parts) + "[/dim]")


# ──────────────────────────────────────────────────────────────────────────────
# policy command  (learning store / model performance)
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--api-key", "-k", help="API key")
def policy(api_key: Optional[str]):
    """Show agent learning store: model performance and cost statistics"""

    if not api_key:
        api_key = get_api_key()

    if not api_key:
        console.print("[red]Error: API key required[/red]")
        sys.exit(1)

    response = make_api_request("GET", "/learning/summary", api_key)

    summary = response.get("summary", {})
    models = response.get("models", {})

    # Summary panel
    summary_text = (
        f"Investigations : {summary.get('investigations_total', 0)}\n"
        f"Investigation cost : ${summary.get('investigations_cost_usd', 0):.4f}\n"
        f"PoV runs       : {summary.get('pov_total', 0)}\n"
        f"PoV successes  : {summary.get('pov_success_total', 0)}\n"
        f"PoV cost       : ${summary.get('pov_cost_usd', 0):.4f}"
    )
    console.print(Panel(summary_text, title="Agent Learning Store — Summary"))

    # Investigation model table
    inv_rows = models.get("investigate", [])
    if inv_rows:
        inv_table = Table(title="Investigator Agent — Model Performance")
        inv_table.add_column("Model", style="cyan")
        inv_table.add_column("Total", style="white")
        inv_table.add_column("Confirmed", style="green")
        inv_table.add_column("Confirm Rate", style="yellow")
        inv_table.add_column("Cost (USD)", style="magenta")

        for row in inv_rows:
            inv_table.add_row(
                row.get("model", "N/A"),
                str(row.get("total", 0)),
                str(row.get("confirmed", 0)),
                f"{row.get('confirm_rate', 0) * 100:.1f}%",
                f"${row.get('cost_usd', 0):.4f}"
            )
        console.print(inv_table)

    # PoV model table
    pov_rows = models.get("pov", [])
    if pov_rows:
        pov_table = Table(title="PoV Generator Agent — Model Performance")
        pov_table.add_column("Model", style="cyan")
        pov_table.add_column("Total", style="white")
        pov_table.add_column("Confirmed", style="green")
        pov_table.add_column("Success Rate", style="yellow")
        pov_table.add_column("Cost (USD)", style="magenta")

        for row in pov_rows:
            pov_table.add_row(
                row.get("model", "N/A"),
                str(row.get("total", 0)),
                str(row.get("confirmed", 0)),
                f"{row.get('success_rate', 0) * 100:.1f}%",
                f"${row.get('cost_usd', 0):.4f}"
            )
        console.print(pov_table)


# ──────────────────────────────────────────────────────────────────────────────
# metrics command
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--api-key", "-k", help="API key")
def metrics(api_key: Optional[str]):
    """Show system metrics (scan counts, durations, costs)"""

    if not api_key:
        api_key = get_api_key()

    if not api_key:
        console.print("[red]Error: API key required[/red]")
        sys.exit(1)

    response = make_api_request("GET", "/metrics", api_key)

    if not response:
        console.print("[yellow]No metrics available[/yellow]")
        return

    # Pretty-print as a panel of key/value pairs
    lines = []
    for k, v in response.items():
        if isinstance(v, float):
            lines.append(f"{k:35s}: {v:.4f}")
        else:
            lines.append(f"{k:35s}: {v}")

    console.print(Panel("\n".join(lines) if lines else "No data", title="System Metrics"))


# ──────────────────────────────────────────────────────────────────────────────
# health command
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
def health():
    """Show server health and available tool integrations"""

    url = f"{API_BASE_URL}/health"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Cannot reach server: {e}[/red]")
        sys.exit(1)

    def tick(flag: bool) -> str:
        return "[green]✓[/green]" if flag else "[red]✗[/red]"

    health_text = (
        f"Status       : [bold green]{data.get('status', 'unknown')}[/bold green]\n"
        f"Version      : {data.get('version', 'N/A')}\n"
        f"Docker       : {tick(data.get('docker_available', False))}  {'available' if data.get('docker_available') else 'not found — PoV execution disabled'}\n"
        f"CodeQL       : {tick(data.get('codeql_available', False))}  {'available' if data.get('codeql_available') else 'not found — static analysis degraded'}\n"
        f"Joern        : {tick(data.get('joern_available', False))}  {'available' if data.get('joern_available') else 'not found — graph analysis disabled'}"
    )
    console.print(Panel(health_text, title="AutoPoV Agent Server Health"))


# ──────────────────────────────────────────────────────────────────────────────
# report command
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("scan_id")
@click.option("--format", "-f", type=click.Choice(["json", "pdf"]), default="json", help="Report format")
@click.option("--api-key", "-k", help="API key")
def report(scan_id: str, format: str, api_key: Optional[str]):
    """Download a scan report (JSON or PDF)"""

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


# ──────────────────────────────────────────────────────────────────────────────
# keys command group
# ──────────────────────────────────────────────────────────────────────────────

@cli.group()
def keys():
    """API key management (admin commands)"""
    pass


@keys.command("generate")
@click.option("--admin-key", "-a", help="Admin API key")
@click.option("--name", "-n", default="cli", help="Key name")
def generate_key(admin_key: Optional[str], name: str):
    """Generate a new API key (admin only)"""

    if not admin_key:
        admin_key = os.getenv("AUTOPOV_ADMIN_KEY")

    if not admin_key:
        console.print("[red]Error: Admin key required. Set AUTOPOV_ADMIN_KEY or use --admin-key[/red]")
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
            "This key has been saved to [bold]~/.autopov/config.json[/bold]",
            title="API Key Generated"
        ))

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@keys.command("list")
@click.option("--admin-key", "-a", help="Admin API key")
def list_keys(admin_key: Optional[str]):
    """List all API keys (admin only)"""

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
        table.add_column("Last Used", style="blue")
        table.add_column("Active", style="magenta")

        for key in data.get("keys", []):
            table.add_row(
                key.get("key_id", "N/A")[:8] + "...",
                key.get("name", "N/A"),
                (key.get("created_at") or "N/A")[:10],
                (key.get("last_used") or "never")[:10],
                "[green]Yes[/green]" if key.get("is_active") else "[red]No[/red]"
            )

        console.print(table)

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@keys.command("revoke")
@click.argument("key_id")
@click.option("--admin-key", "-a", help="Admin API key")
@click.confirmation_option(prompt="Are you sure you want to revoke this key?")
def revoke_key(key_id: str, admin_key: Optional[str]):
    """Revoke an API key by its ID (admin only)"""

    if not admin_key:
        admin_key = os.getenv("AUTOPOV_ADMIN_KEY")

    if not admin_key:
        console.print("[red]Error: Admin key required[/red]")
        sys.exit(1)

    url = f"{API_BASE_URL}/keys/{key_id}"
    headers = {"Authorization": f"Bearer {admin_key}"}

    try:
        response = requests.delete(url, headers=headers)
        response.raise_for_status()
        console.print(f"[green]Key {key_id} revoked successfully[/green]")

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# admin command group
# ──────────────────────────────────────────────────────────────────────────────

@cli.group()
def admin():
    """Admin-only management commands"""
    pass


@admin.command("cleanup")
@click.option("--admin-key", "-a", help="Admin API key")
@click.option("--max-age-days", default=30, help="Remove results older than N days (default: 30)")
@click.option("--max-results", default=500, help="Keep only the N most recent results (default: 500)")
@click.confirmation_option(prompt="This will permanently delete old scan result files. Continue?")
def admin_cleanup(admin_key: Optional[str], max_age_days: int, max_results: int):
    """Clean up old scan result files on the server (admin only)"""

    if not admin_key:
        admin_key = os.getenv("AUTOPOV_ADMIN_KEY")

    if not admin_key:
        console.print("[red]Error: Admin key required. Set AUTOPOV_ADMIN_KEY or use --admin-key[/red]")
        sys.exit(1)

    url = f"{API_BASE_URL}/admin/cleanup"
    headers = {"Authorization": f"Bearer {admin_key}"}

    try:
        response = requests.post(
            url,
            headers=headers,
            params={"max_age_days": max_age_days, "max_results": max_results}
        )
        response.raise_for_status()
        data = response.json()

        console.print(Panel(
            f"Files removed : [yellow]{data.get('files_removed', 0)}[/yellow]\n"
            f"Space freed   : [yellow]{data.get('bytes_freed', 0) / 1024:.1f} KB[/yellow]\n"
            f"Message       : {data.get('message', '')}",
            title="Cleanup Complete"
        ))

    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# config command
# ──────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--api-key", "-k", help="API key (shows server-side config too)")
def config(api_key: Optional[str]):
    """Show client and server configuration"""

    stored_key = api_key or get_api_key()

    config_text = (
        f"API URL    : {API_BASE_URL}\n"
        f"API Key    : {'*' * 10 if stored_key else '[red]Not set[/red]'}\n"
        f"Config file: ~/.autopov/config.json\n"
        f"\n"
        f"[dim]Webhook endpoints:[/dim]\n"
        f"  GitHub : {API_BASE_URL.replace('/api', '')}/api/webhook/github\n"
        f"  GitLab : {API_BASE_URL.replace('/api', '')}/api/webhook/gitlab"
    )
    console.print(Panel(config_text, title="AutoPoV Configuration"))

    # If we have a key, also show server config
    if stored_key:
        try:
            srv = make_api_request("GET", "/config", stored_key)
            srv_text = (
                f"App version  : {srv.get('app_version', 'N/A')}\n"
                f"Routing mode : {srv.get('routing_mode', 'N/A')}\n"
                f"Model mode   : {srv.get('model_mode', 'N/A')}\n"
                f"Auto model   : {srv.get('auto_router_model', 'N/A')}\n"
                f"CodeQL       : {'available' if srv.get('codeql_available') else 'not found'}\n"
                f"Docker       : {'available' if srv.get('docker_available') else 'not found'}\n"
                f"CWEs         : {len(srv.get('supported_cwes', []))} supported"
            )
            console.print(Panel(srv_text, title="Server Configuration"))
        except Exception:
            pass  # Don't fail config display if server is unreachable


# ──────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ──────────────────────────────────────────────────────────────────────────────

def _monitor_and_display(scan_id: str, api_key: str, output: str):
    """Monitor a scan in real-time then display results"""
    console.print("[blue]Waiting for scan to complete...[/blue]")
    console.print("[dim]Press Ctrl+C to stop monitoring (scan will continue)[/dim]\n")

    last_logs_count = 0
    last_findings_count = 0
    shown_findings = set()

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
                    safe_log = log.replace("[", "\\[").replace("]", "\\]")
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
                        cwe_type = finding.get('cwe_type', 'Unknown')
                        file = finding.get('filepath', 'Unknown')
                        line = finding.get('line_number', 0)
                        confidence = finding.get('confidence', 0)

                        if confidence >= 0.8:
                            console.print(f"[red]🔴 HIGH: {cwe_type} at {file}:{line} ({confidence:.0%})[/red]")
                        elif confidence >= 0.5:
                            console.print(f"[yellow]🟡 MEDIUM: {cwe_type} at {file}:{line} ({confidence:.0%})[/yellow]")
                        else:
                            console.print(f"[blue]🔵 LOW: {cwe_type} at {file}:{line} ({confidence:.0%})[/blue]")

                console.print(f"\n[dim]Total findings so far: {len(findings)}[/dim]\n")
                last_findings_count = len(findings)

            if status in ["failed", "completed", "cancelled"]:
                console.print(f"\n[bold]Status: {status.upper()}[/bold]")

            if status == "cancelled":
                console.print("[yellow]Scan was cancelled.[/yellow]")
                return

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
        console.print(f"[dim]Use: autopov results {scan_id}[/dim]")
        return

    # Display final results
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

        summary_text = (
            f"Scan ID  : {result['scan_id']}\n"
            f"Status   : {result['status']}\n"
            f"Model    : {result['model_name']}\n"
            f"Duration : {result['duration_s']:.2f}s\n"
            f"Cost     : ${result['total_cost_usd']:.4f}\n"
            f"\n"
            f"Total Findings : {result['total_findings']}\n"
            f"Confirmed      : {result['confirmed_vulns']}\n"
            f"False Positives: {result['false_positives']}\n"
            f"Failed         : {result['failed']}"
        )
        console.print(Panel(summary_text, title="Scan Summary"))

        if result.get("findings"):
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

            error_findings = [
                f for f in result["findings"]
                if f.get("final_status") != "confirmed" and f.get("llm_verdict") == "ERROR"
            ]
            if error_findings:
                console.print("\n[yellow]Findings with Investigation Errors:[/yellow]")
                error_table = Table()
                error_table.add_column("CWE", style="cyan")
                error_table.add_column("File", style="green")
                error_table.add_column("Line", style="yellow")
                error_table.add_column("Error", style="red")

                for finding in error_findings:
                    error_msg = (finding.get("llm_explanation", "Unknown error") or "")[:50] + "..."
                    error_table.add_row(
                        finding.get("cwe_type", "N/A"),
                        finding.get("filepath", "N/A"),
                        str(finding.get("line_number", "N/A")),
                        error_msg
                    )

                console.print(error_table)

            pending_findings = [
                f for f in result["findings"]
                if f.get("final_status") == "pending" and f.get("llm_verdict") != "ERROR"
            ]
            if pending_findings:
                console.print(f"\n[dim]Pending/Skipped Findings: {len(pending_findings)}[/dim]")
                for finding in pending_findings[:5]:
                    verdict = finding.get("llm_verdict", "UNKNOWN")
                    confidence = finding.get("confidence", 0)
                    console.print(
                        f"  [dim]• {finding.get('cwe_type')} at "
                        f"{finding.get('filepath')}:{finding.get('line_number')} "
                        f"— Verdict: {verdict} ({confidence:.2f})[/dim]"
                    )
                if len(pending_findings) > 5:
                    console.print(f"  [dim]... and {len(pending_findings) - 5} more[/dim]")

    elif output == "pdf":
        url = f"{API_BASE_URL}/report/{scan_id}?format=pdf"
        headers = {"Authorization": f"Bearer {api_key}"}

        response = requests.get(url, headers=headers)
        response.raise_for_status()

        pdf_path = f"{scan_id}_report.pdf"
        with open(pdf_path, "wb") as f:
            f.write(response.content)

        console.print(f"[green]PDF report saved: {pdf_path}[/green]")


if __name__ == "__main__":
    cli()
