"""Dataset ingestion CLI.

Usage:
    uv run python -m firmable.data.ingest
    uv run python -m firmable.data.ingest --max-records 100000
    uv run python -m firmable.data.ingest --output raw/profile.json
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click
import rich.console
import rich.progress
import structlog

from firmable.data.profiler import DatasetProfile, profile_dataset, save_profile

console = rich.console.Console()
log = structlog.get_logger()


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
    )


def _print_report(profile: DatasetProfile) -> None:
    """Print a rich-formatted summary of the profiling results."""
    stats = profile.read_stats.summary()
    identity = profile.identity.summary()
    security = profile.security.summary()

    console.print("[bold green]✅ Profile complete[/bold green]\n")

    console.print("[bold]── Read Stats ──────────────────────────────[/bold]")
    console.print(f"  Records read    : {stats['records_read']:,}")
    console.print(f"  Records valid   : {stats['records_valid']:,}")
    console.print(f"  Malformed JSON  : {stats['records_malformed_json']:,}")
    console.print(f"  Malformed schema: {stats['records_malformed_schema']:,}")
    console.print(f"  Error rate      : {stats['error_rate']:.4%}")
    console.print(f"  Bytes read      : {stats['bytes_read'] / 1024**3:.2f} GB")

    console.print("\n[bold]── Identity ────────────────────────────────[/bold]")
    console.print(f"  Unique IPs      : {identity['unique_ips']:,}")
    console.print(f"  Unique domains  : {identity['unique_domains']:,}")
    console.print(f"  Unique orgs     : {identity['unique_orgs']:,}")
    console.print(f"  Unique ASNs     : {identity['unique_asns']:,}")
    console.print(f"  Unique countries: {identity['unique_countries']:,}")
    console.print(f"  % with domain   : {identity['pct_with_domain']:.1%}")
    console.print(f"  % with org      : {identity['pct_with_org']:.1%}")
    console.print(f"  % cloud         : {identity['pct_cloud']:.1%}")
    console.print(f"  Ambiguous domains (multi-org): {identity['domains_with_multiple_orgs']:,}")

    console.print("\n[bold]── Security Signals ────────────────────────[/bold]")
    console.print(f"  % with vulns    : {security['pct_with_vulns']:.1%}")
    console.print(f"  Unique CVEs     : {security['unique_cves']:,}")
    console.print(f"  Critical CVEs   : {security['records_with_critical_cve']:,} records")
    console.print(f"  High CVEs       : {security['records_with_high_cve']:,} records")
    console.print(f"  EOL software    : {security['records_eol']:,} records")
    console.print(f"  Self-signed cert: {security['records_self_signed_cert']:,} records")
    console.print(f"  Exposed DB      : {security['records_exposed_db']:,} records")
    console.print(f"  Exposed admin   : {security['records_exposed_admin']:,} records")

    if security["top_10_ports"]:
        console.print("\n[bold]── Top Ports ───────────────────────────────[/bold]")
        for port, count in security["top_10_ports"]:
            console.print(f"  {port:>6} : {count:>8,}")

    if security["top_10_products"]:
        console.print("\n[bold]── Top Products ────────────────────────────[/bold]")
        for product, count in security["top_10_products"][:5]:
            console.print(f"  {product!r:30s} : {count:>8,}")

    if security["top_10_cves"]:
        console.print("\n[bold]── Top CVEs ────────────────────────────────[/bold]")
        for cve, count in security["top_10_cves"][:5]:
            console.print(f"  {cve!r:30s} : {count:>8,}")

    if security["cvss_distribution"]:
        dist = security["cvss_distribution"]
        console.print("\n[bold]── CVSS Distribution ───────────────────────[/bold]")
        console.print(
            f"  min={dist['min']}  p25={dist['p25']}"
            f"  p50={dist['p50']}  p75={dist['p75']}  max={dist['max']}"
        )
        console.print(
            f"  Critical (≥9.0): {dist['critical_count']:,}"
            f"  High (7-9): {dist['high_count']:,}"
            f"  Medium (4-7): {dist['medium_count']:,}"
        )


@click.command()
@click.option(
    "--dataset",
    default=None,
    envvar="DATASET_PATH",
    help="Path to the .zst dataset file (or set DATASET_PATH env var).",
)
@click.option(
    "--max-records",
    default=None,
    type=int,
    help="Limit records for sampling (None = full dataset).",
)
@click.option(
    "--output",
    default="raw/profile.json",
    show_default=True,
    help="Path to write the profile JSON.",
)
@click.option(
    "--log-level",
    default="INFO",
    show_default=True,
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
)
def ingest(
    dataset: str | None,
    max_records: int | None,
    output: str,
    log_level: str,
) -> None:
    """Stream and profile the Shodan dataset."""
    _configure_logging(log_level)

    if dataset is None:
        console.print("[red]Error:[/] --dataset or DATASET_PATH env var is required.")
        sys.exit(1)

    data_path = Path(dataset)
    if not data_path.exists():
        console.print(f"[red]Error:[/] Dataset not found: {data_path}")
        sys.exit(1)

    output_path = Path(output)
    file_size_gb = data_path.stat().st_size / (1024**3)

    console.print("\n[bold]Firmable Dataset Profiler[/bold]")
    console.print(f"  Dataset : {data_path}")
    console.print(f"  Size    : {file_size_gb:.2f} GB (compressed)")
    console.print(f"  Limit   : {max_records or 'full dataset'}")
    console.print(f"  Output  : {output_path}")
    console.print()

    profile: DatasetProfile | None = None

    with rich.progress.Progress(
        rich.progress.SpinnerColumn(),
        rich.progress.TextColumn("[progress.description]{task.description}"),
        rich.progress.BarColumn(),
        rich.progress.MofNCompleteColumn(),
        rich.progress.TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Streaming records…", total=max_records)
        profile = profile_dataset(data_path, max_records=max_records, batch_size=5000)
        progress.update(task, completed=profile.read_stats.records_valid)

    _print_report(profile)

    save_profile(profile, output_path)
    console.print(f"\n[dim]Profile saved → {output_path}[/dim]")


if __name__ == "__main__":
    ingest()
