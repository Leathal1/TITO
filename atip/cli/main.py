"""
ATIP Command Line Interface

The interface through which analysts command the intelligence organism.
"""

import sys
import logging
from pathlib import Path
from typing import Optional
import click

from atip.config.config import Config, create_default_config
from atip.collectors.cve.nvd_collector import NVDCollector
from atip.collectors.osint.osint_collector import OSINTCollector
from atip.core.pipeline.processor import ThreatPipeline
from atip.dissemination.reports.markdown_report import MarkdownReportGenerator


def setup_logging(config: Config) -> None:
    """Setup logging configuration"""
    log_level = config.get("logging.level", "INFO")
    log_format = config.get("logging.format")
    log_file = config.get("logging.file")

    logging.basicConfig(
        level=getattr(logging, log_level),
        format=log_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
            *(
                [logging.FileHandler(log_file)]
                if log_file
                else []
            ),
        ],
    )


@click.group()
@click.option("--config", "-c", help="Path to configuration file")
@click.pass_context
def cli(ctx, config):
    """
    ATIP - Advanced Threat Intelligence Platform

    An intelligence organism that transforms chaos into actionable clarity.
    """
    ctx.ensure_object(dict)
    ctx.obj["config"] = Config(config)
    setup_logging(ctx.obj["config"])


@cli.command()
@click.option("--output", "-o", default="config.yaml", help="Output path for config file")
def init_config(output):
    """Create a default configuration file"""
    try:
        create_default_config(output)
        click.echo(f"✓ Created configuration file at {output}")
        click.echo("  Edit this file to customize ATIP settings")
    except Exception as e:
        click.echo(f"✗ Failed to create config: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--all", "-a", "collect_all", is_flag=True, help="Run all collectors")
@click.option("--nvd", is_flag=True, help="Run NVD collector")
@click.option("--osint", is_flag=True, help="Run OSINT collector")
@click.option("--output", "-o", help="Output file for collected threats (JSON)")
@click.pass_context
def collect(ctx, collect_all, nvd, osint, output):
    """
    Collect threat intelligence from sources

    Examples:
        atip collect --all              # Run all collectors
        atip collect --nvd              # Run only NVD collector
        atip collect --nvd --osint      # Run specific collectors
    """
    config = ctx.obj["config"]

    collectors = []

    if collect_all or nvd:
        if config.get("collectors.nvd.enabled", True):
            collectors.append(NVDCollector(config.get("collectors.nvd")))
            click.echo("→ NVD collector enabled")

    if collect_all or osint:
        if config.get("collectors.osint.enabled", True):
            collectors.append(OSINTCollector(config.get("collectors.osint")))
            click.echo("→ OSINT collector enabled")

    if not collectors:
        click.echo("✗ No collectors enabled. Use --all, --nvd, or --osint", err=True)
        sys.exit(1)

    # Run collectors
    all_threats = []
    click.echo("")
    click.echo("Starting collection...")
    click.echo("")

    for collector in collectors:
        try:
            click.echo(f"Running {collector.source_name} collector...")
            threats = collector.collect()
            all_threats.extend(threats)
            click.echo(f"  ✓ Collected {len(threats)} threats from {collector.source_name}")
        except Exception as e:
            click.echo(f"  ✗ {collector.source_name} failed: {e}", err=True)

    click.echo("")
    click.echo(f"Total raw threats collected: {len(all_threats)}")

    # Process through pipeline
    click.echo("")
    click.echo("Processing threats through pipeline...")
    pipeline = ThreatPipeline(config.get("pipeline"))
    processed_threats = pipeline.process(all_threats)

    click.echo(f"  ✓ Pipeline complete: {len(processed_threats)} threats remain")
    click.echo("")

    # Show top threats
    if processed_threats:
        click.echo("Top 5 threats by priority:")
        for i, threat in enumerate(processed_threats[:5], 1):
            stride = f" [{threat.stride_profile}]" if threat.stride_profile else ""
            click.echo(
                f"  {i}. [{threat.severity.value.upper()}]{stride} "
                f"{threat.title[:80]} (priority: {threat.priority_score:.2f})"
            )
        click.echo("")

    # Save to file if requested
    if output:
        import json

        with open(output, "w") as f:
            json.dump([t.to_dict() for t in processed_threats], f, indent=2)
        click.echo(f"✓ Saved threats to {output}")

    click.echo("")
    click.echo("Collection complete.")


@cli.command()
@click.option("--format", "-f", type=click.Choice(["markdown", "json", "html"]), default="markdown")
@click.option("--output", "-o", help="Output file path")
@click.option("--input", "-i", help="Input file (JSON threats)")
@click.pass_context
def report(ctx, format, output, input):
    """
    Generate threat intelligence report

    Examples:
        atip report                          # Generate markdown report
        atip report -f json -o report.json   # Generate JSON report
        atip report -i threats.json          # Generate from saved threats
    """
    config = ctx.obj["config"]

    # Load threats
    threats = []
    if input:
        import json

        click.echo(f"Loading threats from {input}...")
        with open(input, "r") as f:
            threat_data = json.load(f)
            # Would need to reconstruct Threat objects here
            click.echo(f"Loaded {len(threat_data)} threats")
    else:
        # Run collection
        click.echo("Collecting fresh threat data...")
        # Run collectors (simplified)
        nvd_collector = NVDCollector(config.get("collectors.nvd"))
        threats = nvd_collector.collect()

        # Process
        pipeline = ThreatPipeline(config.get("pipeline"))
        threats = pipeline.process(threats)

    if not threats:
        click.echo("✗ No threats to report", err=True)
        sys.exit(1)

    # Generate report
    click.echo("")
    click.echo(f"Generating {format} report...")

    if format == "markdown":
        generator = MarkdownReportGenerator(config.get("reports.output_dir", "reports"))
        report_path = generator.generate(threats, output)
        click.echo(f"✓ Report generated: {report_path}")

    elif format == "json":
        import json

        output_path = output or "report.json"
        with open(output_path, "w") as f:
            json.dump([t.to_dict() for t in threats], f, indent=2)
        click.echo(f"✓ Report generated: {output_path}")

    else:
        click.echo(f"✗ Format '{format}' not yet implemented", err=True)
        sys.exit(1)


@cli.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8080, type=int, help="Port to bind to")
@click.pass_context
def serve(ctx, host, port):
    """
    Start the ATIP API server

    The API provides programmatic access to threat intelligence.
    """
    config = ctx.obj["config"]

    # Override with CLI args
    host = host or config.get("api.host", "0.0.0.0")
    port = port or config.get("api.port", 8080)

    click.echo(f"Starting ATIP API server on {host}:{port}")
    click.echo("")
    click.echo("API endpoints:")
    click.echo("  GET  /api/threats              - List threats")
    click.echo("  GET  /api/threats/{id}         - Get threat details")
    click.echo("  GET  /api/stride               - STRIDE-LM categories")
    click.echo("  POST /api/collect              - Trigger collection")
    click.echo("")
    click.echo("Press Ctrl+C to stop")
    click.echo("")

    # Placeholder - real implementation would start FastAPI/Flask server
    click.echo("✗ API server not yet fully implemented", err=True)
    click.echo("  (This is a demonstration of the architecture)")


@cli.command()
@click.pass_context
def status(ctx):
    """Show ATIP system status"""
    config = ctx.obj["config"]

    click.echo("ATIP System Status")
    click.echo("=" * 50)
    click.echo("")

    # Configuration
    click.echo("Configuration:")
    click.echo(f"  Config file: {config.config_path or 'None (using defaults)'}")
    click.echo("")

    # Collectors
    click.echo("Collectors:")
    click.echo(f"  NVD:   {'✓ Enabled' if config.get('collectors.nvd.enabled') else '✗ Disabled'}")
    click.echo(f"  OSINT: {'✓ Enabled' if config.get('collectors.osint.enabled') else '✗ Disabled'}")
    click.echo("")

    # Pipeline
    click.echo("Pipeline:")
    click.echo(f"  Min Priority: {config.get('pipeline.min_priority', 0.2)}")
    click.echo(f"  Max Age: {config.get('pipeline.max_age_days', 90)} days")
    click.echo("")

    # API
    click.echo("API:")
    click.echo(f"  Status: {'✓ Enabled' if config.get('api.enabled') else '✗ Disabled'}")
    click.echo(f"  Port: {config.get('api.port', 8080)}")
    click.echo("")


def main():
    """Entry point"""
    cli(obj={})


if __name__ == "__main__":
    main()
