import os
import sys
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table

from devsecops_agent.config import settings
from devsecops_agent.context.extractor import ContextExtractor
from devsecops_agent.orchestrator.pipeline import OrchestrationPipeline
from devsecops_agent.schemas.pipeline import PipelineStage

app = typer.Typer(
    help="Autonomous Multi-Agent Framework for Containerized Vulnerability Exploitation and Remediation"
)
console = Console()


@app.command()
def scan(
    repo: str = typer.Option(".", help="Path to local repository or remote GitHub git URL"),
    base_branch: Optional[str] = typer.Option(None, help="Base Git branch (e.g. main)"),
    head_branch: Optional[str] = typer.Option(None, help="Head/PR Git branch (e.g. feature/pr)"),
    diff_file: Optional[str] = typer.Option(None, help="Optional path to static diff file (fallback)"),
    test_cmd: str = typer.Option("pytest", help="Regression test command to execute in sandbox"),
    driver: str = typer.Option("docker", help="Sandbox driver: docker, auto, or local"),
    provider: Optional[str] = typer.Option(None, help="LLM Provider: gemini, openai, ollama, or mock"),
    api_key: Optional[str] = typer.Option(None, help="API Key for hosted LLM provider"),
    apply_to_repo: bool = typer.Option(True, help="Apply verified patches directly to target repository"),
    create_branch: bool = typer.Option(True, help="Create a git remediation branch and commit verified patch"),
    output_report: Optional[str] = typer.Option("reports/remediation_report.md", help="Path to write output markdown report")
):
    """
    Analyzes code changes in a Pull Request, confirms vulnerabilities via dynamic exploitation,
    and synthesizes verified non-regressive patches.
    """
    console.print(
        "[bold cyan]Autonomous Multi-Agent DevSecOps Framework[/bold cyan] [green](CET Group 14)[/green]"
    )

    # 1. Handle remote Git repository URL (e.g. https://github.com/...)
    temp_clone_dir = None
    if repo.startswith("http://") or repo.startswith("https://") or repo.startswith("git@"):
        import tempfile
        import subprocess
        temp_clone_dir = tempfile.mkdtemp(prefix="devsecops_repo_")
        console.print(f"• Cloning remote repository [italic]{repo}[/italic] into sandbox workspace...")
        subprocess.run(["git", "clone", repo, temp_clone_dir], check=True)
        repo_path = Path(temp_clone_dir).resolve()
    else:
        repo_path = Path(repo).resolve()
        if not repo_path.exists():
            console.print(f"[bold red]Error:[/bold red] Repository path '{repo}' not found.")
            raise typer.Exit(code=1)

    # Configure LLM provider override if specified
    if provider:
        settings.LLM_PROVIDER = provider
    if api_key:
        if settings.LLM_PROVIDER == "gemini":
            settings.GEMINI_API_KEY = api_key
        else:
            settings.OPENAI_API_KEY = api_key
            settings.HOSTED_LLM_API_KEY = api_key

    console.print(f"• Active LLM Provider: [bold yellow]{settings.LLM_PROVIDER.upper()}[/bold yellow]")
    console.print(f"• Sandbox Driver: [bold blue]{driver.upper()}[/bold blue]")

    extractor = ContextExtractor(str(repo_path))

    # Extract Git PR diff directly from repository
    if diff_file:
        df = Path(diff_file)
        if df.exists():
            diff_text = df.read_text(encoding="utf-8")
            console.print(f"• Loaded diff from file: [italic]{diff_file}[/italic]")
        else:
            console.print(f"[bold red]Error:[/bold red] Diff file '{diff_file}' not found.")
            raise typer.Exit(code=1)
    else:
        diff_text = extractor.get_git_diff(base_branch, head_branch)
        if base_branch and head_branch:
            console.print(f"• Extracted Git PR diff: [italic]{base_branch}...{head_branch}[/italic]")
        elif base_branch:
            console.print(f"• Extracted Git diff against: [italic]{base_branch}[/italic]")
        else:
            console.print("• Extracted Git diff from repository HEAD")

    if not diff_text.strip():
        console.print("[yellow]No code changes detected in the specified Git range.[/yellow]")
        return

    candidates = extractor.extract_candidates_from_diff(diff_text)
    if not candidates:
        console.print("[yellow]No Python changes or vulnerability candidates detected in diff.[/yellow]")
        return

    console.print(f"Extracted [bold]{len(candidates)}[/bold] candidate(s) for verification.")

    orchestrator = OrchestrationPipeline(
        repo_path=str(repo_path),
        sandbox_driver=driver,
        test_command=test_cmd
    )

    pr_ref = f"{base_branch or 'main'}...{head_branch or 'HEAD'}"
    report = orchestrator.run(candidates, pr_ref=pr_ref)

    # Print summary table
    table = Table(title="Autonomous Remediation Summary")
    table.add_column("Candidate ID", style="cyan")
    table.add_column("OWASP Category", style="magenta")
    table.add_column("Exploit Confirmed", style="yellow")
    table.add_column("Remediation Status", style="green")

    for rec in report.records:
        confirmed = "YES" if (rec.exploit_report and rec.exploit_report.confirmed) else "NO"
        status_color = "green" if rec.status == PipelineStage.REMEDIATION_SUCCESS else "red"
        table.add_row(
            rec.candidate.id,
            rec.candidate.owasp_category.value,
            confirmed,
            f"[{status_color}]{rec.status.value}[/{status_color}]"
        )

    console.print(table)

    # Apply verified patches to repository and create remediation Git branch
    if apply_to_repo and report.successfully_remediated > 0:
        import subprocess
        for rec in report.records:
            if rec.status == PipelineStage.REMEDIATION_SUCCESS and rec.final_verified_patch:
                patch = rec.final_verified_patch
                console.print(f"\n[bold green]Applying verified patch for {rec.candidate.id}...[/bold green]")
                
                # 1. Write patched file contents to actual repository on disk
                for rel_path, content in patch.modified_files.items():
                    target_file_path = repo_path / rel_path
                    target_file_path.parent.mkdir(parents=True, exist_ok=True)
                    target_file_path.write_text(content, encoding="utf-8")
                    console.print(f"  • Updated file on disk: [bold cyan]{rel_path}[/bold cyan]")

                # 2. Create Git remediation branch and commit fix if inside a Git repository
                if create_branch and (repo_path / ".git").exists():
                    try:
                        branch_name = f"remediation/{rec.candidate.id.lower()}-fix"
                        subprocess.run(["git", "checkout", "-B", branch_name], cwd=str(repo_path), capture_output=True, check=True)
                        for rel_path in patch.modified_files.keys():
                            subprocess.run(["git", "add", rel_path], cwd=str(repo_path), capture_output=True, check=True)
                        commit_msg = (
                            f"fix(security): autonomous remediation for {rec.candidate.id}\n\n"
                            f"OWASP Classification: {rec.candidate.owasp_category.value}\n"
                            f"Root Cause: {patch.root_cause_analysis}\n"
                            f"Verified non-regressive by Autonomous DevSecOps Multi-Agent Framework."
                        )
                        subprocess.run(["git", "commit", "-m", commit_msg], cwd=str(repo_path), capture_output=True, check=True)
                        console.print(f"  • Created Git remediation branch: [bold green]{branch_name}[/bold green]")
                        console.print(f"  • Committed verified patch with signature to Git history.")
                    except Exception as ge:
                        console.print(f"[yellow]Notice: Could not automatically commit to Git branch: {ge}[/yellow]")

    if output_report:
        out_p = Path(output_report)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(report.summary_markdown, encoding="utf-8")
        console.print(f"[bold green]Report written to:[/bold green] {output_report}")


@app.command()
def version():
    """Display system version and configuration."""
    from devsecops_agent import __version__
    console.print(f"[bold cyan]DevSecOps Multi-Agent Version:[/bold cyan] {__version__}")


if __name__ == "__main__":
    app()
