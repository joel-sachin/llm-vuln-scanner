import os
import git
import typer
from typing_extensions import Annotated
from dotenv import load_dotenv
from typing import Optional

# Import our new config loader
from utils import config_loader
from scanner import dependency_scanner, code_scanner
from utils import reporting

app = typer.Typer(add_completion=False, help="An LLM-based tool for Vulnerability Detection in Source Code.", rich_markup_mode="rich")

# Load configuration at the start
config = config_loader.load_config()

@app.command()
def scan(
    path: Annotated[str, typer.Argument(help="URL of the Git repository or local path to the project.")],
    output_file: Annotated[Optional[str], typer.Option("--output", "-o", help="Save the report to a file.")] = None,
    format: Annotated[str, typer.Option("--format", help="Format of the output file ('json' or 'html').")] = "json",
    no_dependency_scan: Annotated[bool, typer.Option("--no-deps", help="Skip the dependency vulnerability scan.")] = False,
    no_code_scan: Annotated[bool, typer.Option("--no-code", help="Skip the LLM-based source code scan.")] = False,
    # The default value for the LLM now comes from our config file!
    llm_provider: Annotated[str, typer.Option("--llm", help="Choose the LLM provider ('gemini' or 'openai').")] = config.get('default_llm_provider', 'gemini')
):
    """Scans a software repository for vulnerabilities."""
    load_dotenv()
    
    # ... (Repository Cloning logic remains unchanged)
    if path.startswith("http://") or path.startswith("https://"):
        repo_url = path
        local_repo_path = os.path.join("repos", os.path.basename(repo_url))
        if os.path.exists(local_repo_path): print(f"[*] Repository already exists locally at: {local_repo_path}")
        else:
            print(f"[*] Cloning repository from {repo_url}...")
            os.makedirs("repos", exist_ok=True)
            try:
                git.Repo.clone_from(repo_url, local_repo_path)
                print(f"[*] Successfully cloned to {local_repo_path}")
            except git.exc.GitCommandError as e:
                typer.echo(f"[!] Error cloning repository: {e}", err=True); raise typer.Exit(code=1)
        repo_to_analyze = local_repo_path
    else:
        if not os.path.isdir(path):
            typer.echo(f"[!] Error: Local path '{path}' not found or is not a directory.", err=True); raise typer.Exit(code=1)
        repo_to_analyze = path
        
    print(f"[*] Starting analysis for repository: {repo_to_analyze}")
    
    all_findings = {"dependency_vulnerabilities": [], "code_vulnerabilities": []}
    
    if not no_dependency_scan:
        print("\n[+] Running dependency scan...")
        # We can pass the config to the dependency scanner in the future if needed
        vulnerable_dependencies = dependency_scanner.scan(repo_to_analyze)
        all_findings["dependency_vulnerabilities"] = vulnerable_dependencies
    else:
        print("\n[*] Skipping dependency scan as requested.")

    if not no_code_scan:
        print(f"\n[+] Running source code vulnerability scan with [bold magenta]{llm_provider}[/bold magenta]...")
        # We now pass the loaded config to the code scanner
        code_vulnerabilities = code_scanner.scan(repo_to_analyze, llm_provider, config)
        all_findings["code_vulnerabilities"] = code_vulnerabilities
    else:
        print("\n[*] Skipping source code scan as requested.")

    if output_file:
        if format == "json": reporting.save_json_report(all_findings, output_file)
        elif format == "html": reporting.save_html_report(all_findings, output_file)
        else: typer.echo(f"[!] Error: Invalid output format '{format}'.", err=True)
    else:
        reporting.print_dependency_report(all_findings["dependency_vulnerabilities"])
        reporting.print_code_vulnerability_report(all_findings["code_vulnerabilities"])

    print("\n[*] Analysis complete.")

if __name__ == "__main__":
    app()