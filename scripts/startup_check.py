import sys
import shutil
import importlib.util
from pathlib import Path
from rich.console import Console
from rich import print
import os

console = Console()

REQUIRED_MODULES = ["rich"]
REQUIRED_DIRS = ["modules", "core", "tools"]
EXTERNAL_TOOLS = {
    "BloodyAD": ["bloodyAD"],
    "Certipy": ["certipy-ad"]
}

def check_python_version():
    print("[bold cyan]🧪 Checking Python version...[/bold cyan]")
    if sys.version_info < (3, 9):
        console.print("[bold red]❌ Python 3.9 or higher is required.[/bold red]")
        sys.exit(1)
    console.print("[green]✔ Python version is OK[/green]")

def check_python_modules():
    print("[bold cyan]🧪 Checking Python modules...[/bold cyan]")
    for mod in REQUIRED_MODULES:
        if importlib.util.find_spec(mod) is None:
            console.print(f"[bold red]❌ Missing Python module:[/bold red] {mod}")
            sys.exit(1)
    console.print("[green]✔ All required Python modules are installed[/green]")

def check_impacket_installed():
    print("[bold cyan]🧪 Checking for Impacket tools...[/bold cyan]")
    impacket_found = False
    for path in os.environ.get("PATH", "").split(os.pathsep):
        try:
            for file in os.listdir(path):
                if file.startswith("impacket-"):
                    impacket_found = True
                    break
            if impacket_found:
                break
        except FileNotFoundError:
            continue

    if impacket_found:
        console.print("[green]✔ Impacket tools are installed[/green]")
    else:
        console.print("[bold red]❌ Impacket tools not found in PATH[/bold red]")

def check_external_tools():
    print("[bold cyan]🧪 Checking other external tools...[/bold cyan]")
    for group, tools in EXTERNAL_TOOLS.items():
        found = all(shutil.which(tool) for tool in tools)
        if found:
            console.print(f"[green]✔ {group} tools are installed[/green]")
        else:
            console.print(f"[bold red]❌ {group} tools are missing[/bold red]")

def check_structure():
    print("[bold cyan]🧪 Checking project structure...[/bold cyan]")
    missing = []
    for d in REQUIRED_DIRS:
        if not Path(d).is_dir():
            missing.append(d)
    if missing:
        console.print(f"[bold red]❌ Missing required directories:[/bold red] {', '.join(missing)}")
        sys.exit(1)
    console.print("[green]✔ Project directory structure is valid[/green]")

def run_checks():
    print("[bold cyan]🔍 Running BaldHead startup checks...[/bold cyan]")
    check_python_version()
    check_python_modules()
    check_impacket_installed()
    check_external_tools()
    check_structure()
    console.print("[bold green]✅ All checks passed. Launching BaldHead...[/bold green]\n")

if __name__ == "__main__":
    run_checks()

