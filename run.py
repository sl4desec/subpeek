import sys
import subprocess
import time
import json
import warnings
import os
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.align import Align

warnings.filterwarnings("ignore")

console = Console()


def print_banner():
    banner_text = r"""
 [white]
   ██████  █    ██  ▄▄▄▄    ██▓███  ▓█████ ▓█████  ██ ▄█▀
 ▒██    ▒  ██  ▓██▒▓█████▄ ▓██░  ██▒▓█   ▀ ▓█   ▀  ██▄█▒ 
 ░ ▓██▄   ▓██  ▒██░▒██▒ ▄██▓██░ ██▓▒▒███   ▒███   ▓███▄░ 
   ▒   ██▒▓▓█  ░██░▒██░█▀  ▒██▄█▓▒ ▒▒▓█  ▄ ▒▓█  ▄ ▓██ █▄ 
 ▒██████▒▒▒▒█████▓ ░▓█  ▀█▓▒██▒ ░  ░░▒████▒░▒████▒▒██▒ █▄
 ▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ░░▒▓███▀▒▒▓▒░ ░  ░░ ▒░ ░░░ ▒░ ░▒ ▒▒ ▓▒
 ░ ░▒  ░ ░░░▒░ ░ ░  ░▒░▒   ░░▒ ░     ░ ░  ░ ░ ░  ░░ ░▒ ▒░
 ░  ░  ░   ░░░ ░ ░   ░    ░ ░░         ░      ░   ░ ░░ ░ 
       ░     ░       ░  ░              ░  ░   ░   ░  ░   
                       ░                                 
[/white]"""
    console.print(Align.center(Text.from_markup(banner_text)))
    console.print(Align.center(Text("@sl4de", style="bold white")))
    console.print(Text("=" * 60, style="red dim"), justify="center")


def run_rust_core(domain):
    if getattr(sys, "frozen", False):
        base_path = sys._MEIPASS
        rust_bin = os.path.join(base_path, "subpeek_core.exe")
    else:
        rust_bin = os.path.join("target", "release", "subpeek_core.exe")

    if not os.path.exists(rust_bin):
        console.print(f"[bold red]Core binary missing: {rust_bin}[/bold red]")
        return []

    try:
        result = subprocess.run(
            [rust_bin, domain],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        if result.returncode != 0:
            return []
        return json.loads(result.stdout)
    except:
        return []


def main():
    while True:
        console.clear()
        print_banner()

        console.print(
            "[bold red][?][/bold red] [bold white]Target Domain (or 'q'):[/bold white] ",
            end="",
        )
        domain = input().strip()
        if domain.lower() in ["q", "exit"]:
            sys.exit()
        if not domain:
            continue

        console.print("")
        results = []

        with Progress(
            SpinnerColumn(style="bold red"),
            TextColumn("[bold white]{task.description}[/bold white]"),
            transient=True,
        ) as p:
            task = p.add_task("Scanning", total=None)
            p.update(task, description=f"Enumerating Subdomains for {domain}...")

            results = run_rust_core(domain)

        if results:
            console.print(
                f"\n[bold white]Found {len(results)} Alive Subdomains[/bold white]\n"
            )

            table = Table(
                show_header=True,
                header_style="bold red",
                border_style="red",
                expand=True,
            )
            table.add_column("Subdomain", style="white")
            table.add_column("IP", style="bold white", justify="center")
            table.add_column("Status", style="white", justify="center")
            table.add_column("Title", style="white")
            table.add_column("Server", style="red")

            for res in sorted(results, key=lambda x: x["subdomain"]):
                sub = res.get("subdomain", "")
                ip = res.get("ip") or "-"
                status = str(res.get("status_code")) if res.get("status_code") else "-"
                title = res.get("title") or "-"
                server = res.get("server") or "-"

                # Truncate long titles
                if len(title) > 30:
                    title = title[:27] + "..."

                table.add_row(sub, ip, status, title, server)

            console.print(table)
        else:
            console.print("[bold red]No active subdomains found.[/bold red]")

        console.print(
            "\n[bold red][?][/bold red] [bold white]Save results? (Y/N):[/bold white] ",
            end="",
        )
        save = input().strip().lower()
        if save == "y":
            try:
                import tkinter as tk
                from tkinter import filedialog

                root = tk.Tk()
                root.withdraw()
                try:
                    root.attributes("-topmost", True)
                except:
                    pass

                timestamp = int(time.time())
                default_filename = f"subpeek_{domain}_{timestamp}.json"
                file_path = filedialog.asksaveasfilename(
                    title="Save Results",
                    initialfile=default_filename,
                    defaultextension=".json",
                    filetypes=[("JSON Files", "*.json")],
                )
                root.destroy()

                if file_path:
                    with open(file_path, "w") as f:
                        json.dump(results, f, indent=4)
                    console.print(
                        f"[bold red][OK][/bold red] [bold white]File saved.[/bold white]"
                    )
                    time.sleep(1)
            except Exception as e:
                console.print(f"[bold red]Error: {e}[/bold red]")
                time.sleep(2)

        console.clear()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
