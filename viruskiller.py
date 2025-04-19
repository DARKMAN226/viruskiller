#!/usr/bin/env python3
"""
VIRU$-KILLER - Scanner simple de ports, sous-domaines et IP
Dev: Virus-man
"""

import asyncio
import aiodns
import socket
import requests
import subprocess
import platform
import re
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel
from rich.align import Align
from rich.text import Text

console = Console()
DNS_TIMEOUT = 3
HTTP_TIMEOUT = 10

# Clés API (à garder secrètes)
VIEWDNS_API_KEY = "a51b854caf97d77d6fc9048c5680ce856088c712"
ALIENV_API_KEY = "23681f965da7a57e7c37a330fb047256b85f7152b7c016cd9c9445d3cb9f6b2f"

# Wordlist simple pour brute force sous-domaines
WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "admin", "test", "dev",
    "api", "blog", "shop", "vpn", "m", "portal", "secure", "ns1", "ns2"
]

def print_banner():
    banner = """
██╗   ██╗██╗██████╗ ██╗   ██╗███████╗   ██╗  ██╗██╗██╗     ██╗     ███████╗██████╗ 
██║   ██║██║██╔══██╗██║   ██║██╔════╝   ██║ ██╔╝██║██║     ██║     ██╔════╝██╔══██╗
██║   ██║██║██████╔╝██║   ██║███████╗   █████╔╝ ██║██║     ██║     █████╗  ██████╔╝
╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║   ██╔═██╗ ██║██║     ██║     ██╔══╝  ██╔══██╗
 ╚████╔╝ ██║██║  ██║╚██████╔╝███████║██╗██║  ██╗██║███████╗███████╗███████╗██║  ██║
  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
"""
    console.print(Align.center(banner, vertical="middle", style="bold red"))
    console.print(Align.center("[bold green]VIRU$-KILLER[/bold green]  -  Par Virus-man\n", vertical="middle"))

def is_host_online(host):
    """Ping la cible pour vérifier si elle est en ligne"""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', host]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        if result.returncode == 0:
            # Analyse de la sortie pour vérifier la connectivité
            if platform.system().lower() == 'windows':
                pattern = re.compile(r"TTL=\d+")
            else:
                pattern = re.compile(r"ttl=\d+")

            if pattern.search(result.stdout):
                return True
            else:
                return False
        else:
            return False
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        console.print(f"[red]Erreur lors du ping : {e}[/red]")
        return False


async def scan_port(host, port):
    """Teste si un port est ouvert sur l'hôte"""
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=2)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

async def scan_ports(host, ports):
    """Scan plusieurs ports en parallèle avec l'API ViewDNS"""
    open_ports = []
    if VIEWDNS_API_KEY:
        try:
            url = f"https://api.viewdns.info/portscan/?host={host}&apikey={VIEWDNS_API_KEY}&output=json"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data and data.get("result") == "Success":
                for port_data in data.get("open_ports", []):
                    port = int(port_data.get("port"))
                    console.print(f"[green][+][/green] Port {port} ouvert (ViewDNS API)")
                    open_ports.append(port)
            else:
                console.print(f"[red]Erreur lors du scan avec l'API ViewDNS. {data.get('result')}[/red]")
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Erreur de requête API ViewDNS : {e}[/red]")
        except Exception as e:
            console.print(f"[red]Erreur inattendue lors du scan avec ViewDNS : {e}[/red]")
    else:
        console.print("[red]Clé API ViewDNS non configurée. Utilisation du scan local.[/red]")
        sem = asyncio.Semaphore(100)
        async def scan(p):
            async with sem:
                if await scan_port(host, p):
                    console.print(f"[green][+][/green] Port {p} ouvert")
                    open_ports.append(p)
        tasks = [asyncio.create_task(scan(port)) for port in ports]
        await asyncio.gather(*tasks)
    return open_ports

def fetch_crtsh_subdomains(domain):
    """Récupère les sous-domaines via crt.sh"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=HTTP_TIMEOUT)
        if resp.status_code != 200:
            console.print(f"[red]Erreur crt.sh HTTP {resp.status_code}[/red]")
            return []
        subs = set()
        for entry in resp.json():
            names = entry.get('name_value', '').split('\n')
            for name in names:
                if name.endswith(domain):
                    subs.add(name.lower())
        return list(subs)
    except Exception as e:
        console.print(f"[red]Erreur crt.sh : {e}[/red]")
        return []

async def brute_force_subdomains(domain, wordlist):
    """Valide les sous-domaines issus de la wordlist"""
    resolver = aiodns.DNSResolver(timeout=DNS_TIMEOUT)
    found = set()
    sem = asyncio.Semaphore(100)

    async def check(sub):
        async with sem:
            fqdn = f"{sub}.{domain}"
            try:
                res = await resolver.gethostbyname(fqdn, socket.AF_INET)
                if res.addresses:
                    console.print(f"[green][+][/green] Résolu : {fqdn} -> {', '.join(res.addresses)}")
                    found.add(fqdn)
            except:
                pass

    tasks = [asyncio.create_task(check(sub)) for sub in wordlist]
    await asyncio.gather(*tasks)
    return found

async def get_otx_reputation(domain):
    """Récupère la réputation d'un domaine via AlienVault OTX"""
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        headers = {"X-OTX-API-KEY": ALIENV_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data
    except requests.RequestException as e:
        console.print(f"[red]Erreur API AlienVault OTX : {e}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]Erreur inattendue lors de la récupération de la réputation OTX : {e}[/red]")
        return None


async def discover_subdomains(domain):
    console.print(Panel.fit(f"[bold red]Recherche avancée de sous-domaines pour :[/bold red]\n[bold yellow]{domain}[/bold yellow]", style="bright_blue"))
    
    console.print("\n[bold cyan]Recherche via crt.sh...[/bold cyan]")
    crt_subs = fetch_crtsh_subdomains(domain)
    console.print(f"[yellow]Sous-domaines trouvés via crt.sh : {len(crt_subs)}[/yellow]\n")

    console.print("[bold cyan]Brute force DNS avec wordlist intégrée...[/bold cyan]")
    brute_subs = await brute_force_subdomains(domain, WORDLIST)
    console.print(f"[yellow]Sous-domaines trouvés via brute force : {len(brute_subs)}[/yellow]\n")

    console.print("[bold cyan]Récupération de la réputation via AlienVault OTX...[/bold cyan]")
    otx_data = await get_otx_reputation(domain)
    if otx_data:
        if otx_data.get("reputation"):
            console.print(f"[green]Réputation AlienVault OTX : {otx_data['reputation']}[/green]")
        else:
            console.print("[yellow]Aucune réputation trouvée sur AlienVault OTX.[/yellow]")
    else:
        console.print("[red]Impossible de récupérer la réputation AlienVault OTX.[/red]")

    all_subs = set(crt_subs) | brute_subs

    if all_subs:
        table = Table(title=f"Sous-domaines valides pour {domain}")
        table.add_column("Sous-domaine", style="cyan")
        for sub in sorted(all_subs):
            table.add_row(sub)
        console.print(table)
    else:
        console.print("[red]Aucun sous-domaine valide trouvé.[/red]")

async def scan_ip_ports():
    ip = Prompt.ask("Entrez l'adresse IP à scanner").strip()
    if not ip:
        console.print("[red]Adresse IP invalide.[/red]")
        return
    ports_input = Prompt.ask("Entrez les ports à scanner (ex: 22,80,443 ou 1-1024)")
    ports = parse_ports(ports_input)
    if not ports:
        console.print("[red]Aucune plage de ports valide fournie.[/red]")
        return
    console.print(f"[bold cyan]Scan des ports sur {ip}...[/bold cyan]")
    open_ports = await scan_ports(ip, ports)
    if open_ports:
        console.print(f"[green]Ports ouverts sur {ip} : {sorted(open_ports)}[/green]")
    else:
        console.print(f"[yellow]Aucun port ouvert détecté sur {ip}.[/yellow]")

def parse_ports(ports_str):
    """Parse une chaîne de ports en liste d'entiers"""
    ports = set()
    parts = ports_str.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                ports.update(range(start, end+1))
            except:
                pass
        else:
            try:
                ports.add(int(part))
            except:
                pass
    return sorted(p for p in ports if 0 < p < 65536)

async def main_menu():
    while True:
        print_banner()
        menu_content = Text()
        menu_content.append("Menu principal :\n", style="bold cyan")
        menu_content.append("1. Vérifier si un hôte est en ligne\n")
        menu_content.append("2. Scanner les ports d'un hôte\n")
        menu_content.append("3. Trouver les sous-domaines d'un domaine\n")
        menu_content.append("4. Scanner une IP pour ports ouverts\n")
        menu_content.append("5. Quitter\n")

        console.print(Panel(menu_content, title="[bold red]VIRU$-KILLER Menu[/bold red]", border_style="bright_blue"))

        choice = Prompt.ask("Choisissez une option", choices=["1","2","3","4","5"], default="1")
        
        if choice == "1":
            host = Prompt.ask("Entrez l'adresse IP ou le domaine à tester").strip()
            online = is_host_online(host)
            if online:
                console.print(f"[green]L'hôte {host} est en ligne.[/green]")
            else:
                console.print(f"[red]L'hôte {host} ne répond pas.[/red]")
            _ = Prompt.ask("Appuyez sur Entrée pour continuer")
        
        elif choice == "2":
            host = Prompt.ask("Entrez l'adresse IP ou le domaine à scanner").strip()
            ports_input = Prompt.ask("Entrez les ports à scanner (ex: 22,80,443 ou 1-1024)")
            ports = parse_ports(ports_input)
            if not ports:
                console.print("[red]Aucune plage de ports valide fournie.[/red]")
                _ = Prompt.ask("Appuyez sur Entrée pour continuer")
                continue
            console.print(f"[bold cyan]Scan des ports sur {host}...[/bold cyan]")
            open_ports = await scan_ports(host, ports)
            if open_ports:
                console.print(f"[green]Ports ouverts sur {host} : {sorted(open_ports)}[/green]")
            else:
                console.print(f"[yellow]Aucun port ouvert détecté sur {host}.[/yellow]")
            _ = Prompt.ask("Appuyez sur Entrée pour continuer")

        elif choice == "3":
            domain = Prompt.ask("Entrez le nom de domaine cible").strip()
            await discover_subdomains(domain)
            _ = Prompt.ask("Appuyez sur Entrée pour continuer")

        elif choice == "4":
            await scan_ip_ports()
            _ = Prompt.ask("Appuyez sur Entrée pour continuer")

        elif choice == "5":
            console.print("[bold yellow]Merci d'avoir utilisé VIRU$-KILLER. À bientôt ![/bold yellow]")
            break

if __name__ == "__main__":
    # Correction boucle asyncio sous Windows
    import sys
    if sys.platform.startswith("win"):
        import asyncio
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main_menu())
    except KeyboardInterrupt:
        console.print("\n[red]Interruption utilisateur. Fermeture...[/red]")
