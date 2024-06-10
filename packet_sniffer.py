import argparse
from scapy.all import sniff
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

def packet_callback(packet):
    if packet.haslayer('IP'):
        source_ip = packet[0][1].src
        destination_ip = packet[0][1].dst
        protocol = packet[0][1].proto

        table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        table.add_column("Field", style="dim", width=12)
        table.add_column("Value")

        table.add_row("Source IP", source_ip)
        table.add_row("Destination IP", destination_ip)
        table.add_row("Protocol", str(protocol))

        console.print(Panel.fit(table, title="[bold blue]Packet Info[/bold blue]", border_style="blue"))

        if packet.haslayer('Raw'):
            payload = packet['Raw'].load
            console.print(Panel.fit(f"[bold cyan]Payload:[/bold cyan] {payload}", border_style="cyan"))

def main(interface):
    console.print(Panel.fit(f"[bold green]Starting packet capture on {interface}...[/bold green]", border_style="green"))
    sniff(prn=packet_callback, iface=interface, store=0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PacketProbe - A stylish network packet analyzer tool")
    parser.add_argument("-i", "--interface", type=str, required=True, help="Network interface to sniff packets on")
    args = parser.parse_args()

    try:
        main(args.interface)
    except KeyboardInterrupt:
        console.print(Panel.fit("[bold red]Packet capture stopped by user.[/bold red]", border_style="red"))
    except PermissionError:
        console.print(Panel.fit("[bold red]Permission denied: Run the script with sudo.[/bold red]", border_style="red"))
