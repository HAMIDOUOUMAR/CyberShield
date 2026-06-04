"""CyberShield command line entrypoint.

This module provides a small interactive menu for file scanning and process
monitoring features.
"""
import argparse

from monitor.process_monitor import ProcessMonitor
from monitor.process_report import save_process_report
from realtime.realtime_engine import start_realtime_monitoring
from report_engine import save_report
from scanner.file_scanner import scan_directory


def run_file_scan(path: str | None = None) -> None:
    """Scan files from a user-provided path and save the scan report."""
    target = path or input("Entrez le chemin du fichier ou dossier a scanner : ").strip()

    try:
        results = scan_directory(target)
        save_report(results)
        print("Rapport sauvegarde dans reports/report.json")
    except FileNotFoundError as error:
        print(error)


def run_process_monitoring() -> None:
    """Display active processes and save the process monitoring report."""
    monitor = ProcessMonitor()
    processes = monitor.get_active_processes()

    for process in processes:
        print(
            f"PID: {process['pid']} | "
            f"Name: {process['name']} | "
            f"CPU: {process['cpu']:.1f}% | "
            f"Memory: {process['memory']:.2f}%"
        )

    save_process_report(processes)
    print("Rapport sauvegarde dans reports/process_report.json")


def run_realtime_protection() -> None:
    """Ask for a folder and start realtime protection on it."""
    directory_path = input("Entrez le dossier a surveiller : ").strip()
    start_realtime_monitoring(directory_path)


def show_menu() -> None:
    """Display the interactive CyberShield menu."""
    while True:
        print("\nCyberShield")
        print("1 - Scan de fichiers")
        print("2 - Surveillance des processus")
        print("3 - Protection temps reel")
        print("4 - Quitter")

        choice = input("Choix : ").strip()

        if choice == "1":
            run_file_scan()
        elif choice == "2":
            run_process_monitoring()
        elif choice == "3":
            run_realtime_protection()
        elif choice == "4":
            print("Au revoir.")
            break
        else:
            print("Choix invalide.")


def main() -> None:
    """Run CyberShield from the command line."""
    parser = argparse.ArgumentParser(description="CyberShield security toolkit.")
    parser.add_argument("path", nargs="?", help="File or directory path to scan")
    args = parser.parse_args()

    # Keep direct path scanning available for quick command-line tests.
    if args.path:
        run_file_scan(args.path)
    else:
        show_menu()


if __name__ == "__main__":
    main()
