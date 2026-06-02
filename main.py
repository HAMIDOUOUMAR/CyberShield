"""CyberShield

Programme principal qui demande un chemin et affiche le SHA-256 de chaque fichier trouvé.
"""
from pathlib import Path
import argparse

from scanner.hash_engine import calculate_sha256
from scanner.file_scanner import scan_directory


def main() -> None:
    """Entrypoint for CyberShield.

    The program asks the user for a path (or accepts it as a positional
    argument) and prints the SHA-256 digest for each file found.
    """
    parser = argparse.ArgumentParser(description="CyberShield - affiche le SHA-256 des fichiers d'un chemin.")
    parser.add_argument("path", nargs="?", help="Chemin du fichier ou dossier à scanner")
    args = parser.parse_args()

    if args.path:
        target = args.path
    else:
        target = input("Entrez le chemin du fichier ou dossier à scanner : ").strip()

    try:
        for file_path in scan_directory(target):
            try:
                digest = calculate_sha256(file_path)
                print(f"{file_path}  {digest}")
            except Exception as e:
                print(f"Erreur lors du hachage de {file_path}: {e}")
    except FileNotFoundError:
        print(f"Le chemin '{target}' n'existe pas.")


if __name__ == "__main__":
    main()
