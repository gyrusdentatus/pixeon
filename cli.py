# cli.py

import click
from keymanagement import (
    generate_keypair,
    load_signing_key,
    load_verify_key,
    load_private_key,
    load_public_key,
    CONFIG_DIR
)
from cryptoutils import (
    encrypt_message,
    decrypt_message,
    sign_message,
)
from imageutils import (
    image_to_bytes,
    bytes_to_image,
    hide_message,
    extract_message,
)
import os
import requests  # Import requests for handling URLs
from rich import print
from rich.prompt import Prompt
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from cryptography.hazmat.primitives import serialization

console = Console()

# Define the CLI group
@click.group()
def cli():
    pass

# Functions for loading public keys from different sources
def load_public_key_from_path(filepath):
    filepath = os.path.expanduser(filepath)
    with open(filepath, 'rb') as f:
        key_data = f.read()
    public_key = serialization.load_pem_public_key(
        key_data,
        backend=None
    )
    return public_key

def load_public_key_from_data(key_data):
    key_data = key_data.encode()
    public_key = serialization.load_ssh_public_key(
        key_data,
        backend=None
    )
    return public_key

def load_public_key_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        key_data = response.content
        public_key = serialization.load_ssh_public_key(
            key_data,
            backend=None
        )
        return public_key
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Failed to download key: {e}[/]")
        raise e

def load_public_key_from_github(username):
    url = f"https://github.com/{username}.keys"
    try:
        response = requests.get(url)
        response.raise_for_status()
        keys_data = response.text.strip().split('\n')
        # Parse keys and look for an RSA key
        for key_line in keys_data:
            if key_line.startswith('ssh-rsa'):
                key_data = key_line.strip()
                public_key = serialization.load_ssh_public_key(
                    key_data.encode(),
                    backend=None
                )
                return public_key
        raise ValueError("No RSA public key found for this GitHub user.")
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Failed to fetch keys from GitHub: {e}[/]")
        raise e
    except Exception as e:
        console.print(f"[red]Error processing GitHub keys: {e}[/]")
        raise e

@cli.command()
def generate_keys():
    """
    Generate a new key pair for signing and encryption.
    """
    name = Prompt.ask("[bold cyan]Enter a name for your keypair[/]")
    generate_keypair(name)

@cli.command()
@click.argument('image_path')
def hide(image_path):
    """
    Hide a message in an image.
    """
    # Ensure config directory exists
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)
        console.print(f"[green]Created config directory at {CONFIG_DIR}[/]")

    # List available keys
    key_dirs = [d for d in os.listdir(CONFIG_DIR) if os.path.isdir(os.path.join(CONFIG_DIR, d))]
    if not key_dirs:
        console.print("[red]No keys found. Please generate keys first.[/]")
        return

    # Select your key
    console.print("[bold cyan]Select your key:[/]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Number", style="dim", width=6)
    table.add_column("Key Name", style="bold")
    for idx, key_name in enumerate(key_dirs):
        table.add_row(str(idx + 1), key_name)
    console.print(table)
    choice = Prompt.ask("[bold cyan]Enter the number of your key[/]", default="1")
    try:
        choice = int(choice)
        if choice < 1 or choice > len(key_dirs):
            raise ValueError()
        my_key_name = key_dirs[choice - 1]
    except ValueError:
        console.print("[red]Invalid choice.[/]")
        return

    # Load your signing key
    signing_key = load_signing_key(my_key_name)

    # Recipient's public key selection
    console.print("[bold cyan]Recipient's public key:[/]")
    console.print("1. Select from existing keys")
    console.print("2. Enter path to key file")
    console.print("3. Enter URL to download key")
    console.print("4. Paste key manually")
    console.print("5. Enter GitHub username")
    choice = Prompt.ask("[bold cyan]Choose an option[/]", choices=["1", "2", "3", "4", "5"], default="1")

    try:
        if choice == "1":
            # Select from existing keys
            console.print("[bold cyan]Select recipient's key:[/]")
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Number", style="dim", width=6)
            table.add_column("Key Name", style="bold")
            for idx, key_name in enumerate(key_dirs):
                table.add_row(str(idx + 1), key_name)
            console.print(table)
            recipient_choice = Prompt.ask("[bold cyan]Enter the number of the recipient's key[/]", default="1")
            recipient_choice = int(recipient_choice)
            if recipient_choice < 1 or recipient_choice > len(key_dirs):
                raise ValueError()
            recipient_key_name = key_dirs[recipient_choice - 1]
            recipient_public_key = load_public_key(recipient_key_name)
        elif choice == "2":
            # Enter path to key file
            key_path = Prompt.ask("[bold cyan]Enter the path to the recipient's public key file[/]")
            recipient_public_key = load_public_key_from_path(key_path)
        elif choice == "3":
            # Enter URL to download key
            key_url = Prompt.ask("[bold cyan]Enter the URL of the recipient's public key[/]")
            recipient_public_key = load_public_key_from_url(key_url)
        elif choice == "4":
            # Paste key manually
            key_data = Prompt.ask("[bold cyan]Paste the recipient's public key[/]")
            recipient_public_key = load_public_key_from_data(key_data)
        elif choice == "5":
            # Enter GitHub username
            github_username = Prompt.ask("[bold cyan]Enter the recipient's GitHub username[/]")
            recipient_public_key = load_public_key_from_github(github_username)
        else:
            console.print("[red]Invalid choice.[/]")
            return
    except ValueError:
        console.print("[red]ERR:Invalid choice.[/]")
        return
    except Exception as e:
        console.print(f"[red]Failed to load recipient's public key: {e}[/]")
        return

    # Prompt for the message
    message = Prompt.ask("[bold cyan]Enter the message to hide[/]")

    # Encrypt and sign the message
    encrypted_message = encrypt_message(message.encode(), recipient_public_key)
    signed_message = sign_message(encrypted_message, signing_key).signature + encrypted_message

    # Load image and hide message
    image_bytes, img = image_to_bytes(image_path)
    try:
        modified_image_bytes = hide_message(image_bytes, signed_message)
    except Exception as e:
        console.print(f"[red]Failed to hide message: {e}[/]")
        return

    # Save modified image
    output_image = f"hidden_{os.path.basename(image_path)}"
    modified_img = bytes_to_image(modified_image_bytes, img.mode)
    modified_img.save(output_image)
    console.print(f"[green]Message hidden successfully in [bold]{output_image}[/]")

@cli.command()
@click.argument('image_path')
def reveal(image_path):
    """
    Reveal a hidden message from an image.
    """
    # Ensure config directory exists
    if not os.path.exists(CONFIG_DIR):
        console.print(f"[red]No config directory found at {CONFIG_DIR}[/]")
        return

    # List available keys
    key_dirs = [d for d in os.listdir(CONFIG_DIR) if os.path.isdir(os.path.join(CONFIG_DIR, d))]
    if not key_dirs:
        console.print("[red]No keys found. Please generate keys first.[/]")
        return

    # Select your key
    console.print("[bold cyan]Select your key:[/]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Number", style="dim", width=6)
    table.add_column("Key Name", style="bold")
    for idx, key_name in enumerate(key_dirs):
        table.add_row(str(idx + 1), key_name)
    console.print(table)
    choice = Prompt.ask("[bold cyan]Enter the number of your key[/]", default="1")
    try:
        choice = int(choice)
        if choice < 1 or choice > len(key_dirs):
            raise ValueError()
        my_key_name = key_dirs[choice - 1]
    except ValueError:
        console.print("[red]Invalid choice.[/]")
        return

    # Load your private key
    private_key = load_private_key(my_key_name)

    # Sender's verify key selection
    console.print("[bold cyan]Sender's verify key:[/]")
    console.print("1. Select from existing keys")
    console.print("2. Enter path to key file")
    console.print("3. Enter URL to download key")
    console.print("4. Paste key manually")
    choice = Prompt.ask("[bold cyan]Choose an option[/]", choices=["1", "2", "3", "4"], default="1")

    try:
        if choice == "1":
            # Select from existing keys
            console.print("[bold cyan]Select sender's key:[/]")
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Number", style="dim", width=6)
            table.add_column("Key Name", style="bold")
            for idx, key_name in enumerate(key_dirs):
                table.add_row(str(idx + 1), key_name)
            console.print(table)
            sender_choice = Prompt.ask("[bold cyan]Enter the number of the sender's key[/]", default="1")
            sender_choice = int(sender_choice)
            if sender_choice < 1 or sender_choice > len(key_dirs):
                raise ValueError()
            sender_key_name = key_dirs[sender_choice - 1]
            sender_verify_key = load_verify_key(sender_key_name)
        elif choice == "2":
            # Enter path to key file
            key_path = Prompt.ask("[bold cyan]Enter the path to the sender's verify key file[/]")
            sender_verify_key = load_verify_key_from_path(key_path)
        elif choice == "3":
            # Enter URL to download key
            key_url = Prompt.ask("[bold cyan]Enter the URL of the sender's verify key[/]")
            sender_verify_key = load_verify_key_from_url(key_url)
        elif choice == "4":
            # Paste key manually
            key_data = Prompt.ask("[bold cyan]Paste the sender's verify key[/]")
            sender_verify_key = load_verify_key_from_data(key_data)
        else:
            console.print("[red]Invalid choice.[/]")
            return
    except ValueError:
        console.print("[red]Invalid choice.[/]")
        return
    except Exception as e:
        console.print(f"[red]Failed to load sender's verify key: {e}[/]")
        return

    # Load image and extract message
    image_bytes, img = image_to_bytes(image_path)
    try:
        extracted_bytes = extract_message(image_bytes)
    except Exception as e:
        console.print(f"[red]Failed to extract message: {e}[/]")
        return

    # Separate signature and encrypted message
    signature_length = 64  # Ed25519 signatures are 64 bytes
    signature = extracted_bytes[:signature_length]
    encrypted_message = extracted_bytes[signature_length:]

    # Verify signature
    try:
        sender_verify_key.verify(encrypted_message, signature)
    except Exception as e:
        console.print(f"[red]Failed to verify signature: {e}[/]")
        return

    # Decrypt message
    try:
        decrypted_message = decrypt_message(encrypted_message, private_key)
        console.print(Panel(f"[bold green]Hidden message:[/]\n{decrypted_message.decode()}"))
    except Exception as e:
        console.print(f"[red]Failed to decrypt message: {e}[/]")

# Additional functions for loading verify keys from different sources
def load_verify_key_from_path(filepath):
    filepath = os.path.expanduser(filepath)
    with open(filepath, 'rb') as f:
        key_data = f.read()
    return public.VerifyKey(key_data, encoder=encoding.Base64Encoder)

def load_verify_key_from_data(key_data):
    key_data = key_data.encode()
    return public.VerifyKey(key_data, encoder=encoding.Base64Encoder)

def load_verify_key_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        key_data = response.content
        return public.VerifyKey(key_data, encoder=encoding.Base64Encoder)
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Failed to download key: {e}[/]")
        raise e

if __name__ == '__main__':
    cli()
