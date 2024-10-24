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
    verify_signature,
)
from imageutils import (
    image_to_bytes,
    bytes_to_image,
    hide_message,
    extract_message,
)
import os
from rich import print
from rich.prompt import Prompt
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

@click.group()
def cli():
    pass

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

    # Select recipient's key
    console.print("[bold cyan]Select recipient's key:[/]")
    console.print(table)
    choice = Prompt.ask("[bold cyan]Enter the number of the recipient's key[/]", default="1")
    try:
        choice = int(choice)
        if choice < 1 or choice > len(key_dirs):
            raise ValueError()
        recipient_key_name = key_dirs[choice - 1]
    except ValueError:
        console.print("[red]Invalid choice.[/]")
        return

    # Load keys
    signing_key = load_signing_key(my_key_name)
    recipient_public_key = load_public_key(recipient_key_name)

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
    console.print(f"[green]Message hidden successfully in [bold]{output_image}[/][/]")
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

    # Select sender's key
    console.print("[bold cyan]Select sender's key:[/]")
    console.print(table)
    choice = Prompt.ask("[bold cyan]Enter the number of the sender's key[/]", default="1")
    try:
        choice = int(choice)
        if choice < 1 or choice > len(key_dirs):
            raise ValueError()
        sender_key_name = key_dirs[choice - 1]
    except ValueError:
        console.print("[red]Invalid choice.[/]")
        return

    # Load keys
    private_key = load_private_key(my_key_name)
    sender_verify_key = load_verify_key(sender_key_name)

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

