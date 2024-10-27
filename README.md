
# Pixeon
Conceal your messages within images. Communicate securely and anonymously.

## Introduction

Pixeon a proof-of-concept private messaging tool that allows you to hide encrypted messages within images (memes, photos, screenshots). It’s like sending a secret postcard—only the intended recipient can read the hidden message, while to others, it’s just an ordinary picture.

By leveraging steganography, end-to-end encryption, and the NYM mixnet, ImageWhisper ensures your communications remain confidential and anonymous.

### Features

	•	Steganography: Embed messages within images without altering their appearance.
	•	End-to-End Encryption: Messages are encrypted with the recipient’s RSA public key.
	•	Digital Signatures: Sign messages with your Ed25519 private key for authenticity.
	•	NYM Mixnet Integration: Send and receive messages anonymously over the NYM mixnet.
	•	Public Key Retrieval: Fetch recipient’s public keys from GitHub or other sources.
	•	Error Correction: Robust message embedding that can survive image compression (e.g., on social media platforms).
	•	User-Friendly Interface: Simple steps to create, send, and receive hidden messages.

### How It Works

	1.	Compose Your Message:
	•	Write a message up to 250 words.
	•	Select an image to use as the carrier.
	2.	Encrypt and Embed:
	•	The message is encrypted using the recipient’s RSA public key.
	•	It is then signed with your Ed25519 private key.
	•	The signed, encrypted message is embedded into the image using steganography with error correction.
	3.	Send the Image:
	•	Send the image via the NYM mixnet for anonymity.
	•	Alternatively, post it on social media or any public platform.
	4.	Recipient Receives the Image:
	•	The recipient obtains the image and uses ImageWhisper to extract the hidden message.
	•	They verify the signature and decrypt the message using their private keys.

## Getting Started

### Prerequisites

	•	Python 3.10+
	•	Dependencies: `pip install -r requirements.txt`

### Installation
- set up some `venv`, you know ... 


1.	Clone the Repository:

```
git clone https://github.com/gyrusdentatus/pixeon-cli.git
cd pixeon-cli
```
2.	Install Dependencies:

```
pip install -r requirements.txt
```


## Usage

### Generate Your Keypair

```
./pixeon.py generate-keys
```
#### Hide a Message

```
./pixeon.py hide image.png
```

	•	Follow the prompts to select your key and the recipient’s public key.
	•	Enter your message.
	•	The output image (hidden_image.png) contains the hidden message.

#### Reveal a Message

```
./pixeon.py reveal hidden_image.png
```

	•	Follow the prompts to select your private key and the sender’s public key.
	•	If successful, the hidden message will be displayed.

## Technical Details

	•	Encryption: RSA encryption ensures only the recipient can decrypt the message.
	•	Signatures: Ed25519 digital signatures verify the sender’s identity.
	•	Steganography: LSB (Least Significant Bit) technique with error correction codes like Reed-Solomon to withstand image compression.
	•	Anonymity with NYM: Integration with the NYM mixnet to send messages anonymously.

## Contributing

We welcome contributions! Please read our Contributing Guidelines to get started.

### License

This project is licensed under the IDGAF License.

### Disclaimer

Pixeon is intended for lawful use only. The developers are not responsible for any misuse of this tool.

