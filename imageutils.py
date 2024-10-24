# imageutils.py

from PIL import Image
import numpy as np
import struct

def image_to_bytes(image_path):
    """
    Read an image file and return its byte array representation.
    """
    img = Image.open(image_path)
    if img.mode not in ('RGB', 'L'):
        img = img.convert('RGB')
    img_array = np.array(img, dtype=np.uint8)
    return img_array, img

def bytes_to_image(image_bytes, image_mode):
    """
    Convert a numpy array of bytes back to an image.
    """
    img = Image.fromarray(image_bytes, mode=image_mode)
    return img

def hide_message(image_bytes, message_bytes):
    """
    Hide a message inside an image using LSB steganography.
    """
    flat_image = image_bytes.flatten()
    # Prepend message with its length (4 bytes)
    message_length = len(message_bytes)
    length_bytes = struct.pack('>I', message_length)  # 4 bytes, big-endian
    full_message = length_bytes + message_bytes
    bits = ''.join(format(byte, '08b') for byte in full_message)
    if len(bits) > len(flat_image):
        raise ValueError("Message is too large to hide in the image.")

    # Convert bits to a NumPy array
    bits_array = np.array(list(bits), dtype=np.uint8)
    # Zero out the least significant bit of the pixels
    flat_image[:len(bits_array)] &= 0b11111110
    # Set the least significant bit to the bits of the message
    flat_image[:len(bits_array)] |= bits_array

    modified_image_bytes = flat_image.reshape(image_bytes.shape)
    return modified_image_bytes

def extract_message(image_bytes):
    """
    Extract a hidden message from an image.
    """
    flat_image = image_bytes.flatten()
    # Extract the least significant bits
    bits_array = flat_image & 1
    # Read the first 32 bits to get the message length
    length_bits = bits_array[:32]
    length_bits_str = ''.join(map(str, length_bits))
    message_length = int(length_bits_str, 2)
    total_bits = message_length * 8
    if 32 + total_bits > len(bits_array):
        raise ValueError("No hidden message found or message length is invalid.")
    message_bits = bits_array[32:32 + total_bits]
    bits_str = ''.join(map(str, message_bits))
    message_bytes = int(bits_str, 2).to_bytes(message_length, byteorder='big')
    return message_bytes
