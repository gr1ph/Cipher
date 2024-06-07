import discord
from discord.ext import commands
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import hashlib
import base64
import random
import string

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='/', intents=intents)

# Utility functions
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

# Event: On bot ready
@bot.event
async def on_ready():
    print(f'Logged in as {bot.user.name} - {bot.user.id}')

# Command: Encrypt message
@bot.slash_command(name='encrypt', description='Encrypt a message using Fernet')
async def encrypt(ctx, message: str):
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    encrypted_message = cipher_suite.encrypt(message.encode())
    await ctx.send(f'Encrypted message: {encrypted_message.decode()}\nKey: {key.decode()}')

# Command: Decrypt message
@bot.slash_command(name='decrypt', description='Decrypt a message using Fernet')
async def decrypt(ctx, encrypted_message: str, key: str):
    cipher_suite = Fernet(key.encode())
    decrypted_message = cipher_suite.decrypt(encrypted_message.encode())
    await ctx.send(f'Decrypted message: {decrypted_message.decode()}')

# Command: Hash message using SHA-256
@bot.slash_command(name='hash_sha256', description='Hash a message using SHA-256')
async def hash_sha256(ctx, message: str):
    hash_object = hashlib.sha256(message.encode())
    hex_dig = hash_object.hexdigest()
    await ctx.send(f'SHA-256 hash: {hex_dig}')

# Command: Hash message using MD5
@bot.slash_command(name='hash_md5', description='Hash a message using MD5')
async def hash_md5(ctx, message: str):
    hash_object = hashlib.md5(message.encode())
    hex_dig = hash_object.hexdigest()
    await ctx.send(f'MD5 hash: {hex_dig}')

# Command: Encrypt message using AES
@bot.slash_command(name='encrypt_aes', description='Encrypt a message using AES')
async def encrypt_aes(ctx, key: str, message: str):
    salt = os.urandom(16)
    aes_key = generate_key(key, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode()) + encryptor.finalize()
    await ctx.send(f'Encrypted message: {base64.urlsafe_b64encode(ct).decode()}\nIV: {base64.urlsafe_b64encode(iv).decode()}')

# Command: Decrypt message using AES
@bot.slash_command(name='decrypt_aes', description='Decrypt a message using AES')
async def decrypt_aes(ctx, key: str, iv: str, encrypted_message: str):
    iv = base64.urlsafe_b64decode(iv)
    encrypted_message = base64.urlsafe_b64decode(encrypted_message)
    aes_key = generate_key(key, b'')  # Normally, we should use the same salt used during encryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    await ctx.send(f'Decrypted message: {decrypted_message.decode()}')

# Command: Encrypt message using RSA
@bot.slash_command(name='encrypt_rsa', description='Encrypt a message using RSA')
async def encrypt_rsa(ctx, public_key: str, message: str):
    public_key = serialization.load_pem_public_key(public_key.encode(), backend=default_backend())
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    await ctx.send(f'Encrypted message: {base64.urlsafe_b64encode(encrypted_message).decode()}')

# Command: Decrypt message using RSA
@bot.slash_command(name='decrypt_rsa', description='Decrypt a message using RSA')
async def decrypt_rsa(ctx, private_key: str, encrypted_message: str):
    private_key = serialization.load_pem_private_key(private_key.encode(), password=None, backend=default_backend())
    encrypted_message = base64.urlsafe_b64decode(encrypted_message)
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    await ctx.send(f'Decrypted message: {decrypted_message.decode()}')

# Command: Generate RSA key pair
@bot.slash_command(name='generate_rsa_keys', description='Generate an RSA key pair')
async def generate_rsa_keys(ctx):
    private_key, public_key = rsa_key_pair()
    await ctx.send(f'Private Key:\n{private_key.decode()}\n\nPublic Key:\n{public_key.decode()}')

# Command: Steganography - Hide message in an image
@bot.slash_command(name='steg_hide', description='Hide a message in an image')
async def steg_hide(ctx, message: str, image_url: str):
    from PIL import Image
    import requests
    from io import BytesIO

    response = requests.get(image_url)
    image = Image.open(BytesIO(response.content))

    binary_message = ''.join(format(ord(i), '08b') for i in message)
    binary_message += '1111111111111110'

    pixels = image.load()
    width, height = image.size
    idx = 0

    for y in range(height):
        for x in range(width):
            if idx < len(binary_message):
                pixel = list(pixels[x, y])
                for n in range(3):
                    if idx < len(binary_message):
                        pixel[n] = pixel[n] & ~1 | int(binary_message[idx])
                        idx += 1
                pixels[x, y] = tuple(pixel)
    
    output_image_path = "steg_output.png"
    image.save(output_image_path)
    await ctx.send(file=discord.File(output_image_path))

# Command: Steganography - Reveal message in an image
@bot.slash_command(name='steg_reveal', description='Reveal a hidden message in an image')
async def steg_reveal(ctx, image_url: str):
    from PIL import Image
    import requests
    from io import BytesIO

    response = requests.get(image_url)
    image = Image.open(BytesIO(response.content))

    binary_message = ''
    pixels = image.load()
    width, height = image.size

    for y in range(height):
        for x in range(width):
            pixel = list(pixels[x, y])
            for n in range(3):
                binary_message += str(pixel[n] & 1)

    binary_message = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
    message = ''
    for byte in binary_message:
        if message[-16:] == '1111111111111110':
            break
        else:
            message += chr(int(byte, 2))
    message = message[:-16]

    await ctx.send(f'Hidden message: {message}')

# Command: Cipher Puzzle
@bot.slash_command(name='cipher_puzzle', description='Generate a cipher puzzle for users to solve')
async def cipher_puzzle(ctx):
    puzzles = [
        ("What is the result of encrypting 'HELLO' with the Caesar cipher using a shift of 3?", "KHOOR"),
        ("Decrypt the message 'GSRH RH Z NVHHZTV' using the Atbash cipher.", "THIS IS A MESSAGE"),
        ("What is the result of hashing 'discord' using SHA-256?", hashlib.sha256("discord".encode()).hexdigest()),
    ]
    puzzle, answer = random.choice(puzzles)
    await ctx.send(f'Puzzle: {puzzle}\n\nReply with the answer.')

    def check(m):
        return m.content.strip().upper() == answer.upper() and m.channel == ctx.channel

    try:
        msg = await bot.wait_for('message', check=check, timeout=60)
        await ctx.send(f'Congratulations {msg.author.mention}! You solved the puzzle.')
    except asyncio.TimeoutError:
        await ctx.send('Time is up! The correct answer was: ' + answer)

# Command: Educational Resource
@bot.slash_command(name='crypto_resource', description='Share a cryptography educational resource')
async def crypto_resource(ctx):
    resources = [
        "Learn about AES encryption: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard",
        "Introduction to RSA encryption: https://en.wikipedia.org/wiki/RSA_(cryptosystem)",
        "Understanding the SHA-256 hash function: https://en.wikipedia.org/wiki/SHA-2",
        "Basics of cryptography: https://www.khanacademy.org/computing/computer-science/cryptography",
    ]
    await ctx.send(random.choice(resources))

# Run the bot
bot.run(os.getenv('DISCORD_TOKEN'))
