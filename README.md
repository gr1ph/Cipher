# Cipher

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Discord](https://img.shields.io/badge/Discord.py-1.7.3-blue)

Cipher is a powerful Discord bot designed to provide a variety of cryptographic functionalities, including encryption, decryption, hashing, and more. Enhance your server's security and engage users with educational resources and cryptographic challenges.

> [!IMPORTANT]
> Cipher is in complete alpha expect errors, and a lot of garbage code.

## Features

- **Encryption and Decryption:** Encrypt and decrypt messages using various algorithms.
- **Hashing:** Generate hashes using SHA-256, MD5, and more.
- **Key Generation:** Generate cryptographic keys for different algorithms.
- **Steganography:** Hide and reveal messages within images or other media.
- **Cipher Games/Puzzles:** Engage users with cryptographic challenges and puzzles.
- **Educational Resources:** Share articles, tutorials, and resources about cryptography.
- **Secure Messaging:** Facilitate secure message exchange between users.

## Getting Started

Follow these steps to get Cipher up and running on your Discord server.

### Prerequisites

- Python 3.8+
- `discord.py` library
- `cryptography` library

Install the required libraries using pip:

```bash
pip install discord.py cryptography

### Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/Cipher.git
cd Cipher
```

2. Create a `.env` file in the root directory and add your Discord bot token:

```env
DISCORD_TOKEN=your_discord_bot_token
```

3. Run the bot:

```bash
python bot.py
```

## Usage

Invite Cipher to your Discord server and use the following slash commands:

### Encryption and Decryption

- **Encrypt a message:**
  ```
  /encrypt message:<message>
  ```
  Example: `/encrypt message:Hello, World!`

- **Decrypt a message:**
  ```
  /decrypt encrypted_message:<encrypted_message> key:<key>
  ```
  Example: `/decrypt encrypted_message:gAAAAABf2... key:<key>`

### Hashing

- **Generate SHA-256 hash:**
  ```
  /hash_sha256 message:<message>
  ```
  Example: `/hash_sha256 message:Hello, World!`

- **Generate MD5 hash:**
  ```
  /hash_md5 message:<message>
  ```
  Example: `/hash_md5 message:Hello, World!`

### AES Encryption and Decryption

- **Encrypt a message using AES:**
  ```
  /encrypt_aes key:<key> message:<message>
  ```
  Example: `/encrypt_aes key:mypassword message:Hello, World!`

- **Decrypt a message using AES:**
  ```
  /decrypt_aes key:<key> iv:<iv> encrypted_message:<encrypted_message>
  ```
  Example: `/decrypt_aes key:mypassword iv:<iv> encrypted_message:<encrypted_message>`

### RSA Encryption and Decryption

- **Encrypt a message using RSA:**
  ```
  /encrypt_rsa public_key:<public_key> message:<message>
  ```
  Example: `/encrypt_rsa public_key:<public_key> message:Hello, World!`

- **Decrypt a message using RSA:**
  ```
  /decrypt_rsa private_key:<private_key> encrypted_message:<encrypted_message>
  ```
  Example: `/decrypt_rsa private_key:<private_key> encrypted_message:<encrypted_message>`

## Contributing

We welcome contributions from the community. To contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For questions or suggestions, please contact us at [jacobgreymorgan@gmail.com].

---

Thank you for using Cipher!
```
