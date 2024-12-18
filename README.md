# Secure Communication Between Alice and Bob

This project demonstrates secure communication between two parties, Alice and Bob, using authenticated encryption. The system ensures message confidentiality, authenticity, and protection against replay attacks.

## Features

- **Message Confidentiality**: Uses AES-128-CTR for encryption.
- **Message Authenticity**: Uses HMAC-SHA256 for message authentication.
- **Protection Against Replay Attacks**: Includes a sequence number in the messages.

## Files

- `gen.py`: Generates pre-shared keys for encryption and authentication.
- `alice.py`: Alice's script to send and receive encrypted messages.
- `bobside.py`: Bob's script to send and receive encrypted messages.

## Setup

1. Install the required Python packages:
    ```sh
    pip install -r requirements.txt
    ```

2. Generate the pre-shared keys:
    ```sh
    python3 gen.py
    ```

## Usage

1. Start Bob's script to listen for incoming messages:
    ```sh
    python3 bobside.py
    ```

2. Run Alice's script to send and receive messages:
    ```sh
    python3 alice.py
    ```

## Message Exchange

The following messages are exchanged between Alice and Bob:

1. From Alice: "Hello Bob"
2. From Bob: "Hello Alice"
3. From Alice: "I would like to have dinner"
4. From Bob: "Me too. Same time, same place?"
5. From Alice: "Sure!"

Alice sends an "end" message to indicate the end of the conversation, and Bob closes the connection upon receiving this message.

## Requirements

- Python 3.x
- `pycryptodome` library

## License

This project is licensed under the MIT License.