#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: CS 41
Name: <YOUR NAME>
SUNet: <SUNet ID>

Replace this with a description of the program.
"""
import utils

# Caesar Cipher

def encrypt_caesar(plaintext):
    if (plaintext == ""):
        return ""
    character_list = list(plaintext)
    A = ord('A')
    Z = ord('Z')
    encrypted_message = []
    for char in character_list:
        encrypted_char = ord(char)
        if (char.isalpha()):
            char = char.capitalize()
            encrypted_char = ord(char)
            encrypted_char += 3
            if (encrypted_char > Z):
                encrypted_char -= (Z - A + 1)
        encrypted_message.append(chr(encrypted_char))
        
    return ''.join(encrypted_message)

def decrypt_caesar(ciphertext):
    if (ciphertext == ""):
        return ""
    character_list = list(ciphertext)
    A = ord('A')
    Z = ord('Z')
    decrypted_message = []
    for char in character_list:
        decrypted_char = ord(char)
        if (char.isalpha()):
            char = char.capitalize()
            decrypted_char = ord(char)
            decrypted_char -= 3
            if (decrypted_char < A):
                decrypted_char += (Z - A + 1)
        decrypted_message.append(chr(decrypted_char))
        
    return ''.join(decrypted_message)

# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword):
    if (plaintext == ""):
        return ""
    if (keyword == ""):
        raise ValueError("keyword is required")
    if (not keyword.isalpha()):
        raise ValueError("keyword must only contain letters")
    keyword = keyword.upper()
    character_list = list(plaintext)
    keyword_char_list = list(keyword)
    A = ord('A')
    Z = ord('Z')
    encrypted_message = []
    k = 0
    for char in character_list:
        if (char.isalpha()):
            char = char.capitalize()
            encrypted_char = ord(char) - A + ord(keyword_char_list[k])
            if (encrypted_char > Z):
                encrypted_char -= (Z - A + 1)
            encrypted_message.append(chr(encrypted_char))
        else:
            encrypted_message.append(char)
        k = k + 1 if k < len(keyword_char_list) - 1 else 0
    return ''.join(encrypted_message)

def decrypt_vigenere(ciphertext, keyword):
    if (plaintext == ""):
        return ""
    if (keyword == ""):
        raise ValueError("keyword is required")
    if (not keyword.isalpha()):
        raise ValueError("keyword must only contain letters")
    keyword = keyword.upper()
    character_list = list(plaintext)
    keyword_char_list = list(keyword)
    A = ord('A')
    Z = ord('Z')
    encrypted_message = []
    k = 0
    for char in character_list:
        if (char.isalpha()):
            char = char.capitalize()
            encrypted_char = ord(char) + A - ord(keyword_char_list[k])
            if (encrypted_char < A):
                encrypted_char += (Z - A + 1)
            encrypted_message.append(chr(encrypted_char))
        else:
            encrypted_message.append(char)
        k = k + 1 if k < len(keyword_char_list) - 1 else 0
    return ''.join(encrypted_message)


# Merkle-Hellman Knapsack Cryptosystem

def generate_private_key(n=8):
    """Generate a private key for use in the Merkle-Hellman Knapsack Cryptosystem.

    Following the instructions in the handout, construct the private key components
    of the MH Cryptosystem. This consistutes 3 tasks:

    1. Build a superincreasing sequence `w` of length n
        (Note: you can check if a sequence is superincreasing with `utils.is_superincreasing(seq)`)
    2. Choose some integer `q` greater than the sum of all elements in `w`
    3. Discover an integer `r` between 2 and q that is coprime to `q` (you can use utils.coprime)

    You'll need to use the random module for this function, which has been imported already

    Somehow, you'll have to return all of these values out of this function! Can we do that in Python?!

    @param n bitsize of message to send (default 8)
    @type n int

    @return 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.
    """
    raise NotImplementedError  # Your implementation here

def create_public_key(private_key):
    """Create a public key corresponding to the given private key.

    To accomplish this, you only need to build and return `beta` as described in the handout.

        beta = (b_1, b_2, ..., b_n) where b_i = r × w_i mod q

    Hint: this can be written in one line using a list comprehension

    @param private_key The private key
    @type private_key 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.

    @return n-tuple public key
    """
    raise NotImplementedError  # Your implementation here


def encrypt_mh(message, public_key):
    """Encrypt an outgoing message using a public key.

    1. Separate the message into chunks the size of the public key (in our case, fixed at 8)
    2. For each byte, determine the 8 bits (the `a_i`s) using `utils.byte_to_bits`
    3. Encrypt the 8 message bits by computing
         c = sum of a_i * b_i for i = 1 to n
    4. Return a list of the encrypted ciphertexts for each chunk in the message

    Hint: think about using `zip` at some point

    @param message The message to be encrypted
    @type message bytes
    @param public_key The public key of the desired recipient
    @type public_key n-tuple of ints

    @return list of ints representing encrypted bytes
    """
    raise NotImplementedError  # Your implementation here

def decrypt_mh(message, private_key):
    """Decrypt an incoming message using a private key

    1. Extract w, q, and r from the private key
    2. Compute s, the modular inverse of r mod q, using the
        Extended Euclidean algorithm (implemented at `utils.modinv(r, q)`)
    3. For each byte-sized chunk, compute
         c' = cs (mod q)
    4. Solve the superincreasing subset sum using c' and w to recover the original byte
    5. Reconsitite the encrypted bytes to get the original message back

    @param message Encrypted message chunks
    @type message list of ints
    @param private_key The private key of the recipient
    @type private_key 3-tuple of w, q, and r

    @return bytearray or str of decrypted characters
    """
    raise NotImplementedError  # Your implementation here

def encrypt_scytale(message):
    return