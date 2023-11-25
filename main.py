from sympy import mod_inverse

def rsa_encrypt_block(message, e, n):
    """
    Encrypt a message using RSA encryption with block support.

    :param message: The plaintext message to encrypt.
    :param e: The encryption exponent.
    :param n: The modulus.
    :return: The encrypted message as a list of integers.
    """
    # Convert the message to uppercase (assuming the dictionary is in uppercase)
    message = message.upper()
    
    # Convert each letter in the message to its corresponding number using the provided dictionary
    letter_to_number = {chr(i + 65): str(i).zfill(2) for i in range(26)}  # Dictionary to convert letter to number
    number_message = ''.join([letter_to_number[char] for char in message if char in letter_to_number])
    
    # Split the message into blocks of 4 digits (2 letters)
    blocks = [number_message[i:i+4] for i in range(0, len(number_message), 4)]
    
    # Encrypt each block by computing c = m^e mod n
    encrypted_blocks = [str(pow(int(block), e, n)).zfill(4) for block in blocks]
    
    return encrypted_blocks

def rsa_decrypt_blocks(encrypted_blocks, d, n):
    """
    Decrypt a message using RSA encryption with block support.

    :param encrypted_blocks: The encrypted message as a list of block strings.
    :param d: The decryption exponent.
    :param n: The modulus.
    :return: The decrypted message as a string.
    """
    # Decrypt each block by computing m = c^d mod n
    decrypted_blocks = [str(pow(int(block), d, n)).zfill(4) for block in encrypted_blocks]
    
    # Convert each block back to its corresponding letters
    number_to_letter = {str(i).zfill(2): chr(i + 65) for i in range(26)}  # Dictionary to convert number to letter
    decrypted_message = ''.join(''.join(number_to_letter[decrypted_blocks[i][j:j+2]]
                                        for j in range(0, len(decrypted_blocks[i]), 2))
                                for i in range(len(decrypted_blocks)))
    
    return decrypted_message

# Encrypt the message "STOP" with the public key (13, 2537)
encrypted_message = rsa_encrypt_block("STOP", 13, 2537)

# Prepare for decryption of the given encrypted message '0981 0461' with n = 43 * 59 and e = 13
# Calculate the decryption exponent 'd'
n = 43 * 59
phi_n = (43 - 1) * (59 - 1)
e = 13
d = mod_inverse(e, phi_n)

# Decrypt the provided encrypted message
encrypted_blocks = ['0981', '0461']
decrypted_message = rsa_decrypt_blocks(encrypted_blocks, d, n)

# Print the results
print("Encrypted message: {}".format(encrypted_message))
print("Decrypted message: {}".format(decrypted_message))
