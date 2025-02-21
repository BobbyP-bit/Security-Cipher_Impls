# Bobby Picasio
# 02/14/25
# Homework 2

## ----------------- A5/1 Implementation Encryption ----------------- 

import re
import copy
import sys 

# A5/1 Register lengths
X_LEN, Y_LEN, Z_LEN = 19, 22, 23  # Number of bits in each shift register

# Global shift registers (will be initialized later)
X_REG, Y_REG, Z_REG = [], [], []
CURRENT_KEY = ""  # Store the binary key used for encryption

def text_to_bin(text):  
    """Converts an 8-character text key into a 64-bit binary string."""
    binary = ''.join(format(ord(char), '08b') for char in text)  # Convert each character to 8-bit binary
    return binary[:64].ljust(64, '0')  # Ensure the key is exactly 64 bits (pad with '0' if needed)

def load_registers(bin_key):  
    """Loads the 64-bit key into the shift registers X, Y, and Z."""
    global X_REG, Y_REG, Z_REG
    X_REG = [int(bin_key[i]) for i in range(X_LEN)]  # First 19 bits go into X register
    Y_REG = [int(bin_key[i + X_LEN]) for i in range(Y_LEN)]  # Next 22 bits go into Y register
    Z_REG = [int(bin_key[i + X_LEN + Y_LEN]) for i in range(Z_LEN)]  # Last 23 bits go into Z register

def set_key(bin_key):  
    """Sets the key and initializes registers."""
    global CURRENT_KEY
    CURRENT_KEY = bin_key
    load_registers(bin_key)  # Load the key into the registers

def string_to_bin(text):  
    """Converts plaintext to binary representation."""
    return [int(bit) for bit in ''.join(format(ord(char), '08b') for char in text)]  # Convert text to binary list

def majority_vote(x, y, z):  
    """Determines the majority bit from the three clocking bits."""
    return 1 if (x + y + z) > 1 else 0  # Majority rule (if 2+ bits are '1', return '1', otherwise return '0')

def generate_keystream(length):  
    """Generates a keystream and prints register values at each step."""
    temp_x, temp_y, temp_z = copy.deepcopy(X_REG), copy.deepcopy(Y_REG), copy.deepcopy(Z_REG)  # Copy registers
    keystream = []  # Store generated keystream bits

    for i in range(length):
        # **Step 1: Determine the majority bit**
        maj = majority_vote(temp_x[8], temp_y[10], temp_z[10])  

        # **Step 2: Shift registers based on the majority bit**
        if temp_x[8] == maj:  # X register shift
            bit = temp_x[13] ^ temp_x[16] ^ temp_x[17] ^ temp_x[18]  # Compute new bit (XOR of selected taps)
            temp_x = [bit] + temp_x[:-1]  # Shift X register

        if temp_y[10] == maj:  # Y register shift
            bit = temp_y[20] ^ temp_y[21]  # Compute new bit (XOR of selected taps)
            temp_y = [bit] + temp_y[:-1]  # Shift Y register

        if temp_z[10] == maj:  # Z register shift
            bit = temp_z[7] ^ temp_z[20] ^ temp_z[21] ^ temp_z[22]  # Compute new bit (XOR of selected taps)
            temp_z = [bit] + temp_z[:-1]  # Shift Z register

        # **Step 3: Generate keystream bit**
        keystream_bit = temp_x[18] ^ temp_y[21] ^ temp_z[22]  # XOR last bits of each register
        keystream.append(keystream_bit)  # Store keystream bit

        # **Step 4: Print the state of registers at each step**
        print(f"\nStep {i+1}:")
        print(f"X = {''.join(map(str, temp_x))}")
        print(f"Y = {''.join(map(str, temp_y))}")
        print(f"Z = {''.join(map(str, temp_z))}")
        print(f"Keystream Bit = {keystream_bit}")

    return keystream

def encrypt_text(plain_text):  
    """Encrypts an 8-character plaintext message and demonstrates XOR process."""
    bin_plain = string_to_bin(plain_text)  # Convert plaintext to binary
    keystream = generate_keystream(len(bin_plain))  # Generate a keystream of the same length
    encrypted = []  # Store encrypted bits

    # **Step 5: Perform One-Time Pad (XOR encryption)**
    print("\nOne-Time Pad Encryption Process:")
    for i in range(len(bin_plain)):
        cipher_bit = bin_plain[i] ^ keystream[i]  # XOR each plaintext bit with keystream bit
        encrypted.append(cipher_bit)  # Store encrypted bit
        print(f"\nPlaintext Bit: {bin_plain[i]} XOR Keystream Bit: {keystream[i]} = {cipher_bit}")  # Show XOR process

    # Convert encrypted binary list to a string
    encrypted_str = ''.join(str(bit) for bit in encrypted)
    
    # **Step 6: Print Final Encrypted Message**

    print(f"\nFinal Encrypted Message: {encrypted_str}")

    
    return encrypted_str

def get_user_key():  
    """Prompts user for an 8-character key."""
    while True:
        key = input('Enter an 8-character key: ').strip()
        if len(key) == 8:
            return text_to_bin(key)  # Convert key to 64-bit binary
        print("Invalid key. Please enter exactly 8 characters.")

def get_user_choice():  
    """Prompts user for an action (encrypt/exit)."""
    while True:
        choice = input('\n0) Quit\n1) Encrypt\n\nSelect an option: ').strip()
        if choice in {'0', '1'}:
            return choice  # Return valid choice
        print("Invalid choice. Please enter 0 or 1.")

def get_plaintext():  
    """Prompts user for plaintext of any length."""
    text = input('Enter a plaintext message to encrypt: ').strip()
    if len(text) > 0:  # Allow any length
        return text  
    print("Invalid input. Please enter at least one character.")


def main():  
    """Main program function handling encryption only."""
    bin_key = get_user_key()  # Get user key input
    set_key(bin_key)  # Set the key into registers
    
    while True:
        choice = get_user_choice()  # Ask user what to do
        
        if choice == '0':  # Exit if user selects 0
            print('Exited.....\n')
            sys.exit(0)
        
        elif choice == '1':  # Encrypt message if user selects 1
            plaintext = get_plaintext()  # Get plaintext from user
            encrypt_text(plaintext)  # Encrypt and display output

main()
