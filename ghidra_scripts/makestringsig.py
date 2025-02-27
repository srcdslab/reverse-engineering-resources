from __future__ import print_function
import collections

# Function to format byte signature as SourceMod format
def byte_to_signature(byte):
    return r'\x{:02X}'.format(byte)

# Function to check if the address is part of a string (null-terminated)
def is_string(address):
    data = currentProgram.getMemory()
    try:
        byte = data.getByte(address)
        return byte >= 32 and byte < 127  # ASCII printable character range
    except Exception:
        return False

# Function to generate signature for a string
def string_to_signature(string):
    return ''.join(r'\x{:02X}'.format(ord(c)) for c in string)

def process():
    # Ensure we're on a string address
    current_address = currentAddress
    data = currentProgram.getMemory()
    string_data = []
    
    # Read characters until a null terminator is found
    while is_string(current_address):
        byte = data.getByte(current_address)
        if byte == 0:  # End of string (null terminator)
            break
        string_data.append(chr(byte))
        current_address = current_address.add(1)

    # If a string is found, process it
    if string_data:
        string = ''.join(string_data)
        print("String found:", string)
        print("String signature:", string_to_signature(string))
    else:
        print("No string found at the current address.")

if __name__ == "__main__":
    process()
