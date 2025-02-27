from ghidra.program.model.address import Address
from ghidra.app.script import GhidraScript
import re

class FindSignatureScript(GhidraScript):
    def run(self):
        # Ask user for hex pattern in \x format
        hex_pattern = askString("Signature Search", "Enter hex pattern (e.g., \\x72\\x70\\x74\\x5F):")

        # Convert the input format (\x72\x70\x74\x5F) into a byte array
        try:
            signature = self.convert_hex_string(hex_pattern)
        except ValueError:
            print("Invalid format. Use \\x notation (e.g., \\x72\\x70\\x74\\x5F).")
            return

        # Perform search
        self.find_signature(signature)

    def convert_hex_string(self, hex_pattern):
        # Remove '\x' and split into pairs
        hex_bytes = re.findall(r'\\x([0-9a-fA-F]{2})', hex_pattern)
        
        if not hex_bytes:
            raise ValueError("Invalid hex string format.")

        # Convert hex pairs to byte array
        return bytearray(int(byte, 16) for byte in hex_bytes)

    def find_signature(self, signature):
        mem = currentProgram.getMemory()
        start = currentProgram.getMinAddress()
        end = currentProgram.getMaxAddress()

        addr = start
        while addr < end:
            addr = mem.findBytes(addr, signature, None, True, monitor)
            if addr is None:
                break
            print("Found at: {}".format(addr))
            addr = addr.add(1)  # Move forward to find more occurrences

# Run the script
script = FindSignatureScript()
script.run()
