import platform
import oqs.rand as oqsrand
from oqs import oqs_version, oqs_python_version

def generate_bits(algorithm, num_bits):
    """Generates a string of bits (1s and 0s) using the specified algorithm.

    Args:
        algorithm (str): The algorithm to use 'NIST-KAT'
        num_bits (int): The number of bits to generate.

    Returns:
        str: A string of 1s and 0s representing the generated bits.
    """

    oqsrand.randombytes_switch_algorithm(algorithm)
    random_bytes = oqsrand.randombytes(num_bits // 8)  # Generate bytes for efficiency
    bits = "".join(format(byte, "08b") for byte in random_bytes)  # Convert bytes to bits
    return bits[:num_bits]  # Take only the required number of bits

# print bits from NIST-KAT
bits_nist = generate_bits("NIST-KAT", 30000)  # Generate 64 bits using NIST-KAT
print("Bits from NIST-KAT:", bits_nist)

def save_bits_to_file(algorithm, num_bits, filename):
    """Generates bits using the specified algorithm and saves them to a file.

    Args:
        algorithm (str): The algorithm to use 'NIST-KAT'.
        num_bits (int): The number of bits to generate.
        filename (str): The name of the file to save the bits to.
    """

    bits = generate_bits(algorithm, num_bits)
    with open(filename, "w") as file:
        file.write(bits)

save_bits_to_file("NIST-KAT", 409600, "nist_kat_bits.bin") 