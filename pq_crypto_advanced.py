import oqs  # For post-quantum algorithms
from Crypto.PublicKey import RSA
import time
import pytest
from bokeh.plotting import figure, show
from markdownify import markdownify as md
from tabulate import tabulate

# ... (Import other necessary libraries, e.g., for Markdown report generation)

# Algorithms to compare
pq_kems = ["Kyber512"]  # Adjust based on supported algorithms
classical_kems = ["RSA-2048"]

# Function to measure time
def measure_time(function):
    start_time = time.time()
    function()
    end_time = time.time()
    return end_time - start_time

# Test functions
def test_key_generation_time(algorithm):
    if algorithm == "RSA-2048":
        # Potential fix for context manager issue:
        rsa_key = RSA.generate(2048)
        key_generation_time = measure_time(rsa_key.publickey().exportKey)
    else:
        with oqs.KeyEncapsulation(algorithm) as kem:
            key_generation_time = measure_time(kem.generate_keypair)
    return key_generation_time

def test_encryption_decryption_speed(algorithm):
    message = b"This is a test message."  # Adjust message size as needed

    if algorithm == "RSA-2048":
        with RSA.generate(2048) as rsa_key:
            public_key = rsa_key.publickey()
            ciphertext = public_key.encrypt(message)  # Encrypt the message
            encryption_time = measure_time(public_key.encrypt, message)
            decryption_time = measure_time(rsa_key.decrypt, ciphertext)
    else:
        with oqs.KeyEncapsulation(algorithm) as kem:
            keypair = kem.generate_keypair()
            ciphertext, shared_secret = kem.encapsulate(keypair.public_key)  # Encapsulate the message
            encapsulation_time = measure_time(kem.encapsulate, keypair.public_key)
            decapsulation_time = measure_time(kem.decapsulate, ciphertext, keypair.secret_key)

    return {
        "encryption_time": encryption_time or encapsulation_time,
        "decryption_time": decryption_time or decapsulation_time
    }

def test_ciphertext_size(algorithm):
    message = b"This is a test message."  # Adjust as needed

    if algorithm == "RSA-2048":
        with RSA.generate(2048) as rsa_key:
            public_key = rsa_key.publickey()
            ciphertext = public_key.encrypt(message)
            return len(ciphertext)
    else:
        with oqs.KeyEncapsulation(algorithm) as kem:
            ciphertext, shared_secret = kem.encapsulate(kem.generate_keypair().public_key)
            return len(ciphertext) + len(shared_secret)  # Include shared secret size


def generate_report(results):
    report_markdown = f"""
# Algorithm Comparison Report

## Key Generation Time (seconds)

{md(tabulate([[algorithm, results[algorithm]['key_generation_time']] for algorithm in results], headers=['Algorithm', 'Time']))}

## ... (Add similar sections for other metrics, including charts)
"""

    # Create Bokeh charts (example for key generation time)
    key_gen_chart = figure(x_range=list(results.keys()), title="Key Generation Time Comparison")
    key_gen_chart.vbar(x=list(results.keys()), top=[time for time in results.values()], legend_label="Time (s)", width=0.8)
    key_gen_chart.xaxis.major_label_orientation = 0.75
    report_markdown += f"{show(key_gen_chart)}"  # Embed chart in Markdown

    # Create chart for encryption/decryption speed
    encryption_speed_chart = figure(x_range=list(results.keys()), title="Encryption/Decryption Speed Comparison")
    # ... Add data points and styling for encryption/decryption time values
    encryption_speed_chart.vbar(x=list(results.keys()), top=[result["encryption_time"] + result["decryption_time"] for result in results.values()], legend_label="Time (s)", width=0.8)
    report_markdown += f"{show(encryption_speed_chart)}"

    # Create chart for ciphertext size
    ciphertext_size_chart = figure(x_range=list(results.keys()), title="Ciphertext Size Comparison")
    # ... Add data points and styling for ciphertext size values
    ciphertext_size_chart.vbar(x=list(results.keys()), top=[result["ciphertext_size"] for result in results.values()], legend_label="Size (bytes)", width=0.8)
    report_markdown += f"{show(ciphertext_size_chart)}"

    # Save or display the report
    with open("algorithm_report.md", "w") as f:
        f.write(report_markdown)

    print(report_markdown)  # Optional: Display the report content in the console

# Collect and store results in a structured format
results = {}
for algorithm in pq_kems + classical_kems:
    results[algorithm] = {
        "key_generation_time": test_key_generation_time(algorithm),
        # ... (Add other comparison metrics and their function calls)
    }

# Run report generation
generate_report(results)  # Trigger the report creation and analysis process