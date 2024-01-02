import oqs.rand as oqsrand
import requests
import base64
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import ks_2samp
from scipy.spatial.distance import jensenshannon

# Define API constants
accesstoken = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjU3ZmM1M2FkZTQ5MzQ2YTc5NDdkMzFhYzk1YmEzODFkIn0.eyJleHAiOjE3MzQ0NTMzMDgsIm5iZiI6MTcwMjkxNzMwOCwiaXNzIjoiQVVUSCIsImlhdCI6MTcwMjkxNzMwOCwiZ3JwcyI6WyJQVUIiXSwiYXVkIjpbIlFERUEiLCJSUFMiXSwicmxzIjpbIlFERVVTUiIsIlJORFVTUiJdLCJjaWQiOiJ3THA5RXdqSUhYRzYtMW5WNWJoSGYiLCJkdmMiOiI1ZmViYzlkMzVlMjA0NmE4YWUwM2ZmOTBmZmQxM2JhNSIsImp0aSI6ImRhNmQzMjllYTZkYTQwMDM5MTUyYjIxMDEwZjc3ODU5IiwidHlwIjozfQ.m1ZrV7O5aFy3DLlVBzqmT7wMd8qQaGw2Ef-CKsjKJz2wyYN-1SejhJl36C8tJIxZq3DLtkvNRAUM7-5PTqYzww"
kibData = 1  # 1 KiB = 1024 bytes = 8192 bits
sub = "api-eus"
url = f"https://{sub}.qrypt.com/api/v1/quantum-entropy"


# Function to fetch and decode entropy
def get_entropy(source):
    # Get entropy from OQS
    if source == "oqs":
        entropy_seed = [0] * 48
        for i in range(0, 48):
            entropy_seed[i] = i
        oqsrand.randombytes_nist_kat_init_256bit(bytes(entropy_seed))
        oqsrand.randombytes_switch_algorithm("NIST-KAT")
        return oqsrand.randombytes(1024)  # 1024 bytes = 8192 bits
    # Get entropy from Qrypt API
    elif source == "qrypt":
        headers = {"Authorization": f"Bearer {accesstoken}"}
        params = {"size": kibData}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            qrypt_entropy_b64 = "".join(response.json()["random"])
            return base64.b64decode(qrypt_entropy_b64)
        else:
            raise ValueError(f"Qrypt API error: {response.status_code}")
    else:
        raise ValueError(f"Invalid entropy source: {source}")


# Generate entropy from both sources
oqs_entropy = get_entropy("oqs")
qrypt_entropy = get_entropy("qrypt")

# Get byte lengths
byte_length_oqs = len(oqs_entropy)
byte_length_qrypt = len(qrypt_entropy)

# Compare lengths
if len(oqs_entropy) != len(qrypt_entropy):
    raise ValueError("Entropy lengths mismatch!")

# Convert to uint8 arrays to enable statistical analysis
oqs_entropy_int = np.frombuffer(oqs_entropy, dtype=np.uint8)  # Convert to uint8 array
qrypt_entropy_int = np.frombuffer(
    qrypt_entropy, dtype=np.uint8
)

# Basic statistics
oqs_stats = np.percentile(oqs_entropy_int, [25, 50, 75])
qrypt_stats = np.percentile(qrypt_entropy_int, [25, 50, 75])
print("Entropy Statistics:")
print("OQS (25th, 50th, 75th percentile):", oqs_stats)
print("Qrypt (25th, 50th, 75th percentile):", qrypt_stats)

# Entropy rate
oqs_rate = len(oqs_entropy) * 8 / len(oqs_entropy)
qrypt_rate = len(qrypt_entropy) * 8 / len(qrypt_entropy)
print("Entropy Rate (bits per byte):")
print("OQS:", oqs_rate)
print("Qrypt:", qrypt_rate)


# Entropy difference score (hamming distance)
def hamming_distance(a, b):
    binary = bin(a ^ b)[2:]  # Remove '0b' prefix
    return sum(char == "1" for char in binary)  # Count '1' characters


hamming_score = sum(hamming_distance(x, y) for x, y in zip(oqs_entropy, qrypt_entropy))
print(
    "Hamming distance score:", hamming_score
)

# Kolmogorov-Smirnov test (ensure this is executed before report generation)
ks_statistic, ks_p_value = ks_2samp(oqs_entropy_int, qrypt_entropy_int)
print("Kolmogorov-Smirnov test p-value:", ks_p_value)

# Jensen-Shannon divergence
js_divergence = jensenshannon(oqs_entropy_int, qrypt_entropy_int)
print("Jensen-Shannon divergence:", js_divergence)

# Plot histograms
plt.hist(oqs_entropy_int, bins=256, label="OQS")
plt.hist(qrypt_entropy_int, bins=256, alpha=0.7, label="Qrypt")
plt.legend()
plt.show()

# Generate Markdown report
with open("entropy_analysis.md", "w") as f:
    f.write(
        """# Code Analysis

**Purpose:**
- This Python script compares the statistical properties of entropy data generated from two different sources:
    - OQS (Open Quantum Safe): A library for quantum-resistant cryptography.
    - Qrypt: A quantum-based random number generator API.
- The primary goal is to determine whether the entropy generated by these sources has comparable statistical properties, indicating potential suitability for use in cryptographic applications.

**Key Steps:**
1. **Fetches Entropy:** Retrieves entropy samples from both OQS and Qrypt.
2. **Performs Basic Statistics:** Calculates percentiles and entropy rates for each sample.
3. **Calculates Difference Scores:**
    - Hamming distance: Measures the number of differing bits between the samples.
        - Range: 0 to the length of the compared sequences (in bits).
    - Kolmogorov-Smirnov test: Assesses the similarity of their overall distributions.
        - Range: 0 to 1.
    - Jensen-Shannon divergence: Quantifies the difference between their probability distributions.
        - Range: Non-negative, typically between 0 and 1.
4. **Generates Markdown Report:** Creates this report to summarize the analysis and findings.
            
## Basic Statistics

**Understanding the Entropy Landscape**
- This section explain the fundamental characteristics of the generated entropy from OQS and Qrypt. I analyze
  their statistical distributions and information density to guage their suitability for cryptographic applications.
            
**Percentiles to Uneveil the Value Landscape**
- Percentiles offer a window into how entropy values are distributed within each sample. They reveal the typical values (50th percentile),
             as well as the range of values (25th and 75th percentiles). By comparing the percentiles of OQS and Qrypt, we can
             gain insights into their overall data spread and potential similarities or differences in value distribution.

**Entropy Rate to Assess Information Density**
- Entropy rate is a measure of the information density of a sequence. It is defined as the number of bits per byte. 
            High rates indicate strong randomness, making the data less predictable and more secure for cryptographic use.
            Examining the entropy rates of OQS and Qrypt can help us assess their effectiveness in generating high-quality,
            unprectable random numbers.            

## Percentiles (25th, 50th, 75th)
- OQS (25th, 50th, 75th percentile): {}
- Qrypt (25th, 50th, 75th percentile): {}

## Entropy Rate:
- **Bits per Byte:**
    - OQS: {} 
    - Qrypt: {}

Note: The length of each sequence is {} bytes. This translates to ({} * 8 bits/byte) or 8192 bits for OQS and Qrypt.

## Test Results
**Test** | **Value** | **Interpretation**
---------|-----------|-----------------
Hamming distance | {} | Lower scores indicate greater similarity at the bit level. Range: 0 to the sequence length.
Kolmogorov-Smirnov test p-value | {} | Higher p-values (typically above 0.05) suggest similar distributions. Range: 0 to 1.
Jensen-Shannon divergence | {} | Lower values indicate more similar probability distributions. Range: 0 to 1 (typically).

## Final Analysis:
**Thresholds for Comparability:**
- Hamming distance < 5000 
- Kolmogorov-Smirnov test p-value > 0.05 
- Jensen-Shannon divergence < 0.5 

# Conclusion:
""".format(
            oqs_stats,
            qrypt_stats,
            oqs_rate,
            qrypt_rate,
            byte_length_oqs,
            byte_length_qrypt,
            hamming_score,
            ks_p_value,
            js_divergence,
        )
    )

    if hamming_score < 5000 and ks_p_value > 0.05 and js_divergence < 0.1:
        f.write(
            """
    The results indicate that the entropy generated by OQS and Qrypt has comparable statistical properties, suggesting potential suitability for use in cryptographic applications.
    """
        )
    else:
        f.write(
            """
    The results suggest that there might be significant differences between the entropy generated by OQS and Qrypt. Further investigation is recommended to assess their suitability for cryptographic purposes.
    """
        )