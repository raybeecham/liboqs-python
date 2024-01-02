import oqs  # For post-quantum algorithms
from Crypto.PublicKey import RSA
import time
from bokeh.plotting import figure, show, output_file
from bokeh.layouts import column
from bokeh.models import HoverTool, ColumnDataSource
from bokeh.io import export_png
from Crypto.Cipher import PKCS1_OAEP
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
from datetime import datetime

# Set up Chrome options
chrome_options = Options()
chrome_options.add_argument("--headless")  # Enable headless mode
# Add any additional options you need here

# Correct usage - setting up ChromeDriver with options
service = Service(executable_path=ChromeDriverManager().install())

# At the beginning of your script, after setting up ChromeDriver
driver = webdriver.Chrome(service=service, options=chrome_options)

# Algorithms to compare
pq_kems = ["Kyber512"]  # Adjust based on supported algorithms
classical_kems = ["RSA-2048"]

# Function to measure time
def measure_time(function, *args):
    start_time = time.time()
    function(*args)
    end_time = time.time()
    return end_time - start_time

# Test functions
def test_key_generation_time(algorithm):
    if algorithm == "RSA-2048":
        rsa_key = RSA.generate(2048)
        key_generation_time = measure_time(lambda: rsa_key.publickey().exportKey())
    else:  # Post-quantum algorithm case
        with oqs.KeyEncapsulation(algorithm) as kem:
            key_generation_time = measure_time(kem.generate_keypair)
    return key_generation_time

#create a function to test encryption/decryption speed
def test_encryption_decryption_speed(algorithm):
    message = b"This is a test messageageccccccccccccccccccccdasssssssssssssssrewwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwccc"
    if algorithm == "RSA-2048":
        rsa_key = RSA.generate(2048)
        public_key = rsa_key.publickey()
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(message)
        encryption_time = measure_time(lambda: cipher.encrypt(message))
        cipher = PKCS1_OAEP.new(rsa_key)  # Create a PKCS1_OAEP cipher with the private key
        decryption_time = measure_time(lambda: cipher.decrypt(ciphertext))  # Decrypt using the cipher

        
    else:
        # Create client and server KEM objects for post-quantum algorithm
        with oqs.KeyEncapsulation(algorithm) as client:
            with oqs.KeyEncapsulation(algorithm) as server:
                # Client generates its keypair
                public_key_client = client.generate_keypair()

                # Server encapsulates its secret using the client's public key
                start_encap = time.time()
                ciphertext, shared_secret_server = server.encap_secret(public_key_client)
                end_encap = time.time()
                encapsulation_time = end_encap - start_encap

                # Client decapsulates the server's ciphertext
                start_decap = time.time()
                end_decap = time.time()
                decapsulation_time = end_decap - start_decap

    return {
        "encryption_time": encryption_time if algorithm == "RSA-2048" else encapsulation_time,
        "decryption_time": decryption_time if algorithm == "RSA-2048" else decapsulation_time
    }

# create a function to test ciphertext size
def test_ciphertext_size(algorithm):
    message = b"This is a test messagecccccccccccccccccccccccccccccccccewqqqqqqqqqqqccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc."  # Adjust as needed

    if algorithm == "RSA-2048":
        rsa_key = RSA.generate(2048)
        public_key = rsa_key.publickey()
        cipher = PKCS1_OAEP.new(public_key)  # Create a PKCS1_OAEP cipher
        ciphertext = cipher.encrypt(message)  # Encrypt using the cipher
        return len(ciphertext)  # Size of RSA ciphertext
    else:
        # Post-quantum algorithm case
        with oqs.KeyEncapsulation(algorithm) as client:
            # Client generates its keypair and public key is returned
            public_key_client = client.generate_keypair()

            # Another KeyEncapsulation instance to act as the server
            with oqs.KeyEncapsulation(algorithm) as server:
                # Server encapsulates its secret using the client's public key
                ciphertext, shared_secret_server = server.encap_secret(public_key_client)
                
                # Return the total size of ciphertext and shared secret
                return len(ciphertext) + len(shared_secret_server)

def generate_report(results):
    output_file("report.html")

    # Ensure the 'colors' list has the correct length
    colors = ["blue", "green", "red", "orange"] * (len(results['x']) // 4) + ["blue", "green", "red", "orange"][:len(results['x']) % 4]
    
    # Update the 'results' dictionary to include colors
    results['colors'] = colors

    # Create a ColumnDataSource with the results dictionary
    source = ColumnDataSource(data=results)

    # Key Generation Time Chart
    key_gen_chart = figure(x_range=results['x'], title="Key Generation Time Comparison", tools="save")
    key_gen_hover = HoverTool(tooltips=[("Algorithm", "@x"), ("Time", "@key_generation_time s")])
    key_gen_chart.add_tools(key_gen_hover)
    key_gen_chart.vbar(x='x', top='key_generation_time', width=0.5, source=source)
    key_gen_chart.yaxis.axis_label = "Time (seconds)"
    key_gen_chart.xaxis.axis_label = "Algorithm"

    # Encryption and Decryption Speed Charts
    encryption_results = {"x": results["x"], "encryption_time": results["encryption_time"], "colors": results["colors"]}
    decryption_results = {"x": results["x"], "decryption_time": results["decryption_time"], "colors": results["colors"]}
    
    # Create separate Bokeh figures for encryption and decryption
    encryption_speed_chart = figure(x_range=encryption_results['x'], title="Encryption Speed Comparison", tools="save")
    encryption_hover = HoverTool(tooltips=[("Algorithm", "@x"), ("Time", "@encryption_time s")])
    encryption_speed_chart.add_tools(encryption_hover)
    encryption_speed_chart.vbar(x='x', top='encryption_time', width=0.5, color='green', source=ColumnDataSource(data=encryption_results))
    encryption_speed_chart.yaxis.axis_label = "Time (seconds)"
    encryption_speed_chart.xaxis.axis_label = "Algorithm"

    decryption_speed_chart = figure(x_range=decryption_results['x'], title="Decryption Speed Comparison", tools="save")
    decryption_hover = HoverTool(tooltips=[("Algorithm", "@x"), ("Time", "@decryption_time s")])
    decryption_speed_chart.add_tools(decryption_hover)
    decryption_speed_chart.vbar(x='x', top='decryption_time', width=0.5, color='red', source=ColumnDataSource(data=decryption_results))
    decryption_speed_chart.yaxis.axis_label = "Time (seconds)"
    decryption_speed_chart.xaxis.axis_label = "Algorithm"

    # Ciphertext Size Chart
    ciphertext_size_chart = figure(x_range=results['x'], title="Ciphertext Size Comparison", tools="save")
    ciphertext_hover = HoverTool(tooltips=[("Algorithm", "@x"), ("Size", "@ciphertext_size bytes")])
    ciphertext_size_chart.add_tools(ciphertext_hover)
    ciphertext_size_chart.vbar(x='x', top='ciphertext_size', width=0.5, source=source)
    ciphertext_size_chart.yaxis.axis_label = "Size (bytes)"
    ciphertext_size_chart.xaxis.axis_label = "Algorithm"

    # Combine all plots into a single layout
    combined_layout = column(key_gen_chart, encryption_speed_chart, decryption_speed_chart, ciphertext_size_chart)


    # Export the charts as PNG images
    export_png(key_gen_chart, filename="key_generation_time_chart.png", webdriver=driver)
    export_png(encryption_speed_chart, filename="encryption_speed_chart.png", webdriver=driver)
    export_png(decryption_speed_chart, filename="decryption_speed_chart.png", webdriver=driver)
    export_png(ciphertext_size_chart, filename="ciphertext_size_chart.png", webdriver=driver)


    # Generate the report
    #show(combined_layout)

# Main code
if __name__ == "__main__":
    # Create a list to store the results
    results = {"x": pq_kems + classical_kems, "key_generation_time": [], "encryption_time": [], "decryption_time": [], "ciphertext_size": [], "colors": []}

    # Test key generation time for each algorithm
    for algorithm in results["x"]:
        key_gen_time = test_key_generation_time(algorithm)
        results["key_generation_time"].append(key_gen_time)

    # Test encryption/decryption speed and ciphertext size for each algorithm
    for algorithm in results["x"]:
        speed_results = test_encryption_decryption_speed(algorithm)
        ciphertext_size = test_ciphertext_size(algorithm)
        results["encryption_time"].append(speed_results["encryption_time"])
        results["decryption_time"].append(speed_results["decryption_time"])
        results["ciphertext_size"].append(ciphertext_size)

    # Generate and display the report
    generate_report(results)


# Generate Markdown report
current_time = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")

# Assuming that 'Kyber512' is the first algorithm and 'RSA-2048' is the second algorithm in the 'x' list
kyber_index = results['x'].index('Kyber512')
rsa_index = results['x'].index('RSA-2048')

report_markdown = f"# Post-Quantum Cryptography Algorithm Report\n\n"\
                  f"## Introduction\n"\
                  f"This report provides an analysis of key generation, encryption, and decryption times, "\
                  f"as well as ciphertext sizes for a set of cryptographic algorithms, including both classical and post-quantum candidates.\n\n"\
                  f"## Key Generation Time Analysis\n"\
                  f"The following table and chart illustrate the time taken by each algorithm to generate keys.\n\n"\
                  f"| Algorithm | Key Gen Time (s) |\n"\
                  f"|-------------|--------------------|\n"\
                  f"| Kyber512 | {results['key_generation_time'][kyber_index]} |\n"\
                  f"| RSA-2048 | {results['key_generation_time'][rsa_index]} |\n\n"\
                  f"![Key Generation Time Chart](key_generation_time_chart.png)\n\n"\
                  f"## Encryption Speed Analysis\n"\
                  f"This section compares the encryption speeds of the algorithms.\n\n"\
                  f"| Algorithm | Encryption Time (s) |\n"\
                  f"|-------------|-----------------------|\n"\
                  f"| Kyber512 | {results['encryption_time'][kyber_index]} |\n"\
                  f"| RSA-2048 | {results['encryption_time'][rsa_index]} |\n\n"\
                  f"![Encryption Speed Chart](encryption_speed_chart.png)\n\n"\
                  f"## Decryption Speed Analysis\n"\
                  f"This section compares the decryption speeds of the algorithms.\n\n"\
                  f"| Algorithm | Decryption Time (s) |\n"\
                  f"|-------------|-----------------------|\n"\
                  f"| Kyber512 | {results['decryption_time'][kyber_index]} |\n"\
                  f"| RSA-2048 | {results['decryption_time'][rsa_index]} |\n\n"\
                  f"![Decryption Speed Chart](decryption_speed_chart.png)\n\n"\
                  f"## Ciphertext Size Comparison\n"\
                  f"The size of the ciphertext is a crucial factor in assessing the efficiency of cryptographic algorithms.\n\n"\
                  f"| Algorithm | Ciphertext Size (bytes) |\n"\
                  f"|-------------|---------------------------|\n"\
                  f"| Kyber512 | {results['ciphertext_size'][kyber_index]} |\n"\
                  f"| RSA-2048 | {results['ciphertext_size'][rsa_index]} |\n\n"\
                  f"![Ciphertext Size Chart](ciphertext_size_chart.png)\n\n"\
                  f"## Conclusion\n"\
                  f"This report highlights the performance and efficiency differences between classical and post-quantum cryptographic algorithms. "\
                  f"As the field evolves, these insights are essential for making informed decisions about cryptographic implementations.\n\n"\
                  f"---\n"\
                  f"Generated on: {current_time}"

# Save the Markdown report
with open("algorithm_report.md", "w") as f:
    f.write(report_markdown)

# Print the report content in the console (optional)
print(report_markdown)

