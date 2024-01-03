import requests
import base64
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox



def fetch_quantum_data(size):
# Specify entropy token, requeststed size of entropy, and subdomain

    accesstoken = 'Your Access Key'
    #kibData = 1
    sub = 'api-eus'
    url = f'https://{sub}.qrypt.com/api/v1/quantum-entropy'
    headers = {'Authorization': f'Bearer {accesstoken}'}
    params = {'size': size}


    try:
        response = requests.get(url, headers=headers, params=params)
        random_data = response.json()['random']
        binary_numbers = ''
        for s in random_data:
            binary_numbers += ''.join(f'{b:08b}' for b in base64.decodebytes(s.encode('ascii')))
        return binary_numbers
    except Exception as e:
        print(f"An error occurred during data fetching or processing: {e}")
        raise  # Re-raise the exception so you can catch it in the calling function as well.

# Function to clear the results and info label
def clear_results():
    result_label.delete('1.0', tk.END)
    info_label.config(text="Generated 0 bits (0 bytes)")
    data_size_entry.focus()
    data_size_entry.select_range(0, tk.END)



# Function to handle the submit action
def submit_action():
    data_size_str = data_size_entry.get().strip()
    if data_size_str.isdigit():  # Check if the input string is all digits
        data_size = int(data_size_str)
        binary_numbers = fetch_quantum_data(data_size)
        
        num_bits = len(binary_numbers)  # The number of bits is the length of the string
        num_bytes = num_bits // 8  # Divide by 8 to get the number of bytes
        info_label.config(text=f"Generated {num_bits} bits ({num_bytes} bytes)")
        
        result_label.delete('1.0', tk.END)
        result_label.insert(tk.END, binary_numbers)
    else:
        messagebox.showerror("Error", "Invalid input. Please enter a numeric value.")

# Function to copy text to the clipboard
def copy_to_clipboard(text_widget):
    root.clipboard_clear()  # Clear the clipboard
    text_to_copy = text_widget.get("1.0", tk.END).rstrip()  # Get text and remove trailing newline
    root.clipboard_append(text_to_copy)  # Append the text to the clipboard
    messagebox.showinfo("Copied", "The binary data has been copied to the clipboard.")

# Set up the main window
root = tk.Tk()
root.title("Quantum Random Number Generator")

# Input for data size
data_size_label = ttk.Label(root, text="Enter Data Size (in KiB):")
data_size_label.pack()
data_size_entry = ttk.Entry(root)
data_size_entry.pack()

# Submit button
submit_button = ttk.Button(root, text="Generate", command=submit_action)
submit_button.pack()

# Clear button
clear_button = ttk.Button(root, text="Clear", command=clear_results)
clear_button.pack()

# Info label to display the number of bits and bytes
info_label = tk.Label(root, text="Generated 0 bits (0 bytes)")
info_label.pack()

# Scrollable Text Widget for results
result_frame = ttk.Frame(root)
result_frame.pack()
result_scroll = ttk.Scrollbar(result_frame)
result_scroll.pack(side=tk.RIGHT, fill=tk.Y)
result_label = tk.Text(result_frame, wrap=tk.NONE, yscrollcommand=result_scroll.set, height=10)
result_label.pack()
result_scroll.config(command=result_label.yview)

# Button to copy the results to the clipboard
copy_button = ttk.Button(root, text="Copy to Clipboard", command=lambda: copy_to_clipboard(result_label))
copy_button.pack()

# Run the application
root.mainloop()
