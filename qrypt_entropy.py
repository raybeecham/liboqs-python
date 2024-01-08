import requests
import base64

# Specify entropy token, requested size of entropy, and subdomain
accesstoken = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjU3ZmM1M2FkZTQ5MzQ2YTc5NDdkMzFhYzk1YmEzODFkIn0.eyJleHAiOjE3MzQ0NTMzMDgsIm5iZiI6MTcwMjkxNzMwOCwiaXNzIjoiQVVUSCIsImlhdCI6MTcwMjkxNzMwOCwiZ3JwcyI6WyJQVUIiXSwiYXVkIjpbIlFERUEiLCJSUFMiXSwicmxzIjpbIlFERVVTUiIsIlJORFVTUiJdLCJjaWQiOiJ3THA5RXdqSUhYRzYtMW5WNWJoSGYiLCJkdmMiOiI1ZmViYzlkMzVlMjA0NmE4YWUwM2ZmOTBmZmQxM2JhNSIsImp0aSI6ImRhNmQzMjllYTZkYTQwMDM5MTUyYjIxMDEwZjc3ODU5IiwidHlwIjozfQ.m1ZrV7O5aFy3DLlVBzqmT7wMd8qQaGw2Ef-CKsjKJz2wyYN-1SejhJl36C8tJIxZq3DLtkvNRAUM7-5PTqYzww"

kibData = 1 # 1 KiB = 1024 bytes = 8192 bits
sub = "api-eus"

# Define the request URL
url = f"https://{sub}.qrypt.com/api/v1/quantum-entropy"

# Define and submit the request
headers = {"Authorization": f"Bearer {accesstoken}"}
params = {"size": kibData}
response = requests.get(url, headers=headers, params=params)
print(f"Status code: {response.status_code}")

# Display the entropy bytes
bytes_printed = 0
for s in response.json()["random"]:
    for b in base64.decodebytes(s.encode("ascii")):
        # Print the byte as a hexadecimal value (0x00 to 0xFF)
        print(f"{b:02X}", end="")  # Print in hex format for clarity
        bytes_printed += 1
        if bytes_printed >= 1000:
            break  # Stop printing after 1000 bytes
