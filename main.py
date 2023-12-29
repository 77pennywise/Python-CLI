import hashlib
import base64
import os
import subprocess
import mimetypes
from dns.resolver import Resolver
import socket
import requests

def menu():
    print("Select an option:")
    print("1. Generate SHA-256 hash")
    print("2. Perform Base64 encoding/decoding")
    print("3. Generate secure random number")
    print("4. Resolve domain to IP addresses")
    print("5. Find MIME Type")
    print("6. Port Scan")
    print("7. Subdomain Enumeration")
    print("8. Identify Web Technology")

def hash_sha256(data):
    hashed = hashlib.sha256(data.encode()).hexdigest()
    print("SHA-256 Hash:", hashed)

def base64_encode_decode(data):
    print("Select an option:")
    print("1. Encode to Base64")
    print("2. Decode from Base64")
    choice = input().strip()

    if choice == "1":
        encoded = base64.b64encode(data.encode()).decode()
        print("Encoded data:", encoded)
    elif choice == "2":
        try:
            decoded = base64.b64decode(data).decode()
            print("Decoded data:", decoded)
        except Exception as e:
            print("Error decoding data:", e)
    else:
        print("Invalid option.")

def generate_secure_random_number():
    secure_random_number = os.urandom(16).hex()
    print("Secure random number:", secure_random_number)

def resolve_domain(domain):
    try:
        resolver = Resolver()
        answers = resolver.resolve(domain)
        print("IP addresses associated with the domain:")
        for rdata in answers:
            print(rdata.address)
    except Exception as e:
        print("Error resolving domain:", e)

def guess_mime_type(file_path):
    try:
        mime_type, _ = mimetypes.guess_type(file_path)
        print("Guessed MIME type:", mime_type)
    except Exception as e:
        print("Error guessing MIME type:", e)

def port_scan():
    target = input("Enter the target IP address to scan: ").strip()
    try:
        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((target, port))
            if result == 0:
                print("Port {}: Open".format(port))
            sock.close()
    except KeyboardInterrupt:
        print("Port scanning stopped.")
    except Exception as e:
        print("Error during port scan:", e)

def enumerate_subdomains(domain, wordlist_path):
    try:
        resolver = Resolver()
        with open(wordlist_path, 'r') as wordlist_file:
            wordlist = wordlist_file.readlines()
            for word in wordlist:
                subdomain = word.strip() + '.' + domain
                try:
                    answers = resolver.resolve(subdomain)
                    print(f"Found subdomain: {subdomain}")
                    for rdata in answers:
                        print(f"IP Address: {rdata.address}")
                except:
                    pass  
    except Exception as e:
        print("Error during subdomain enumeration:", e)

def identify_web_technology(url):
    try:
        response = requests.get(url)
        headers = response.headers
        server = headers.get('Server')
        x_powered_by = headers.get('X-Powered-By')
        
        if server:
            print("Server:", server)
        else:
            print("Server information not found.")
        
        if x_powered_by:
            print("X-Powered-By:", x_powered_by)
        else:
            print("X-Powered-By information not found.")
        
    except requests.exceptions.RequestException as e:
        print("Error identifying web technology:", e)


def main():
    menu()
    option = input("Select an option: ").strip()

    if option == "1":
        data = input("Enter the data to hash: ").strip()
        hash_sha256(data)
    elif option == "2":
        data = input("Enter the data to encode/decode: ").strip()
        base64_encode_decode(data)
    elif option == "3":
        generate_secure_random_number()
    elif option == "4":
        domain = input("Enter the domain to resolve: ").strip()
        resolve_domain(domain)
    elif option == "5":
        file_path = input("Enter the file path: ").strip()
        guess_mime_type(file_path)
    elif option == "6":
        port_scan()
    elif option == "7":
        domain = input("Enter the domain to enumerate subdomains: ").strip()
        wordlist_path = input("Enter the path to the wordlist: ").strip()
        enumerate_subdomains(domain, wordlist_path)
    elif option == "8":
        target_url = input("Enter the target URL for web technology identification: ").strip()
        identify_web_technology(target_url)
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
