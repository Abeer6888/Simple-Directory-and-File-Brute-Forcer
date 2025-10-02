## Simple Directory and File Brute-Forcer

## Objective

The objective of this project is to build a command-line tool in python that attempts to discover hidden or unlinked directories and files on a target web server. It does this by reading a provided wordlist (a file containing common names) and sending a series of HTTP requests to check if those paths exist, thus mimicking an attacker's reconnaissance phase.

### Skills Learned
- Web Protocol Interaction (HTTP): Understanding how to send GET requests and interpret HTTP status codes (especially 200 OK, 301/302 Redirection, and 404 Not Found).
- External Library Usage: Using the popular requests library for robust and easy HTTP communication.
- File Input/Output (I/O): Learning how to efficiently read and process large wordlists from a file.
- Concurrency/Performance: Utilizing multi-threading (with concurrent.futures) to perform many checks quickly without getting blocked waiting for server responses.
- Robust Error Handling: Handling common web-related errors like connection timeouts, DNS resolution failures, and connection resets.
- Web Reconnaissance: Understanding the technique of content discovery (or web fuzzing), which is crucial for identifying an application's attack surface.

### Tools Used
The primary programming language used is python

- requests module: used to make simple HTTP requests.
- argparse module: used to parse command line arguments.
- concurrent.futures module: used to manage a pool of threads.

## Steps
the step-by-step development process for the dir_fuzzer.py tool:
- Environment Setup: Install the external requests library.
- Define the Brute-Forcing Logic: Create a core function (check_path) that takes a URL, appends a path (from the wordlist), and sends an HTTP GET request.
- Implement Status Code Checking: The core function must check the HTTP response code to determine if the path is genuinely found (e.g., 200) or not (e.g., 404).
- Wordlist Loading: Create a function to safely load potential paths from the specified file.
- Handle Command-Line Arguments: Use argparse to define the target URL and the wordlist file path.
- Implement Concurrency: Use a ThreadPoolExecutor to handle hundreds or thousands of requests simultaneously to complete the scan quickly.
- Create the Main Execution Flow: Tie all components together, manage the wordlist processing, and print results clearly.

### The Code
```python
import requests
import argparse
from concurrent.futures import ThreadPoolExecutor
import time
import sys

# --- Configuration ---
TIMEOUT = 5  # Request timeout in seconds
MAX_WORKERS = 50 # Maximum number of threads for concurrent requests

# --- Core Functions ---

def load_wordlist(wordlist_path):
    """Loads paths from the wordlist file."""
    try:
        with open(wordlist_path, 'r') as f:
            # Strip whitespace and ignore empty lines/comments
            words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return words
    except FileNotFoundError:
        print(f"Error: Wordlist file not found at '{wordlist_path}'")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading wordlist: {e}")
        sys.exit(1)

def check_path(base_url, path):
    """
    Constructs a URL, sends a GET request, and checks the HTTP status code.
    """
    # Ensure base_url ends with a slash for clean concatenation
    if not base_url.endswith('/'):
        base_url += '/'
        
    full_url = base_url + path
    
    try:
        # Use the 'requests' library to send a GET request
        response = requests.get(full_url, timeout=TIMEOUT, allow_redirects=True)
        
        # Check for successful discovery status codes
        # 200: OK (File/Directory found)
        # 301/302: Redirect (Directory/File moved, still counts as discovered)
        if response.status_code in [200, 301, 302]:
            print(f"✅ Found! Code {response.status_code:<3}: {full_url}")
        # 403: Forbidden (Indicates the path exists but access is denied)
        elif response.status_code == 403:
            print(f"⚠️ Forbidden Code {response.status_code:<3}: {full_url}")
            
    except requests.exceptions.Timeout:
        # Request took too long to complete
        # print(f"⏳ Timeout on {full_url}") # Uncomment for verbose output
        pass
    except requests.exceptions.RequestException as e:
        # Catch other network/connection issues (DNS error, connection reset)
        # print(f"❌ Error connecting to {full_url}: {e}") # Uncomment for verbose output
        pass
    except Exception as e:
        # Catch unexpected errors
        # print(f"⚠️ Unexpected error on {full_url}: {e}")
        pass

# --- Main Execution ---

def main():
    """
    Handles command-line arguments and orchestrates the fuzzing process.
    """
    
    # 1. Setup Argument Parser
    parser = argparse.ArgumentParser(
        description="A simple, multi-threaded Directory and File Fuzzer (Dirbuster).",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        '-u', '--url', 
        required=True, 
        help="Target URL (e.g., http://testphp.vulnweb.com or https://example.com)"
    )
    
    parser.add_argument(
        '-w', '--wordlist', 
        required=True, 
        help="Path to the wordlist file (e.g., common.txt)"
    )

    args = parser.parse_args()
    
    target_url = args.url
    wordlist_path = args.wordlist
    
    # 2. Load Wordlist
    paths_to_check = load_wordlist(wordlist_path)

    print(f"\n🚀 Starting content discovery on target: {target_url}")
    print(f"   Using {len(paths_to_check)} words from wordlist: {wordlist_path}\n")
    start_time = time.time()
    
    # 3. Execute Scan with Thread Pool
    # ThreadPoolExecutor allows for concurrent execution of the check_path function
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all check jobs to the executor
        # executor.submit(function, arg1, arg2, ...)
        for path in paths_to_check:
            executor.submit(check_path, target_url, path)
    
    end_time = time.time()
    
    print(f"\n✅ Fuzzing finished in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
```

### Explanation and Outcome
The script requires two command-line arguments:

-u or --url: The target website's base URL.

-w or --wordlist: The path to your wordlist file.
the excution command is :
python dir_fuzzer.py -u [TARGET_URL] -w [WORDLIST_FILE]

The script will begin printing output to the terminal, showing which paths returned success codes (200, 301, 302) or a Forbidden code (403)

The outcome is a concise list of web paths that could potentially be used for further penetration testing, demonstrating project's ability to perform reconnaissance on a target web application.


<img width="1017" height="227" alt="fuzzer" src="https://github.com/user-attachments/assets/1e1711c0-a970-429a-9ce3-2358c5f7d39c" />

Ref 1:fuzzer outcome with 5 directories and files


<img width="1037" height="215" alt="fuzzer12" src="https://github.com/user-attachments/assets/db9b749f-cc54-40bd-86ee-3cd53f095c09" />

Ref 2:fuzzer outocme with 12 directories and files

### Meaning of the results 
| status code | text | meaning | what it means in security |
| :--- | :--- | :--- | :--- |
| 200 | found | OK/Success. The path (directory or file) exists and the server served its content successfully. |Directly exposes a resource. If it's admin, that's a login page. If it's a file, it's accessible. |
| 301/302 | found | Redirection. The path exists, but the server told the client to look at a different URL. | Confirms the resource exists, even if it's been moved or redirected. |
| 403 | forbidden |Access Denied. The path exists, but the server actively blocked the request | A key finding! It confirms the existence of a sensitive resource (like a .env file or configuration directory) that the developers tried to hide or protect. |
| 404 | no output | Not Found. The path does not exist. |  The script is designed to be quiet for these codes to keep the output clean, as they are the intended "failures."|
