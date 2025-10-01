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
