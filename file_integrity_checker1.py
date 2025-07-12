import os
import hashlib
import json
import time

MONITOR_FOLDER = "E\\MSCIT\\Internship\\test"
HASH_FILE = "file_hashes.json"
CHECK_INTERVAL=10

def calculate_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
        # return sha256.hexdigest()
    except FileNotFoundError:
        # print(f"Error reading {filepath}: {e}")
        return None
    return sha256.hexdigest()

def scan_folder(folder):
    file_hashes = {}
    for root, dirs, files in os.walk(folder):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = calculate_hash(filepath)
            if file_hash:
                file_hashes[filepath] = file_hash
    return file_hashes

def load_baseline():
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, "r")as f:
            return json.load(f)
    return {}    
    

def save_baseline(baseline):
    
    with open(HASH_FILE, "w") as f:
        json.dump(baseline, f, indent=2)
        print("Hashes saved successfully!")

def monitor():
    baseline = load_baseline()
    print("Initial baseline loaded")
    while True:
        current_hashes = scan_folder(MONITOR_FOLDER)
        changes_detected = True

        for filepath, filehash in current_hashes.items():
            if filepath not in baseline:
                print("New file".format(filepath))
                changes_detected = True
            elif baseline[filepath] != filehash:
                print("Modified".format(filepath)) 
                changes_detected = True

        for filepath in baseline:
            if filepath not in current_hashes:
                print("Deleted".format(filepath))
                changes_detected = True

        if changes_detected:
            print("Changes detected. Updating baselines..")    
            save_baseline(current_hashes)
            baseline= current_hashes.copy()
        else:
            print("No change detected")

        print("Scan completed.")
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    print("Monitoring for changes...".format(MONITOR_FOLDER))
    monitor()
