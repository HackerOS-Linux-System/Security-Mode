# module_runner.py
# This is the module runner for Security Mode, written in Python.
# It runs pen-test modules as unprivileged processes inside a sandbox.
# Communication is done via JSON files in /tmp/Security-Mode/.
# Assume it's invoked by the core, reads "module_command.json", runs the module, writes "module_output.json".

import json
import os
import subprocess
import sys
import time

TMP_DIR = "/tmp/Security-Mode"

def ensure_tmp_dir():
    if not os.path.exists(TMP_DIR):
        os.makedirs(TMP_DIR, exist_ok=True)

def read_json(filename):
    ensure_tmp_dir()
    path = os.path.join(TMP_DIR, filename)
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return None

def write_json(filename, data):
    ensure_tmp_dir()
    path = os.path.join(TMP_DIR, filename)
    with open(path, 'w') as f:
        json.dump(data, f)
    print(f"Wrote JSON to {path}")

def run_module(module, args, profile):
    # Based on profile, apply some restrictions (simulated here, actual sandbox by core)
    env = os.environ.copy()
    if profile == "monitor-only":
        # Simulate monitor-only: don't actually run, just log
        return {"stdout": "", "stderr": "Monitor-only mode: no execution", "returncode": 0}
    elif profile == "bezpieczny":
        # Safe mode: add some env vars or limits
        env["SAFE_MODE"] = "1"
    # Agresywny: full run

    # Assume module is an executable path or command
    # For pen-test modules, they could be scripts like nmap, etc.
    try:
        # Run with timeout, capture output
        result = subprocess.run([module] + args, capture_output=True, text=True, timeout=600, env=env, check=False)
        output = {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        output = {"error": "Timeout expired"}
    except Exception as e:
        output = {"error": str(e)}

    return output

def main():
    # Optionally, loop to process multiple, but for simplicity, process once
    command = read_json("module_command.json")
    if not command:
        print("No module command found.")
        sys.exit(1)

    module = command.get("module")
    args = command.get("args", [])
    profile = command.get("profile", "bezpieczny")

    if not module:
        print("No module specified.")
        sys.exit(1)

    print(f"Running module: {module} with args: {args} under profile: {profile}")

    output = run_module(module, args, profile)
    output["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    write_json("module_output.json", output)

    # Optionally, remove command file
    os.remove(os.path.join(TMP_DIR, "module_command.json"))

if __name__ == "__main__":
    main()
