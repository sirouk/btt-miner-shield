import requests
import netifaces
import subprocess
import datetime
import os
import time


# Adjust as needed
log_retention_duration = 14  # Duration to keep logs (ban duration + 7 days)
ban_threshold = 10 # Maximum Concurrent connections, otherwise ban!
sleep_between_checks = 10 # Time in seconds between connection monitoring
update_interval = 300  # Time in seconds check for updates (300 sec = 5 min)
auto_update_enabled = True


# Path for the log file
log_path = os.path.join(os.path.dirname(__file__), 'btt-miner-shield-abuse.log')

def get_latest_commit_hash():
    """Function to get the latest commit hash."""
    result = subprocess.run(["git", "log", "-1", "--format=%H"], capture_output=True, text=True)
    return result.stdout.strip()


def ban_ip_in_ufw(ip):
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
    subprocess.run(["sudo", "ufw", "insert", "1", "deny", "from", ip, "to", "any"], check=True)
    subprocess.run(["sudo", "ufw", "insert", "1", "deny", "to", ip, "from", "any"], check=True)

    #dir_path = os.path.dirname(os.path.realpath(__file__))
    #script_path = os.path.join(dir_path, "block_ip.sh")
    #subprocess.run(["sudo", script_path, ip], check=True)
    
    command = f"""
    while netstat -an | grep ESTABLISHED | grep {ip}; 
    do 
        iptables -A INPUT -s {ip} -j DROP;
        iptables -A OUTPUT -d {ip} -j DROP;
        conntrack -D --orig-src {ip};
        ss --kill -tn 'dst == {ip}'; 
        sleep 1;
    done
    """
    subprocess.run(command, shell=True, check=True)
    #subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def get_established_connections():
    # Run the netstat command and capture its output
    cmd = "netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


def log_excessive_connections(connections):
    seen_ips = set()  # Track seen IPs to avoid duplicates
    file_updated = False
    log_entries = []

    for connection in connections.splitlines():
        count, ip = connection.strip().split(None, 1)
        if int(count) >= ban_threshold and ip not in seen_ips:
            ban_ip_in_ufw(ip)
            seen_ips.add(ip)
            file_updated = True
            with open(log_path, 'r') as log_file:
                log_entries = log_file.readlines()

            with open(log_path, 'w') as log_file:
                updated = False
                for line in log_entries:
                    parts = line.strip().split("|")
                    if len(parts) == 3:
                        log_date, log_ip, _ = parts
                        if log_ip == ip:
                            log_file.write(f"{datetime.datetime.now()}|{ip}|{count}\n")
                            print(f"[VERBOSE] Updated timestamp for IP: {ip} (count: {count})")
                            updated = True
                        else:
                            log_file.write(line)
                    else:
                        log_file.write(line)

                if not updated:
                    log_file.write(f"{datetime.datetime.now()}|{ip}|{count}\n")
                    print(f"[VERBOSE] New IP found and logged: {ip} (count: {count})")

    if file_updated:
        subprocess.run(["sudo", "ufw", "enable"], check=True)
        subprocess.run(["sudo", "ufw", "reload"], check=True)
        # Rewrite the log file if any updates were made
        with open(log_path, 'w') as log_file:
            log_file.writelines(log_entries)


def clean_old_logs():
    with open(log_path, 'r+') as file:
        lines = file.readlines()
        file.seek(0)
        for line in lines:
            log_date = datetime.datetime.strptime(line.split('|')[0], "%Y-%m-%d %H:%M:%S.%f")
            if (datetime.datetime.now() - log_date).days <= log_retention_duration:
                file.write(line)
        file.truncate()


def main():
    start_time = time.time()  # Record the start time
    subprocess.run(["sudo", "apt", "update"], check=True)
    subprocess.run(["sudo", "apt", "install", "-y", "conntrack"], check=True)
    subprocess.run(["sudo", "ufw", "enable"], check=True)
    subprocess.run(["sudo", "ufw", "reload"], check=True)
    
    while True:
        try:
            # Create the log file if it doesn't exist
            if not os.path.exists(log_path):
                open(log_path, 'a').close()  # Create an empty file

            connections = get_established_connections()
            log_excessive_connections(connections)
            print("btt-miner-shield heartbeat")
            clean_old_logs()

            # Check if 5 minutes have passed
            if auto_update_enabled and time.time() - start_time >= update_interval:
                os.chdir(os.path.dirname(__file__))
                
                # Compare git hashes to determine if there was an update
                commit_before_pull = get_latest_commit_hash()
                subprocess.run(["git", "pull"], check=True)
                commit_after_pull = get_latest_commit_hash()

                subprocess.run(["sudo", "ufw", "enable"], check=True)
                subprocess.run(["sudo", "ufw", "reload"], check=True)
                
                if commit_before_pull != commit_after_pull:
                    print("Updates pulled, exiting...")
                    break
                else:
                    print("No updates found, continuing...")
                    # Reset the timer
                    start_time = time.time()
                
        except Exception as e:
            print(f"Error occurred: {e}")

        time.sleep(sleep_between_checks)  # Check every 60 seconds (adjust as needed)


if __name__ == "__main__":
    main()
