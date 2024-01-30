import requests
import netifaces
import subprocess
import datetime
import os
import time

# Path for the log file
log_path = os.path.join(os.path.dirname(__file__), 'btt-miner-shield-abuse.log')
# Duration to keep logs (ban duration + 7 days)
log_retention_duration = 14  # Adjust as needed
ban_threshold = 15
sleep_between_checks = 15



def ban_ip_in_ufw(ip):
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
    subprocess.run(["sudo", "ufw", "insert", "1", "deny", "from", ip, "to", "any"], check=True)
    subprocess.run(["sudo", "ufw", "insert", "1", "deny", "to", ip, "from", "any"], check=True)

    command = f"""
    while sudo netstat -an | grep ESTABLISHED | grep -q {ip}; 
    do 
        sudo ss --kill -tn 'dst == {ip}'; 
        sleep 1; 
    done
    """
    subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


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
        if int(count) > ban_threshold and ip not in seen_ips:
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
        # Rewrite the log file if any updates were made
        with open(log_path, 'w') as log_file:
            log_file.writelines(log_entries)


def log_excessive_connections_old(connections):
    seen_ips = set()  # Track seen IPs to avoid duplicates
    for connection in connections.splitlines():
        count, ip = connection.strip().split(None, 1)
        if int(count) > ban_threshold and ip not in seen_ips:
            ban_ip_in_ufw(ip)
            seen_ips.add(ip)
            with open(log_path, 'r+') as log_file:  # Open the file in append mode 'a'
                updated = False
                for line in log_file:
                    log_date, log_ip, _ = line.strip().split("|")
                    if log_ip == ip:
                        log_file.write(f"{datetime.datetime.now()}|{ip}|{count}\n")
                        print(f"[VERBOSE] Updated timestamp for IP: {ip} (count: {count})")  # Verbose message for updated IP
                        updated = True
                        break
                if not updated:
                    log_file.write(f"{datetime.datetime.now()}|{ip}|{count}\n")
                    print(f"[VERBOSE] New IP found and logged: {ip} (count: {count})")  # Verbose message for new IP

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
    while True:
        try:

            # Create the log file if it doesn't exist
            if not os.path.exists(log_path):
                open(log_path, 'a').close()  # Create an empty file

            connections = get_established_connections()
            log_excessive_connections(connections)
            subprocess.run(["sudo", "ufw", "reload"], check=True)
            clean_old_logs()

        except Exception as e:
            print(f"Error occurred: {e}")

        time.sleep(sleep_between_checks)  # Check every 60 seconds (adjust as needed)

if __name__ == "__main__":
    main()
