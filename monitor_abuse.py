import subprocess
import datetime
import os
import time

# Path for the log file
log_path = os.path.join(os.path.dirname(__file__), 'btt-miner-shield-abuse.log')
# Duration to keep logs (ban duration + 7 days)
log_retention_duration = 14  # Adjust as needed
ban_threshold = 20
sleep_between_checks = 15

def ban_ip_in_ufw(ip):
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)

def get_established_connections():
    # Run the netstat command and capture its output
    cmd = "netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout

def log_excessive_connections(connections):
    seen_ips = set()  # Track seen IPs to avoid duplicates
    for connection in connections.splitlines():
        count, ip = connection.strip().split(None, 1)
        if int(count) > ban_threshold and ip not in seen_ips:
            seen_ips.add(ip)
            with open(log_path, 'r+') as log_file:
                lines = log_file.readlines()
                log_file.seek(0)
                updated = False
                for line in lines:
                    log_date, log_ip, _ = line.strip().split("|")
                    if log_ip == ip:
                        log_file.write(f"{datetime.datetime.now()}|{ip}|{count}\n")
                        updated = True
                        break
                if not updated:
                    log_file.write(f"{datetime.datetime.now()}|{ip}|{count}\n")
                log_file.truncate()

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
            clean_old_logs()

            with open(log_path, 'r') as log_file:
                for line in log_file:
                    _, ip, _ = line.strip().split("|")
                    ban_ip_in_ufw(ip)
        except Exception as e:
            print(f"Error occurred: {e}")

        time.sleep(sleep_between_checks)  # Check every 60 seconds (adjust as needed)

if __name__ == "__main__":
    main()
