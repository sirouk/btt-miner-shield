import requests
import netifaces
import subprocess
import datetime
import os
import time
import re
import sys

# Adjust as needed
log_retention_duration = 30  # Duration to keep logs (ban duration + 7 days)
ban_threshold = 2  # Maximum Concurrent connections, otherwise ban!
connection_threshold = 120  # Maximum oldest connection time in seconds
sleep_between_checks = 5  # Time in seconds between connection monitoring
update_interval = 420  # Time in seconds check for updates (420 sec = 7 min)
auto_update_enabled = True

# Path for the log file
log_path = os.path.join(os.path.dirname(__file__), 'btt-miner-shield-abuse.log')

def get_latest_commit_hash():
    """Function to get the latest commit hash."""
    result = subprocess.run(["git", "log", "-1", "--format=%H"], capture_output=True, text=True)
    return result.stdout.strip()


def get_axon_ports():
    cmd = "ps aux | grep axon.port"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    ports = set()

    for line in result.stdout.splitlines():
        if 'axon.port' in line:
            match = re.search(r'--axon\.port\s+(\d+)', line)
            if match:
                ports.add(int(match.group(1)))

    return list(ports)


def ban_ip_in_ufw(ip):
    print(f"Blocking {ip}...")
    ip_pattern = f" {ip}( |:|$)"
    command = f"""
    sudo iptables -I INPUT -s {ip} -j DROP;
    sudo iptables -I OUTPUT -d {ip} -j DROP;

    sudo ufw delete deny from {ip};
    sudo ufw delete deny to {ip};
    sudo ufw insert 1 deny from {ip} to any;
    sudo ufw insert 2 deny to {ip} from any;

    while sudo netstat -an | grep ESTABLISHED | grep -Eq '{ip_pattern}';
    do
        sudo conntrack -D --orig-src {ip};
        sudo ss --kill -tn 'dst == {ip}';
    done
    """
    subprocess.run(command, shell=True, check=True)


def get_established_connections(axon_ports):
    ipv4_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    cmd = "sudo netstat -an | grep ESTABLISHED | awk '{if ($4 !~ /:22$/ && $5 !~ /:22$/) print $4, $5}'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    connections = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2:
            service_port = int(parts[0].split(':')[-1])
            accessing_ip = re.search(ipv4_regex, parts[1]).group() if re.search(ipv4_regex, parts[1]) else None
            if service_port in axon_ports and service_port >= 1000 and accessing_ip:  # Filter for service ports >= 1000
                connections[(service_port, accessing_ip)] = connections.get((service_port, accessing_ip), 0) + 1
    formatted_result = "\n".join(f"{count} {ip}" for (port, ip), count in connections.items())
    return formatted_result


def parse_ps_etime(etime):
    """Parse the elapsed time format from ps and return total seconds."""
    parts = etime.split('-')
    days = 0
    if len(parts) == 2:
        days = int(parts[0])
        time_part = parts[1]
    else:
        time_part = parts[0]

    h, m, s = [int(i) for i in time_part.split(':')]
    return days * 86400 + h * 3600 + m * 60 + s


# THIS: does not work becuase it grabs the time that the connection with the main socket was established, no IP specific
def get_max_connection_duration(ip):
    cmd = f"lsof -t -i @{ip} | xargs -I {{}} ps --no-headers -o 'pid,etime' -p {{}} | sort -k2,2r | head -n1"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    max_duration = 0
    if result.stdout.strip():
        _, etime = result.stdout.strip().split(maxsplit=1)
        max_duration = parse_ps_etime(etime)
    return max_duration


def handle_excessive_connections(connections):
    seen_ips = set()
    file_updated = False
    log_entries = []

    for connection in connections.splitlines():
        count, ip = connection.strip().split(None, 1)
        max_connection_duration = get_max_connection_duration(ip)
        #if (int(count) > ban_threshold or max_connection_duration > connection_threshold) and ip not in seen_ips:
        if int(count) > ban_threshold and ip not in seen_ips:
            ban_ip_in_ufw(ip)  # Uncomment if you want to enable IP banning again
            seen_ips.add(ip)
            file_updated = True
            print(f"[INFO] IP: {ip}, Count: {count}, Duration: {max_connection_duration}s")
            log_found = False

            with open(log_path, 'r+') as log_file:
                log_entries = log_file.readlines()
                log_file.seek(0)

                for line in log_entries:
                    parts = line.strip().split("|")
                    if len(parts) >= 3 and parts[1] == ip:
                        # Update the existing log entry with new count and max connection duration
                        log_file.write(f"{datetime.datetime.now()}|{ip}|{count}|{max_connection_duration}\n")
                        log_found = True
                    else:
                        log_file.write(line + "\n")

                if not log_found:
                    # Add a new log entry
                    log_file.write(f"{datetime.datetime.now()}|{ip}|{count}|{max_connection_duration}\n")

                log_file.truncate()  # Truncate the file to the current position

    if file_updated:
        subprocess.run(["sudo", "ufw", "--force", "enable"], check=True)
        subprocess.run(["sudo", "ufw", "--force", "reload"], check=True)

def clean_old_logs():
    with open(log_path, 'r+') as file:
        lines = file.readlines()
        file.seek(0)
        for line in lines:
            # Skip empty lines or lines not starting with a date
            if line.strip() == '' or not line[0].isdigit():
                continue
            try:
                log_date = datetime.datetime.strptime(line.split('|')[0], "%Y-%m-%d %H:%M:%S.%f")
                if (datetime.datetime.now() - log_date).days <= log_retention_duration:
                    file.write(line)
            except ValueError as e:
                print(f"Error parsing line: {line}. Error: {e}")
                # Optionally handle or log the error further here
        file.truncate()


def main():
    if not os.geteuid() == 0:
        sys.exit("\nOnly root can run this script\n")

    start_time = time.time()

    subprocess.run(["sudo", "apt", "update"], check=True)
    subprocess.run(["sudo", "apt", "install", "-y", "conntrack"], check=True)
    subprocess.run(["sudo", "ufw", "--force", "enable"], check=True)
    subprocess.run(["sudo", "ufw", "--force", "reload"], check=True)

    # Commands for system setup commented out for brevity
    while True:
        try:
            if not os.path.exists(log_path):
                open(log_path, 'a').close()

            axon_ports = get_axon_ports()
            connections = get_established_connections(axon_ports)
            handle_excessive_connections(connections)
            print(f"btt-miner-shield heartbeat (watching: {axon_ports})")
            clean_old_logs()

            if auto_update_enabled and time.time() - start_time >= update_interval:
                os.chdir(os.path.dirname(__file__))
                commit_before_pull = get_latest_commit_hash()
                subprocess.run(["git", "pull"], check=True)
                commit_after_pull = get_latest_commit_hash()

                if commit_before_pull != commit_after_pull:
                    print("Updates pulled, exiting...")
                    break
                else:
                    print("No updates found, continuing...")
                    start_time = time.time()

                subprocess.run(["sudo", "ufw", "--force", "enable"], check=True)
                subprocess.run(["sudo", "ufw", "--force", "reload"], check=True)

        except Exception as e:
            print(f"Error occurred: {e}")

        time.sleep(sleep_between_checks)

if __name__ == "__main__":
    main()
