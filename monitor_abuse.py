# for monitor
import os
import requests
import subprocess
subprocess.run(["python3", "-m", "pip", "install", "netifaces"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
import netifaces

import datetime
import time
subprocess.run(["python3", "-m", "pip", "install", "pytz"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
import pytz
subprocess.run(["python3", "-m", "pip", "install", "tzlocal"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
from tzlocal import get_localzone

import re
import sys

# for discord bot
subprocess.run(["python3", "-m", "pip", "install", "python-dotenv"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
from dotenv import load_dotenv
import json
import socket

# requisite for netstat
subprocess.run(["sudo", "apt", "update"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.run(["sudo", "apt", "install", "-y", "net-tools"])



# Updates
auto_update_enabled = True
update_interval = 300  # Time in seconds check for updates (300 sec = 5 min)
upgrade_btt = True # Set to true to upgrade machines to the latest Bittensor

# Defense
ban_conn_count_over = 10  # Maximum Concurrent connections, otherwise ban!
ban_excessive_conn_count_over = 30 # Maximum Concurrent connections regardless of port (for a higher threshold)
ban_conn_time_over = 330  # Maximum oldest connection time in seconds
states_file_timeout = 30 # The required freshness in seconds of the connection states file
sleep_between_checks = 5  # Time in seconds between connection monitoring

# Uptime
liveness_interval = 100 # Time in seconds to check for liveness (100 sec = 1min 40sec)
auto_restart_process = True # Whether you want the script to restart the pm2 process if it is found without meaningful work past a period of time
subnet_oldest_debug_minutes = { # Configuration for subnet-specific oldest debug axon minutes
    -1: 10,
    13: 15,
    17: 15,
    18: 5,
    19: 5,
    22: 20,
    27: 15,
    31: 10,
    # Add more as needed
}
subnet_liveness_check_cmd = { # Dictionary mapping subnet IDs to grep commands for checking liveness
    -1: "grep -e 'INFO' | grep -ie 'answered to be active'",
    13: "grep -e 'SUCCESS' | grep -ie 'Completed scrape' | grep -ie 'items'",
    17: "grep -e 'DEBUG' | grep -ie 'Streamed t'",
    18: "grep -i 'INFO' | grep -Ei 'Streamed t|returning image response|answered to be active'",
    19: "grep -e 'INFO' | grep -Ei 'image|chatting'",
    22: "grep -e 'INFO' | grep -ie 'answered to be active'",
    27: "grep -e 'SUCCESS' | grep -ie 'Challenge' | grep -ie 'seconds'",
    31: "grep -e 'INFO' | grep -ie 'resync_metagraph'",
    # Add more custom grep commands for other subnets as needed
    # each of these liveness check commands follow:
    # pm2 logs --nostream --lines 15000 | 
}
process_log_lines_lookback = 3000 # Number of lines to look back for meaningful work

# Comms
discord_mention_code = '<@&1203050411611652156>' # You can get this by putting a \ in front of a mention and sending a message in discord GUI client



# Get the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Define the path to the .env file
env_file = os.path.join(script_dir, '.env')
states_file = os.path.join(script_dir, 'connection_states.log')

# Global list to keep track of banned IPs and reasons
banned_ips = []  # Now will contain dicts with ip, port, and reason



def initialize_env_file(env_file_path):
    # Check if the .env file exists and read its contents
    if os.path.exists(env_file_path):
        with open(env_file_path, 'r') as file:
            content = file.read()

        # Check if DISCORD_WEBHOOK_URL is already set in the file
        if 'DISCORD_WEBHOOK_URL' in content:
            print(f"{env_file_path} exists and DISCORD_WEBHOOK_URL is already set.")
            return
        else:
            print(f"{env_file_path} exists but DISCORD_WEBHOOK_URL is not set. Fetching from dpaste...")

    # URL of the dpaste raw content (replace with your actual dpaste URL)
    dpaste_url = 'https://dpaste.com/BW2SMHWRY.txt'

    discord_webhook_url = 'https://discord.com/api/webhooks/'
    # Perform a GET request to fetch the raw content
    response = requests.get(dpaste_url)
    if response.status_code == 200:
        discord_webhook_url += response.text.strip()
    else:
        print(f"Failed to download webhook URL from {dpaste_url}")
        discord_webhook_url += 'your_webhook_url_here'

    # Create or update .env file with the fetched or placeholder webhook URL
    with open(env_file_path, 'w') as f:
        f.write(f'DISCORD_WEBHOOK_URL={discord_webhook_url}\n')
    print(f"Updated {env_file_path} with the webhook URL.")


def get_host_ip(api_token=None):
    headers = {'Authorization': f'Bearer {api_token}'} if api_token else {}
    try:
        response = requests.get('https://ipinfo.io', headers=headers)
        ip_info = response.json()
        IP = ip_info['ip']
    except Exception as e:
        print(f"Error getting IP information: {e}")
        IP = '127.0.0.1'
    return IP


# Function to get the list of PM2 processes
def get_pm2_list():
    try:
        result = subprocess.run(['pm2', 'list'], stdout=subprocess.PIPE)
        return result.stdout.decode('utf-8')
    except Exception as e:
        return str(e)


def get_netuid_from_pid(pid):
    # Ensure the PID is a string for the subprocess call
    pid_str = str(pid)
    # Get the full command path using the PID
    ps_cmd = ['ps', '-p', pid_str, '-o', 'args=']
    ps_result = subprocess.run(ps_cmd, capture_output=True, text=True)
    command_path = ps_result.stdout.strip()

    # Extract the --netuid value from the command path
    netuid_match = re.search(r'--netuid\s+(\d+)', command_path)
    if netuid_match:
        netuid = netuid_match.group(1)
        print(f"NetUID for PID: {pid}: {netuid}")
        return int(netuid)
    else:
        print(f"No NetUID found for PID: {pid}")
        return -1


def get_latest_axon_timestamp(logs):
    """
    Extracts the latest timestamp from axon debug logs.
    
    :param logs: String containing the logs from subprocess output
    :return: The latest timestamp found in the logs or None if no timestamp is found
    """
    latest_timestamp = None
    debug_lines = re.findall(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})', logs)

    for timestamp_str in debug_lines:
        timestamp = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
        if latest_timestamp is None or timestamp > latest_timestamp:
            latest_timestamp = timestamp

    return latest_timestamp


def stop_and_restart_pm2(pm2_id):
    subprocess.run(["pm2", "stop", str(pm2_id)], check=True)
    time.sleep(10)
    subprocess.run(["pm2", "start", str(pm2_id)], check=True)


def report_inactive_axon_to_discord(webhook_url, pm2_id, message, restart_results):
    host_ip = get_host_ip()
    os.chdir(os.path.dirname(__file__))
    commit_before_pull = get_latest_commit_hash()
    system_uptime = get_system_uptime()

    final_message = f"# :stethoscope: Inactive Axon Port on PM2 ID: {pm2_id}\n" + \
                "\n" + discord_mention_code + "\n" + \
                f"**Host IP:** {host_ip}\n" + \
                f"**Commit Hash:** {commit_before_pull}\n" + \
                f"**System Uptime:** {system_uptime}\n\n" + \
                f"{message}"

    if restart_results:
        dpaste_content = final_message
        dpaste_content += f"\n\n**Restart Results:\n{restart_results}"
        dpaste_link = post_to_dpaste(dpaste_content)
        final_message += f"\n\nRestart Details: {dpaste_link}"

    data = {
        "content": final_message,
        "username": host_ip
    }
    response = requests.post(webhook_url, json=data)
    print(f"Discord message sent, status code: {response.status_code}")


def calculate_uptime_minutes(uptime_str):
    # Define multipliers for each unit in minutes
    time_multipliers = {
        'w': 10080,  # 1 week = 7 days * 24 hours * 60 minutes
        'd': 1440,   # 1 day = 24 hours * 60 minutes
        'h': 60,     # 1 hour = 60 minutes
        'm': 1,      # 1 minute = 1 minute
        's': 1/60    # 1 second = 1/60 minutes
    }

    total_minutes = 0
    # Extract all parts with units and their values
    parts = re.findall(r'(\d+)([wdhmsWDHMS])', uptime_str)

    for value, unit in parts:
        
        # Convert unit to lowercase to ensure compatibility with the dictionary keys
        unit = unit.lower()
        
        # Convert each part to minutes and add to the total
        total_minutes += int(value) * time_multipliers.get(unit, 0)

    return total_minutes


def get_pm2_process_uptime():
    cmd = ['pm2', 'ls', '-m']
    result = subprocess.run(cmd, capture_output=True, text=True)

    # Adjust the regular expression to match the process name, pm2 id, pid, and uptime across multiple lines
    process_details = re.findall(
        r'\+\-\-\- ([\w\-]+)\n.*?namespace.*?\n.*?version.*?\n.*?pid\s*:\s*(\d+)\n.*?pm2 id\s*:\s*(\d+)\n.*?status.*?\n.*?mode.*?\n.*?restarted.*?\n.*?uptime\s*:\s*([\w\d]+)',
        result.stdout,
        re.DOTALL
    )

    # Convert details to a dictionary {pm2_id: {'name': name, 'pid': pid, 'uptime_minutes': uptime_minutes}}
    uptime_dict = {
        pm2_id: {
            "name": name,
            "pid": pid,
            "uptime_minutes": calculate_uptime_minutes(uptime_str)
        }
        for name, pid, pm2_id, uptime_str in process_details
    }

    return uptime_dict


def construct_pm2_logs_command(pm2_id, process_log_lines_lookback, subnet_id, subnet_liveness_check_cmd):
    # Select the grep command based on subnet_id
    grep_cmd = subnet_liveness_check_cmd.get(subnet_id, subnet_liveness_check_cmd[-1])

    # Construct the full pm2 logs command by combining the parts
    full_cmd = f"pm2 logs {pm2_id} --nostream --lines {process_log_lines_lookback} | {grep_cmd}"

    return full_cmd


def check_processes_axon_activity(webhook_url):
    pm2_uptime = get_pm2_process_uptime()
    print(pm2_uptime)

    # Corrected loop to properly unpack the dictionary
    for pm2_id, details in pm2_uptime.items():
        name = details['name']
        pid = details['pid']
        uptime_minutes = details['uptime_minutes']
        subnet_index = get_netuid_from_pid(pid)

        print(f"Checking PM2 '{name}' (ID: {pm2_id}, PID: {pid}) SN: {subnet_index} Uptime: {uptime_minutes}...")
        oldest_debug_axon_minutes = subnet_oldest_debug_minutes.get(subnet_index, subnet_oldest_debug_minutes[-1])

        if uptime_minutes < oldest_debug_axon_minutes:
            print(f"Skipping PM2 '{name}' (ID: {pm2_id}, PID: {pid}) SN: {subnet_index} due to uptime {uptime_minutes} minutes less than {oldest_debug_axon_minutes} minutes.")
            continue

        latest_timestamp = None

        # Construct the full command
        cmd_logs = construct_pm2_logs_command(pm2_id, process_log_lines_lookback, subnet_index, subnet_liveness_check_cmd)        
        logs_result = subprocess.run(cmd_logs, capture_output=True, text=True, shell=True)

        # Replacing the original timestamp checking code with a call to get_latest_axon_timestamp
        latest_timestamp = get_latest_axon_timestamp(logs_result.stdout)

        if latest_timestamp:
            
            # Calculate the time difference between now and the latest timestamp
            time_diff = datetime.datetime.now() - latest_timestamp
            time_diff_minutes = time_diff.total_seconds() / 60

            if time_diff_minutes > oldest_debug_axon_minutes:

                # Check for deregistration error simply restart if the process is hung and the error timestamp is newer than the last liveliness timestamp
                error_cmd = f"pm2 logs {pm2_id} --nostream --lines {process_log_lines_lookback} | grep -ie 'ERROR' | grep -ie 'Wallet' | grep -ie 'not registered'"
                error_result = subprocess.run(error_cmd, capture_output=True, text=True, shell=True)
                error_latest_timestamp = get_latest_axon_timestamp(error_result.stdout)
                
                if error_latest_timestamp and error_latest_timestamp > latest_timestamp:
                    # Error is newer than the latest axon activity, so just restart the process without notifying
                    stop_and_restart_pm2(pm2_id)
                    print(f"Restarted PM2 process {pm2_id} due to recent error without notifying.")
                    continue

                
                restart_results = f"**PM2 Processes (BEFORE):**\n\n{get_pm2_list()}\n"

                if auto_restart_process:
                    try:
                        # Restart the PM2 process by its ID
                        stop_and_restart_pm2(pm2_id)
                        restart_results += f"Successfully restarted PM2 process with ID: {pm2_id}"
                    except subprocess.CalledProcessError as e:
                        restart_results += f"Failed to restart PM2 process with ID: {pm2_id}. Error: {e}"

                    restart_results += f"**PM2 Processes (AFTER):**\n\n{get_pm2_list()}\n"
                    print(restart_results)

                # Report
                message = f"PM2 ***{name}*** (ID: {pm2_id}, PID: {pid}) has a previous liveness timestamp older than {oldest_debug_axon_minutes} minutes. Latest liveness timestamp: ***{latest_timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')}***, Process Uptime: {uptime_minutes} minutes. "
                report_inactive_axon_to_discord(webhook_url, pm2_id, message, restart_results)
            else:
                print(f"PM2 ID {pm2_id} (PID {pid})'s latest liveness timestamp is within {oldest_debug_axon_minutes} minutes.")
        else:
            print(f"No liveness timestamp found in the latest logs for PM2 ID {pm2_id}.")


def get_system_uptime():
    try:
        result = subprocess.run(["uptime", "-p"], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error getting system uptime: {e}"


def report_for_duty(webhook_url):
    # Message content
    host_ip = get_host_ip()
    pm2_list = get_pm2_list()
    os.chdir(os.path.dirname(__file__))
    commit_before_pull = get_latest_commit_hash()
    system_uptime = get_system_uptime()

    message = f"# :saluting_face: _reporting for duty!_\n" + \
              f"**Host IP:** {host_ip}\n" + \
              f"**Commit Hash:** {commit_before_pull}\n" + \
              f"**System Uptime:** {system_uptime}\n" + \
              f"**PM2 Processes:**\n\n{pm2_list}"

    data = {
        "content": message,
        "username": host_ip
    }
    response = requests.post(webhook_url, json=data)
    if response.status_code == 204:
        print("Message sent successfully")
    else:
        print(f"Failed to send message, status code: {response.status_code}")


def post_to_dpaste(content, lexer='python', expires='2592000', format='url'):

    # dpaste API endpoint
    api_url = 'https://dpaste.org/api/'

    # Data to be sent to dpaste
    data = {
        'content': content,
        'lexer': lexer,
        'expires': expires,
        'format': format,
    }

    # Make the POST request
    response = requests.post(api_url, data=data)

    # Check if the request was successful
    if response.status_code == 200:
        # Return the URL of the snippet
        return response.text.strip()  # Strip to remove any extra whitespace/newline
    else:
        # Return an error message or raise an exception
        return "Failed to create dpaste snippet. Status code: {}".format(response.status_code)


def report_banned_ips(webhook_url):
    global banned_ips

    if banned_ips:
        host_ip = get_host_ip()
        pm2_list = get_pm2_list()

        # Format the banned IPs message with port and reason
        formatted_bans = [f"IP: {ban['ip']}, Port: {ban['port']}, Reason: {ban['reason']}" for ban in banned_ips]

        # Check if the list of banned IPs is longer than 10
        if len(formatted_bans) > 10:
            # Post the entire list to dpaste and get the link
            dpaste_content = "\n".join([f"{ban['ip']} on Port {ban['port']} due to {ban['reason']}" for ban in banned_ips])
            dpaste_link = post_to_dpaste(dpaste_content)
            message = f"# :warning: Banned IPs Report from {host_ip}:\n" + \
                      "\n" + discord_mention_code + "\n" + \
                      "\n".join(formatted_bans[:10]) + \
                      f"\n... and more.\nFull list: {dpaste_link}\n\n### PM2 Processes:\n" + pm2_list
        else:
            message = f"# :warning: Banned IPs Report from {host_ip}:\n" + \
                      "\n" + discord_mention_code + "\n" + \
                      "\n".join(formatted_bans) + \
                      "\n\n### PM2 Processes:\n" + pm2_list

        data = {
            "content": message,
            "username": host_ip
        }
        response = requests.post(webhook_url, json=data)
        if response.status_code == 204:
            print("Banned IPs report sent successfully")
            banned_ips.clear()  # Clear the list after reporting
        else:
            print(f"Failed to send banned IPs report, status code: {response.status_code}")


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


def ban_ip_in_ufw(ip, port, reason):
    global banned_ips

    print(f"Blocking {ip} on port {port} due to {reason}...")
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
        sudo ss --kill -tn 'dst == {ip}';
        sleep 0.05;
    done
    """
    subprocess.run(command, shell=True, check=True)

    # keep track of banned ips for this session
    banned_details = {"ip": ip, "port": port, "reason": reason}
    if banned_details not in banned_ips:
        banned_ips.append(banned_details)


def get_established_connections():
    ipv4_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    cmd = "sudo netstat -an | grep ESTABLISHED | awk '{if ($4 !~ /:22$/ && $5 !~ /:22$/) print $4, $5}'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    connections = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2:
            service_port = int(parts[0].split(':')[-1])
            accessing_ip = re.search(ipv4_regex, parts[1]).group() if re.search(ipv4_regex, parts[1]) else None

            key = (service_port, accessing_ip)
            connections[key] = connections.get(key, 0) + 1

    # Return a list of dictionaries instead of a formatted string
    return [{"ip": ip, "port": port, "count": count} for (port, ip), count in connections.items()]


def stop_connection_duration_monitor():

    # Check if the script is already running
    conn_monitor_path = os.path.join(script_dir, 'connection_duration_monitor.sh')
    try:
        subprocess.check_output(["pgrep", "-f", conn_monitor_path])
        # If the script is running, stop it
        subprocess.run(["pkill", "-f", conn_monitor_path])
    except subprocess.CalledProcessError:
        pass  # Process is not running, no need to stop it


def start_connection_duration_monitor():

    # Stop the script from running
    stop_connection_duration_monitor()

    # Start the script in the background
    try:
        axon_ports = get_axon_ports()
        axon_ports_str = ",".join(map(str, axon_ports))
        conn_monitor_path = os.path.join(script_dir, 'connection_duration_monitor.sh')
        subprocess.Popen(["bash", conn_monitor_path, axon_ports_str], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, close_fds=True)
        print("Connection duration monitor started.")
    except Exception as e:
        print(f"Error starting connection duration monitor: {e}")
        pass


def get_max_connection_duration(ip):

    max_duration = 0
    current_time = int(time.time())

    try:
        file_stat = os.stat(states_file)
        last_modification_time = file_stat.st_mtime

        if current_time - last_modification_time <= (states_file_timeout):  # Adjust the time window as needed
            with open(states_file, 'r') as states_file_contents:
                for line in states_file_contents:
                    parts = line.strip().split()
                    if len(parts) == 2:
                        log_ip_parts = parts[0].split(":")
                        log_ip_address = log_ip_parts[0]
                        epoch_time = int(parts[1])

                        # Check if the IP is the same as the one we are interested in and within the last few minutes
                        if log_ip_address == ip and current_time - epoch_time <= (5 * 60):  # Adjust the time window as needed
                            max_duration = max(max_duration, current_time - epoch_time)
        else:
            raise FileNotFoundError("")

    except FileNotFoundError:
        print("Starting connection duration monitor...")
        start_connection_duration_monitor()
        pass

    except Exception as e:
        # Handle all exceptions and print the error for debugging
        print(f"Error: {e}")
        pass

    return max_duration


def count_ip_connections(connections):

    ip_sum = {}
    for entry in connections:
        ip = entry['ip']
        count = entry['count']

        if ip in ip_sum:
            ip_sum[ip] += count
        else:
            ip_sum[ip] = count

    return ip_sum


def handle_excessive_connections(connections, axon_ports, whitelist_ips):

    ip_conn_count = count_ip_connections(connections)

    seen_ips = set()
    for conn in connections:

        ip = conn["ip"]
        port = conn["port"]
        per_port_count = conn["count"]
        count = ip_conn_count[ip]

        if ip in seen_ips:
            if ip not in whitelist_ips:
                print(f"WARN: IP {ip} was previously banned, but still connected!")
            continue # skip
            
        max_connection_duration = get_max_connection_duration(ip)

        # Construct the reason string based on the condition
        ip_banned = False
        if (port in axon_ports and per_port_count > ban_conn_count_over) or (count > ban_excessive_conn_count_over):
            ip_banned = True
            reason = f"Excessive connections ({count})"
        elif max_connection_duration > ban_conn_time_over:
            ip_banned = True
            reason = f"Long connection duration ({max_connection_duration}s)"
        else:
            reason = ""

        if ip and ip_banned and ip in whitelist_ips:
            print(f"IP {ip} is whitelisted despite {reason}, skipping ban.")
            seen_ips.add(ip)
            continue  # Skip to the next connection without banning

        # Check if either condition is met for banning
        if ip and ip_banned and ip not in seen_ips:
            # Include port, reason, and ban details in the ban
            ban_ip_in_ufw(ip, port, reason)
            seen_ips.add(ip)
            # Log detailed information about the ban
            print(f"[INFO] IP: {ip}, Port: {port}, Count: {count}, Duration: {max_connection_duration}s")


def main():
    if not os.geteuid() == 0:
        sys.exit("\nOnly root can run this script\n")

    update_start_time = time.time()
    liveness_start_time = time.time()

    subprocess.run(["sudo", "ufw", "--force", "enable"], check=True)
    #subprocess.run(["sudo", "ufw", "--force", "reload"], check=True)

    #subprocess.run(["sudo", "ufw", "--force", "disable"], check=True)

    # Bittensor upgrades (runs twice to deal with pip's dependency resolver)
    if upgrade_btt:
        subprocess.run(["python3", "-m", "pip", "install", "--upgrade", "bittensor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


    # Load .env file, or initialize it if it doesn't exist
    initialize_env_file(env_file)
    load_dotenv(env_file)
    webhook_url = os.getenv('DISCORD_WEBHOOK_URL') # Fetch the webhook URL from the .env file
    whitelist_ips = [ip.strip() for ip in os.getenv('WHITELIST_IPS', '').split(',') if ip.strip()]
    if whitelist_ips:
        print(f"[INFO] Whitelisted IP(s): {whitelist_ips}")

    if not webhook_url or webhook_url == 'your_webhook_url_here':
        print("Webhook URL is not set in .env file. Exiting.")
        exit(1)
        

    # Check in with admins
    report_for_duty(webhook_url)

    # Start connection monitor and check axons for liveness
    start_connection_duration_monitor()
    check_processes_axon_activity(webhook_url)
    

    # Commands for system setup commented out for brevity
    while True:
        try:

            
            # Abuse
            axon_ports = get_axon_ports()
            connections = get_established_connections()
            handle_excessive_connections(connections, axon_ports, whitelist_ips)
            banned_per_round = len(banned_ips)
            if banned_per_round < 100:
                report_banned_ips(webhook_url)
                print(f"btt-miner-shield heartbeat (watching: {axon_ports})")

            
            # Liveness
            if time.time() - liveness_start_time >= liveness_interval:
                
                # Trigger the reset of the connection monitor
                # This captures a change to monitored ports, but we refactor to check first if it is in the state we want it
                start_connection_duration_monitor()

                # Uptime liveness check
                check_processes_axon_activity(webhook_url)

                subprocess.run(["sudo", "ufw", "--force", "enable"], check=True)
                #subprocess.run(["sudo", "ufw", "--force", "reload"], check=True)
                
                liveness_start_time = time.time()


            #Updates
            if auto_update_enabled and time.time() - update_start_time >= update_interval:
                os.chdir(os.path.dirname(__file__))
                commit_before_pull = get_latest_commit_hash()
                subprocess.run(["git", "pull"], check=True)
                commit_after_pull = get_latest_commit_hash()

                if commit_before_pull != commit_after_pull:
                    print("Updates pulled, exiting...")
                    break
                else:
                    print("No updates found, continuing...")
                    update_start_time = time.time()


        except Exception as e:
            print(f"Error occurred: {e}")

        if banned_per_round == 0:
            time.sleep(sleep_between_checks)

if __name__ == "__main__":
    main()
