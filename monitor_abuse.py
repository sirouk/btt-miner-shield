# for monitor
import requests
import netifaces
import subprocess
import datetime
import os
import time
import re
import sys

# for discord bot
subprocess.run(["python3", "-m", "pip", "install", "python-dotenv"])
from dotenv import load_dotenv
import json
import socket

# Global list to keep track of banned IPs
banned_ips = []

# Adjust as needed
ban_threshold = 2  # Maximum Concurrent connections, otherwise ban!
connection_threshold = 120  # Maximum oldest connection time in seconds
sleep_between_checks = 5  # Time in seconds between connection monitoring
update_interval = 420  # Time in seconds check for updates (420 sec = 7 min)
auto_update_enabled = True
upgrade_btt = True # Set to true to upgrade machines to the latest bittensor


# Get the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Define the path to the .env file
env_file = os.path.join(script_dir, '.env')


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


def get_host_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


# Function to get the list of PM2 processes
def get_pm2_list():
    try:
        result = subprocess.run(['pm2', 'list'], stdout=subprocess.PIPE)
        return result.stdout.decode('utf-8')
    except Exception as e:
        return str(e)


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
              f"**PM2 Processes:**\n{pm2_list}"

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
    """
    Post content to dpaste and return the URL of the snippet.

    :param content: The content to paste.
    :param lexer: The syntax highlighting option (default: python).
    :param expires: Expiration time for the snippet (default: 2592000 seconds = 1 month).
    :param format: The format of the API response (default: url).
    :return: The URL of the created dpaste snippet.
    """
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

        # Check if the list of banned IPs is longer than 10
        if len(banned_ips) > 10:
            # Post the entire list to dpaste and get the link
            dpaste_link = post_to_dpaste("\n".join(banned_ips))
            message = f"# :warning: Banned IPs Report from {host_ip}:\n" + \
                      "\n".join(banned_ips[:10]) + \
                      f"\n... and more.\nFull list: {dpaste_link}\n\n### PM2 Processes:\n" + pm2_list
        else:
            message = f"# :warning: Banned IPs Report from {host_ip}:\n" + \
                      "\n".join(banned_ips) + \
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


def ban_ip_in_ufw(ip):
    global banned_ips
            
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
        sleep 0.25;
    done
    """
    subprocess.run(command, shell=True, check=True)

    # keep track of banned ips for this session
    if ip not in banned_ips:
        banned_ips.append(ip)


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
    for connection in connections.splitlines():
        count, ip = connection.strip().split(None, 1)
        #max_connection_duration = get_max_connection_duration(ip)
        max_connection_duration = 0
        #if (int(count) > ban_threshold or max_connection_duration > connection_threshold) and ip not in seen_ips:
        if int(count) > ban_threshold and ip not in seen_ips:
            ban_ip_in_ufw(ip)  # Uncomment if you want to enable IP banning again
            seen_ips.add(ip)
            file_updated = True
            print(f"[INFO] IP: {ip}, Count: {count}, Duration: {max_connection_duration}s")


    if file_updated:
        subprocess.run(["sudo", "ufw", "--force", "enable"], check=True)
        subprocess.run(["sudo", "ufw", "--force", "reload"], check=True)


def main():
    if not os.geteuid() == 0:
        sys.exit("\nOnly root can run this script\n")

    start_time = time.time()

    subprocess.run(["sudo", "apt", "update"], check=True)
    subprocess.run(["sudo", "apt", "install", "-y", "conntrack"], check=True)
    subprocess.run(["sudo", "ufw", "--force", "enable"], check=True)
    subprocess.run(["sudo", "ufw", "--force", "reload"], check=True)

    # Bittensor upgrades (runs twice to deal with pip's dependency resolver)
    if upgrade_btt:
        subprocess.run(["python3", "-m", "pip", "install", "--upgrade", "bittensor"], check=True)
        subprocess.run(["python3", "-m", "pip", "install", "--upgrade", "bittensor"], check=True)
                    


    # Load .env file, or initialize it if it doesn't exist
    initialize_env_file(env_file)
    load_dotenv(env_file)
    webhook_url = os.getenv('DISCORD_WEBHOOK_URL') # Fetch the webhook URL from the .env file

    if not webhook_url or webhook_url == 'your_webhook_url_here':
        print("Webhook URL is not set in .env file. Exiting.")
        exit(1)

    # Check in with admins
    report_for_duty(webhook_url)


    # Commands for system setup commented out for brevity
    while True:
        try:

            axon_ports = get_axon_ports()
            connections = get_established_connections(axon_ports)
            handle_excessive_connections(connections)
            report_banned_ips(webhook_url)
            print(f"btt-miner-shield heartbeat (watching: {axon_ports})")

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
