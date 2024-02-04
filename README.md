# btt-miner-shield

## NOTE:
This script auto-updates by default. If you prefer not then just modify the monitor_abuse.py file and set `auto_update_enabled = False`.

## CAUTION:
Before you use this script, please make sure you have you have a rule present for SSH to remotely manage your machine, preferably only to your IP(s)!

## Requisites:
```bash
sudo apt update
sudo apt install npm -y
sudo npm install pm2 -g
pm2 update
```

## Installation:
```bash
cd ~
git clone https://github.com/sirouk/btt-miner-shield
cd btt-miner-shield
pm2 start monitor_abuse.py --name btt-miner-shield-protection --interpreter python3
```

## Configuration:

`nano ~/btt-miner-shield/monitor_abuse.py`

```bash
# Adjust as needed
ban_conn_count_over = 5  # Maximum Concurrent connections, otherwise ban!
ban_conn_time_over = 300  # Maximum oldest connection time in seconds
states_file_timeout = 30 # The required freshness of the connection states file
sleep_between_checks = 5  # Time in seconds between connection monitoring
update_interval = 300  # Time in seconds check for updates (300 sec = 5 min)
auto_update_enabled = True
upgrade_btt = True # Set to true to upgrade machines to the latest Bittensor
discord_mention_code = '<@&1234567890987654321>' # You can get this by putting a \ in front of a mention and sending a message in discord GUI client
```


## Watch the output
`pm2 logs btt-miner-shield-protection`

## Force update
`cd ~/btt-miner-shield && git pull && pm2 restart btt-miner-shield-protection && pm2 logs btt-miner-shield-protection`
