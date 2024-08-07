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
```

## Configuration:

`nano ~/btt-miner-shield/monitor_abuse.py`

Adjust as needed:
```bash
# Updates
auto_update_enabled = True
update_interval = 300  # Time in seconds check for updates (300 sec = 5 min)
upgrade_btt = True # Set to true to upgrade machines to the latest Bittensor

# Defense
ban_conn_count_over = 3  # Maximum Concurrent connections, otherwise ban!
ban_excessive_conn_count_over = 10 # Maximum Concurrent connections regardless of port (for a higher threshold)
ban_conn_time_over = 330  # Maximum oldest connection time in seconds
states_file_timeout = 30 # The required freshness in seconds of the connection states file
sleep_between_checks = 5  # Time in seconds between connection monitoring

# Uptime
auto_restart_process = True # Whether you want the script to restart the pm2 process if it is found without meaningful work past a period of time
subnet_oldest_debug_minutes = { # Configuration for subnet-specific oldest debug axon minutes
    -1: 10,
    13: 25,
    22: 20,
    # Add more as needed
}
subnet_liveness_check_cmd = { # Dictionary mapping subnet IDs to grep commands for checking liveness
    -1: "grep -e 'DEBUG' | grep -e 'axon' | grep -e '-->' | grep -v '| 404 |'",
    24: "grep -e 'INFO' | grep -ie 'Succes' | grep -ie 'fully' | grep -ie 'transmitted'",
    # Add more custom grep commands for other subnets as needed
    # use this for testing time frames: pm2 logs --nostream --lines 15000 | grep -e 'DEBUG' | grep -e 'axon' | grep -e '-->' | grep -v '| 404 |'
}
process_log_lines_lookback = 1000 # Number of lines to look back for meaningful work

# Comms
discord_mention_code = '<@&0123456789876543210>' # You can get this by putting a \ in front of a mention and sending a message in the discord GUI client
```

## Env Var Config:
```bash
cp ~/btt-miner-shield/.env.sample ~/btt-miner-shield/.env
nano ~/btt-miner-shield/.env
# edit for your discord webhook and desired IP whitelist (if any)
```


## Startup:
```bash
pm2 start monitor_abuse.py --name btt-miner-shield-protection --interpreter python3 && pm2 save
```

## Optionally startup w/default netuid:
Use this when the running process does not indicate netuid.
```bash
pm2 start monitor_abuse.py --name btt-miner-shield-protection --interpreter python3 -- --netuid 19 && pm2 save
```

## Watch the output
`pm2 logs btt-miner-shield-protection`

## Force update
`cd ~/btt-miner-shield && git pull && pm2 restart btt-miner-shield-protection && pm2 save && pm2 logs btt-miner-shield-protection`
