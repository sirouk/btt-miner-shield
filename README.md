# btt-miner-shield

## NOTE:
This script auto-updates by default. If you prefer not then just modify the monitor_abuse.py file and set `auto_update_enabled = False`.

## CAUTION:
Before you use this script, please make sure you have you have a rule present for SSH to remotely manage your machine, preferably only to your IP(s)!

## Requisites:
```bash
sudo apt update
sudo apt install jq npm -y
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
log_retention_duration = 30  # Duration to keep logs (ban duration + 7 days)
ban_threshold = 7 # Maximum Concurrent connections, otherwise ban!
sleep_between_checks = 7 # Time in seconds between connection monitoring
update_interval = 420  # Time in seconds check for updates (420 sec = 7 min)
auto_update_enabled = True
```


## Watch the output
`pm2 logs btt-miner-shield-protection`

## Force update
`cd ~/btt-miner-shield && git pull && pm2 restart btt-miner-shield-protection && pm2 logs btt-miner-shield-protection`
