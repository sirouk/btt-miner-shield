# btt-miner-shield

## NOTE:
This script auto-updates by default. If you prefer not then just modify the monitor_abuse.py file and set `auto_update_enabled = False`.

## CAUTION:
Before you use this script, please make sure you have you have a rule present for SSH to remotely manage your machine, preferably only to your IP(s)!

```bash
cd ~
git clone https://github.com/sirouk/btt-miner-shield
cd btt-miner-shield
pm2 start monitor_abuse.py --name btt-miner-shield-protection --interpreter python3
```

## Watch the output
`pm2 logs btt-miner-shield-protection`
