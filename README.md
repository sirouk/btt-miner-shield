# btt-miner-shield

```bash
apt update && apt install conntrack -y
cd ~
git clone https://github.com/sirouk/btt-miner-shield
cd btt-miner-shield
pm2 start monitor_abuse.py --name btt-miner-shield-protection --interpreter python3
```
