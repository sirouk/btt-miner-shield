#!/bin/bash

# Check if at least one argument is given (port number)
if [ $# -eq 0 ]; then
    echo "Usage: $0 port1,port2,..."
    exit 1
fi


# Configuration
# Configuration
IFS=',' read -ra monitor_ports <<< "$1" # Split the first argument into an array based on comma
log_file="$HOME/btt-miner-shield/connection_durations.log"
state_file="$HOME/btt-miner-shield/connection_states.log"
temp_file="${state_file}.tmp"

# Ensure directories exist
mkdir -p "$(dirname "$log_file")"
mkdir -p "$(dirname "$state_file")"

# Initialize or clear log and state files
: > "$log_file"
: > "$state_file"

# Echo starting
echo "Monitoring new connections on ports ${monitor_ports[*]}. Duration will be logged to $log_file."

# Function to capture and log new connections
monitor_connections() {
    for monitor_port in "${monitor_ports[@]}"; do
        (ss -tn state established "sport = :$monitor_port" | grep -vE 'Local|State' | awk '{print $4 " " $5}' | while read -r line; do
            local remote_ip=${line%%:*}
            local remote_port=${line#*:}
            remote_port=${remote_port%% *}

            local conn_id="$remote_ip:$remote_port"
            local current_time=$(date +%s)

            # If the connection is new, log its start time
            if ! grep -qF "$conn_id" "$state_file"; then
                echo "$conn_id $current_time" >> "$state_file"
                echo "Detected new connection: $conn_id"
            fi
        done) &
    done
    wait
}


update_durations() {
    local current_time=$(date +%s)
    local established_connections=$(ss -tn state established)
    local temp_file="${state_file}.tmp"
    
    # Initialize temp file
    : > "$temp_file"

    # Obtain a lock on the state file
    exec 9>>"$state_file"
    if ! flock -n 9; then
        echo "Failed to obtain lock on $state_file"
        return 1
    fi

    while IFS= read -r line; do
        IFS=' ' read -r conn_id start_time <<< "$line"
        local duration=$((current_time - start_time))

        # Check if the connection is still active
        if echo "$established_connections" | grep -q "$conn_id"; then
            # Connection is still active; copy the line to the temp file
            echo "$line" >> "$temp_file"
        else
            # Connection is no longer active; log its duration and do not copy it to the temp file
            local message="Connection $conn_id lasted $duration seconds."
            echo "$message"
            echo "$message" >> "$log_file"
        fi
    done < "$state_file"

    # Move the temp file to the original state file
    mv "$temp_file" "$state_file"

    # Release the lock
    flock -u 9
    exec 9>&-
}



# Main monitoring loop
while true; do
    monitor_connections
    update_durations
    sleep 0.33 # Keep it real
done
