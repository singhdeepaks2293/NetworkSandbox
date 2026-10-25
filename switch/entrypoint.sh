#!/bin/sh
# Start the switch daemon in the background on port 2200
/switch daemon --tcp 2200 &
sleep 1

# Launch ttyd with --writable and explicitly connect cli to port 2200
exec ttyd -p 8080 --writable /switch cli --port 2200