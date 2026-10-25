#!/bin/sh
# Start the switch daemon in the background on port 2200
/switch daemon --tcp 2200 &
sleep 1
# Launch ttyd wrapping the switch CLI so it displays in the browser on port 8080
exec ttyd -p 8080 -w /switch cli