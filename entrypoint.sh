#!/bin/bash

# 1. Clean up old locks (as root)
rm -f /tmp/.X0-lock /tmp/.X11-unix/X0 2>/dev/null

# 2. Fix the /tmp directory permissions for Xvfb
mkdir -p /tmp/.X11-unix
chmod 1777 /tmp/.X11-unix
chown root:root /tmp/.X11-unix

# 3. Ensure app volumes are owned by the user
mkdir -p /app/keys /app/received_files /app/logs
chown -R i2iuser:i2igroup /app/keys /app/received_files /app/logs

# 4. Start Xvfb and VNC as root
Xvfb :0 -screen 0 1280x900x24 &
while [ ! -S /tmp/.X11-unix/X0 ]; do sleep 0.1; done

fluxbox -display :0 &
x11vnc -display :0 -nopw -forever -shared -quiet &
websockify --web /usr/share/novnc/ 8080 localhost:5900 &

export DISPLAY=:0

# 5. Run Python as i2iuser
# This ensures files created in the volume are owned by YOU on Arch
exec gosu i2iuser python main.py
