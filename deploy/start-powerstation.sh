#!/data/data/com.termux/files/usr/bin/sh
cd "$HOME/powerstation-monitor" || exit 1
nohup ./keepalive.sh >> ./keepalive.log 2>&1 &
