#!/data/data/com.termux/files/usr/bin/sh
cd "$HOME/powerstation-monitor" || exit 1
mkdir -p ./data

termux-wake-lock 2>/dev/null || true

while true; do
  if ! pgrep -f "bin/ntfy-cgo serve" >/dev/null 2>&1; then
    nohup ./bin/ntfy-cgo serve \
      --listen-http 0.0.0.0:2586 \
      --cache-file ./data/cache.db \
      --cache-duration 24h \
      >> ./ntfy.log 2>&1 &
    sleep 2
  fi
  if ! pgrep -f "python monitor.py" >/dev/null 2>&1; then
    nohup python monitor.py >> ./monitor.log 2>&1 &
    sleep 2
  fi
  sleep 30
done
