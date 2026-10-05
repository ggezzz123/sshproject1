#!/bin/sh
# Joins the Tailscale network in the background (so the app can reach Oracle on your PC) and
# starts the app right away. A Tailscale problem must never keep the web app from listening.
if [ -n "$TS_AUTHKEY" ]; then
  (
    tailscaled --state=mem: --socket=/var/run/tailscale/tailscaled.sock &
    i=0
    until timeout 30 tailscale up --authkey="$TS_AUTHKEY" --hostname="${TS_HOSTNAME:-ssh-monitor-fly}" --accept-dns=false; do
      i=$((i + 1))
      if [ "$i" -ge 5 ]; then echo "[tailscale] giving up after $i attempts"; exit 0; fi
      echo "[tailscale] attempt $i failed, retrying..."
      sleep 3
    done
    echo "[tailscale] connected"
  ) &
else
  echo "[tailscale] TS_AUTHKEY not set, skipping"
fi

exec node server.js
