#!/bin/bash

echo "Starting AnyTLS Server..."
cargo run --bin anytls-server -- -l 0.0.0.0:443 -p password &
SERVER_PID=$!

echo "Waiting for server to start..."
sleep 2

echo "Starting AnyTLS Client..."
cargo run --bin anytls-client -- -l 127.0.0.1:1080 -s 127.0.0.1:443 -p password &
CLIENT_PID=$!

echo "Waiting for client to start..."
sleep 2

echo "Testing SOCKS5 proxy with curl..."
curl -x socks5h://127.0.0.1:1080 -I https://www.jd.com/ --connect-timeout 10

echo "Cleaning up..."
kill $CLIENT_PID 2>/dev/null
kill $SERVER_PID 2>/dev/null
wait
