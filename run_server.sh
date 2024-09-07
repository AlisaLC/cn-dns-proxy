deltun() {
  kill "$pid"
  ip link delete dprox
  iptables -t nat -D POSTROUTING -s 172.16.0.0/24 ! -d 172.16.0.0/24 -j MASQUERADE
  exit 0
}

sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 172.16.0.0/24 ! -d 172.16.0.0/24 -j MASQUERADE
python server.py
pid=$!
trap deltun INT TERM
wait "$pid"
