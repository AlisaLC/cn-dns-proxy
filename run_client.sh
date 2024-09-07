
deltun() {
    kill "$pid"
    ip link delete dprox
}

QUERA_IP=$(dig +short quera.org | head -n 1)
python client.py &
pid=$!
trap deltun INT TERM
sleep 3
ip route add "$QUERA_IP" dev dprox
wait "$pid"
