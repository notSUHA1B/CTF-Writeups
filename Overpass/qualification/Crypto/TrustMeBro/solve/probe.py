import socket, time, sys
s = socket.create_connection(("vps1.ctf.bracken.sh", 30000), timeout=15)
time.sleep(2)
print(repr(s.recv(65536)))
for n in [1, 10, 200]:
    s.sendall(b"".join(b"%x\n" % (12345+i) for i in range(n)))
    time.sleep(3)
    try:
        d = s.recv(1<<20); print(n, len(d), repr(d[:200]))
    except Exception as ex: print(n, ex)
