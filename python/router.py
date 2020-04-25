import socket
import time
import sys

UDP_BROADCAST_IP = '10.0.1.255'
UDP_PORT = 1234
ADVERTISEMENT_INTERVAL = 1 	


if len(sys.argv) != 3:
    print('Error: wrong number of parameters.')

else:
    router_parameters = sys.argv[1]+':'+ sys.argv[2]

    # Create a new socket using the given address family and socket type
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # socket.SO_REUSEPORT: enable port reusage so we will be able to run multiple clients and servers on single (host, port).
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    # socket.SO_BROADCAST: this option controls whether datagrams may be broadcast from the socket.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    message = bytes(router_parameters,encoding='utf8')

    print('Sending router name: ' + sys.argv[1] + ' and priority: ' + sys.argv[2])

    while True:
        print("Sending keep alive message")
        # Send keep alive message each ADVERTISEMENT_INTERVAL seconds. 
        # Message format is router_name:priority
        s.sendto(message, (UDP_BROADCAST_IP, UDP_PORT))
        time.sleep(ADVERTISEMENT_INTERVAL)