# THIS IS A DEMO FILE, NOT INTENDED FOR PRODUCTION USE
# This file is used to demonstrate how a connection to a mining pool can be detected by the port 3333 which is used by the stratum protocol.
# The Stratum protocol is used by mining pools to communicate with miners.
import socket
import time

PORT = 3333


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("1.1.1.1", PORT))
    except socket.gaierror as ex:
        print(ex)
        print("Got exception")
    time.sleep(10000000)


if __name__ == "__main__":
    main()