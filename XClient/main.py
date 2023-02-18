import threading
import queue
import socket
import logging
from multiprocessing import Queue
import ssl
import sys
import argparse
import time
from typing import Tuple


def parse_input_argument():
    parser = argparse.ArgumentParser(description='This is a client program that create a tunnel\
                                                  to the server over various TCP connections.')

    parser.add_argument('-ut', '--udp-tunnel', action='append', required=True,
                        help="Make a tunnel from the client to the server. The format is\
                              'listening ip:listening port:remote ip:remote port'.")
    parser.add_argument('-s', '--server', required=True,
                        help="The IP address and (TCP) port number of the tunnel server.\
                               The format is 'server ip:server port'.")
    parser.add_argument('-v', '--verbosity', choices=['error', 'info', 'debug'], default='info',
                        help="Determine the verbosity of the messages. The default value is 'info'.")

    args = parser.parse_args()
    return args


def read_n_byte_from_tcp_sock(sock, n):
    """Just for read n byte  from tcp socket"""
    buff = bytearray(n)
    pos = 0
    while pos < n:
        cr = sock.recv_into(memoryview(buff)[pos:])
        if cr == 0:
            raise EOFError
        pos += cr
    return buff


def handle_tcp_conn_recv(stcp_socket: socket.socket, udp_socket: socket.socket, incom_udp_addr: Tuple[str, int]):
    """
    read from tcp socket for the UDP segment received through the tunnel,
    then forward received segment to incom_udp_addr
    """
    while True:
        try:
            udp_seg_len = int.from_bytes(read_n_byte_from_tcp_sock(stcp_socket, 4), byteorder='big')
            udp_seg = read_n_byte_from_tcp_sock(stcp_socket, udp_seg_len)
            udp_socket.sendto(udp_seg, incom_udp_addr)
        except socket.error as e:
            logging.error("(Error) Error receiving data from the TCP socket: {}".format(e))
            break


def handle_tcp_conn_send(stcp_socket: socket.socket, rmt_udp_addr: Tuple[str, int], udp_to_tcp_queue: queue.Queue):
    """
    Get remote UDP ip and port(rmt_udp_addr) and Concat them then sending it to the TCP socket
    after that read from udp_to_tcp_queue for sendeig a UDP segment and update queue,
    don't forgot to block the queue when you are reading from it.
    """
    try:
        rmt_udp_ip = socket.inet_aton(rmt_udp_addr[0])
        # Send ip and port of the udp destination at first.
        # Every packet on this connection will be forwarded to this destination.
        stcp_socket.sendall(rmt_udp_ip)
        stcp_socket.sendall(rmt_udp_addr[1].to_bytes(2, byteorder='big'))
        logging.info("Sent remote UDP address to the TCP socket: {}".format(rmt_udp_addr))
    except socket.error as e:
        logging.error("Error sending data to the TCP socket: {}".format(e))
        return
    while True:
        try:
            data = udp_to_tcp_queue.get(block=True, timeout=1)
            # Send data len as the first 4 bytes of every packet to handle different packet sizes.
            stcp_socket.sendall(len(data).to_bytes(4, byteorder='big'))
            stcp_socket.sendall(data)
            logging.debug("Sent UDP segment to the TCP socket: {}".format(rmt_udp_addr))
        except queue.Empty:
            continue
        except socket.error as e:
            logging.error("(Error) Error sending data to the TCP socket: {}".format(e))
            break


def handle_udp_conn_recv(udp_socket: socket.socket, tcp_server_addr: Tuple[str, int], rmt_udp_addr: Tuple[str, int]):
    """
        Receive a UDP packet form incom_udp_addr.
        It also keeps the associated thread for handling tcp connections in udp_conn_list,
        if incom_udp_addr not in udp_conn_list, Recognize a new UDP connection from incom_udp_addr. So establish a TCP connection to the remote server for it
        and if incom_udp_addr in udp_conn_list you should continue sending in esteblished socekt  ,
        you need a queue for connecting udp_recv thread to tcp_send thread.
         """
    logging.debug("Start handling UDP connection to {}".format(rmt_udp_addr))
    udp_conn_list = dict()
    while True:
        try:
            data, incom_udp_addr = udp_socket.recvfrom(65535)
            if incom_udp_addr not in udp_conn_list:
                logging.info("New UDP connection from {}".format(incom_udp_addr))

                tcp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
                context = ssl.create_default_context()
                context.load_verify_locations('XClient/rootCA.pem')
                stcp_socket = context.wrap_socket(tcp_socket, server_hostname='pouyaesmaili.ir')

                stcp_socket.connect(tcp_server_addr)
                udp_to_tcp_queue = Queue(maxsize=16384)
                udp_conn_list[incom_udp_addr] = (stcp_socket, udp_to_tcp_queue)
                threading.Thread(target=handle_tcp_conn_recv,
                                 args=(stcp_socket, udp_socket, incom_udp_addr)).start()
                threading.Thread(target=handle_tcp_conn_send,
                                 args=(stcp_socket, rmt_udp_addr, udp_to_tcp_queue)).start()
            stcp_socket, udp_to_tcp_queue = udp_conn_list[incom_udp_addr]
            udp_to_tcp_queue.put(data, block=True, timeout=1)
        except queue.Full:
            logging.error("UDP to TCP queue is full, drop the UDP packet")
        except socket.error as e:
            logging.error("Error receiving data from the UDP socket: {}".format(e))


def main():
    args = parse_input_argument()

    tcp_server_ip = args.server.split(':')[0]
    tcp_server_port = int(args.server.split(':')[1])
    tcp_server_addr = (tcp_server_ip, tcp_server_port)

    log_level = logging.INFO
    if args.verbosity == 'error':
        log_level = logging.ERROR
    elif args.verbosity == 'info':
        log_level = logging.INFO
    elif args.verbosity == 'debug':
        log_level = logging.DEBUG
    log_format = "%(asctime)s: (%(levelname)s) %(message)s"
    logging.basicConfig(format=log_format, level=log_level, datefmt="%H:%M:%S")

    done = Queue()
    for tun_addr in args.udp_tunnel:
        tun_addr_split = tun_addr.split(':')
        udp_listening_ip = tun_addr_split[0]
        udp_listening_port = int(tun_addr_split[1])
        rmt_udp_ip = tun_addr_split[2]
        rmt_udp_port = int(tun_addr_split[3])
        rmt_udp_addr = (rmt_udp_ip, rmt_udp_port)

        try:
            udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            udp_socket.bind((udp_listening_ip, udp_listening_port))
        except socket.error as e:
            logging.error("(Error) Error openning the UDP socket: {}".format(e))
            logging.error(
                "(Error) Cannot open the UDP socket {}:{} or bind to it".format(udp_listening_ip, udp_listening_port))
            sys.exit(1)
        else:
            logging.info("Bind to the UDP socket {}:{}".format(udp_listening_ip, udp_listening_port))

        threading.Thread(target=handle_udp_conn_recv,
                         args=(udp_socket, tcp_server_addr, rmt_udp_addr)).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Closing the TCP connection...")


if __name__ == "__main__":
    main()
