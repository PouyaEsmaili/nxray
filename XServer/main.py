import threading
import socket
import logging
import ssl
import time
import sys
import argparse
import random
import time


def parse_input_argument():
    parser = argparse.ArgumentParser(description='This is a client program that create a tunnel\
                                                  to the server over various TCP connections.')

    parser.add_argument('-s', '--server', required=True,
                        help='The IP address and (TCP) port number of the tunnel server.\
                              A tcp socket will be openned on this port')
    parser.add_argument('-v', '--verbosity', choices=['error', 'info', 'debug'], default='info',
                        help="Determine the verbosity of the messages. The default value is 'info'.")

    args = parser.parse_args()
    return args


def read_n_byte_from_tcp_sock(sock, n):
    '''Just for read n byte  from tcp socket'''
    buff = bytearray(n)
    pos = 0
    while pos < n:
        cr = sock.recv_into(memoryview(buff)[pos:])
        if cr == 0:
            raise EOFError
        pos += cr
    return buff


def handle_tcp_conn_recv(stcp_socket: socket.socket, udp_socket: socket.socket):
    """
    read from tcp socket for the UDP segment received through the tunnel,
    then forward received segment to incom_udp_addr
    """
    try:
        rmt_udp_ip = read_n_byte_from_tcp_sock(stcp_socket, 4)
        rmt_udp_port = int.from_bytes(read_n_byte_from_tcp_sock(stcp_socket, 2), byteorder='big')
        rmt_udp_addr = (socket.inet_ntoa(rmt_udp_ip), rmt_udp_port)
    except socket.error as e:
        logging.error("(Error) Error receiving data from the TCP socket: {}".format(e))
        return
    while True:
        try:
            udp_seg_len = int.from_bytes(read_n_byte_from_tcp_sock(stcp_socket, 4), byteorder='big')
            udp_seg = read_n_byte_from_tcp_sock(stcp_socket, udp_seg_len)
            udp_socket.sendto(udp_seg, rmt_udp_addr)
        except socket.error as e:
            logging.error("(Error) Error receiving data from the TCP socket: {}".format(e))
            break


def handle_tcp_conn_send(stcp_socket: socket.socket, udp_socket: socket.socket):
    """
    read from udp socket for the UDP segment received from the client,
    then forward received segment to the server
    """
    while True:
        try:
            udp_seg, incom_udp_addr = udp_socket.recvfrom(65535)
            stcp_socket.sendall(len(udp_seg).to_bytes(4, byteorder='big'))
            stcp_socket.sendall(udp_seg)
        except socket.error as e:
            logging.error("(Error) Error receiving data from the UDP socket: {}".format(e))
            break


def main():
    args = parse_input_argument()

    tcp_server_listen_ip = args.server.split(':')[0]
    tcp_server_listen_port = int(args.server.split(':')[1])

    log_level = logging.INFO
    if args.verbosity == 'error':
        log_level = logging.ERROR
    elif args.verbosity == 'info':
        log_level = logging.INFO
    elif args.verbosity == 'debug':
        log_level = logging.DEBUG
    log_format = "%(asctime)s: (%(levelname)s) %(message)s"
    logging.basicConfig(format=log_format, level=log_level, datefmt="%H:%M:%S")

    # Create a TCP socket
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='XServer/rootCA.pem', keyfile='XServer/rootCA.key')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
        tcp_socket.bind((tcp_server_listen_ip, tcp_server_listen_port))
        tcp_socket.listen()
        with context.wrap_socket(tcp_socket, server_side=True) as stcp_socket:
            while True:
                logging.info("Waiting for a TCP connection...")
                conn, addr = stcp_socket.accept()
                logging.info("Received a TCP connection from {}".format(addr))
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_socket.bind(('', 0))
                logging.info("UDP socket binded to {}".format(udp_socket.getsockname()))
                threading.Thread(target=handle_tcp_conn_recv, args=(conn, udp_socket)).start()
                threading.Thread(target=handle_tcp_conn_send, args=(conn, udp_socket)).start()


if __name__ == '__main__':
    main()
