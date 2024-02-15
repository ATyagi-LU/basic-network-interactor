#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback # useful for exception handling
import threading
# NOTE: Do not import any other modules - the ones above should be sufficient

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk',timeout=2,count=10)
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=2, count=10)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=2, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: bytes) -> int:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, seq: int, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationHostname, destinationAddress, seq, ttl, time))
        else:
            print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationAddress, seq, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printOneTraceRouteIteration(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))

class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket : socket.socket, destinationAddress : str, ID : int, timeout : int) -> tuple[int,int,int,int]:  
        icmpSocket.settimeout(timeout)
        # 1. Wait for the socket to receive a reply
        # 2. If reply received, record time of receipt, otherwise, handle timeout
        try:
            packet = icmpSocket.recv(1024)        
        except TimeoutError:
            return 0,0,0,0,1,0
        # 3. Unpack the imcp and ip headers for useful information, including Identifier, TTL, sequence number
        ipHeader = struct.unpack("!BBHHHBBHII",packet[:20])
        ipHeaderSize = (ipHeader[0] & 15)*4
        icmpHeader = struct.unpack("!BBHHH", packet[ipHeaderSize:ipHeaderSize+8])
        # 5. Check that the Identifier (ID) matches between the request and reply
        id = icmpHeader[3]
        if (id != ID and icmpHeader[0] == 0):
            return 0,0,0,0,1,0
        # 6. Return time of receipt, TTL, packetSize, sequence number, code
        
        return time.time_ns()/1000000, ipHeader[5], ipHeader[2], icmpHeader[4], icmpHeader[0], ipHeader[-2]

    def sendOnePing(self, icmpSocket: socket.socket, seq_num : int, destinationAddress : str, ID : int) -> int:
        # 1. Build ICMP header
        checksum = 0
        packet = struct.pack(
            "!BBHHH",
            8,
            0,
            checksum,
            ID,
            seq_num
        )
        # 2. Checksum ICMP packet using given function
        checksum = socket.ntohs(NetworkApplication.checksum(self, packet))
        # 3. Insert checksum into packet
        packet = struct.pack(
            "!BBHHH",
            8,
            0,
            checksum,
            ID,
            seq_num
        )
        # 4. Send packet using socket
        icmpSocket.sendto(packet,(destinationAddress,1))
        # 5. Return time of sending
        return time.time_ns()/1000000

    def doOnePing(self, destinationAddress : str, packetID : int, seq_num : int, timeout : int):
        # 1. Create ICMP socket
        sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
        # 2. Call sendOnePing function
        sendTime = self.sendOnePing(sock,seq_num,destinationAddress,packetID)
        # 3. Call receiveOnePing function
        recieveTime, TTL, packetSize, seqNum, _, _ = self.receiveOnePing(sock,destinationAddress,packetID,timeout)
        # 4. Close ICMP socket
        sock.close()
        # 5. Print out the delay (and other relevant details) using the printOneResult method, below is just an example.
        try:
            hostname = socket.gethostbyaddr(destinationAddress)[0]
        except:
            hostname = destinationAddress
        self.printOneResult(destinationAddress,packetSize,recieveTime-sendTime,seqNum,TTL,hostname) # Example use of printOneResult - complete as appropriate
        return

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        # 1. Look up hostname, resolving it to an IP address
        address =  socket.gethostbyname(args.hostname)
        # 2. Repeat below args.count times
        for i in range(args.count):
            self.doOnePing(address,10,i,args.timeout)
            time.sleep(1)
            # 3. Call doOnePing function, approximately every second, below is just an example

class Traceroute(ICMPPing):

    def sendUDPping(self,socket,destinationAddress):
        socket.sendto(b'',(destinationAddress,80))
        return time.time_ns() / 1000000

    def trace(self,protocol,destinationAddress, timeout, ID, seq_num):
        
        
        sockUDP = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
        sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        ttl = 0
        icmpcode = 11
        while icmpcode not in [0,3]:
            ttl+=1
            sock.setsockopt(socket.SOL_IP, socket.IP_TTL,ttl)
            sockUDP.setsockopt(socket.SOL_IP, socket.IP_TTL,ttl)
            measurements = []
            for i in range(3):
                #print("socket set")
                if (protocol == 'icmp'):
                    sendTime = super().sendOnePing(sock,seq_num,destinationAddress,ID)
                elif(protocol == 'udp'):
                    sendTime = self.sendUDPping(sockUDP,destinationAddress)
                #print("ping sent with TTL = " + str(ttl))
                recieveTime, TTL, packetSize, seqNum, icmpcode, recDestAddr = super().receiveOnePing(sock,destinationAddress,ID,timeout)

                if recieveTime == 0:
                    measurements.append(None)
                else:
                    measurements.append(recieveTime-sendTime)
                recDestAddr = socket.inet_ntoa(struct.pack("!I", recDestAddr))
                try:
                    hostname = socket.gethostbyaddr(recDestAddr)[0]
                except:
                    hostname = recDestAddr
            self.printOneTraceRouteIteration(ttl,recDestAddr, measurements,hostname)    
    

    def __init__(self, args):
        print('Traceroute to: %s...' % (args.hostname))
        address =  socket.gethostbyname(args.hostname)
        self.trace(args.protocol,address,args.timeout,10,1)
        

class WebServer(NetworkApplication):

    def handleRequest(self, tcpSocket : socket.socket):
        # 1. Receive request message from the client on connection socket
        data = tcpSocket.recv(2048)
        httpsHeader = data.decode()
        filePath = "." + data.split()[1].decode()

        try:
            file = open(filePath,'r')
            content = """HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"""
            content += file.read()
        except FileNotFoundError:
            content = """HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n"""
            content += """<html><body><p>404 Not Found</p></body></html>"""
        tcpSocket.send(content.encode())
        tcpSocket.close()
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        # 3. Read the corresponding file from disk
        # 4. Store in temporary buffer
        # 5. Send the correct HTTP response error
        # 6. Send the content of the file to the socket
        # 7. Close the connection socket

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        LOCAL_HOST = '127.0.0.1'
        PORT = args.port
        server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
            # 2. Bind the server socket to server address and server port
        server.bind((LOCAL_HOST, PORT))
            # 3. Continuously listen for connections to server socket
        server.listen()
            # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        live = True
        while live:
            conn, _ = server.accept()
            self.handleRequest(conn)
            live = False
        server.close()
        # 5. Close server socket


class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))

# Do not delete or modify the code below
if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
