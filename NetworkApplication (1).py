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
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
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

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        # 1. Wait for the socket to receive a reply
        # 2. If reply received, record time of receipt, otherwise, handle timeout
        icmpSocket.settimeout(timeout)
        while True:
            try:
                packetData = icmpSocket.recv(65535)
                timeOfReceipt = time.time()
                # 3. Unpack the imcp and ip headers for useful information, including Identifier, TTL, sequence number 
                ipHeader = struct.unpack('!BBHHHBBHHH',packetData[0:16])
                headerLength = int(bin(ipHeader[0])[5:9],2) #(in words) * 32/8  (4) for bytes
                icmpHeader = struct.unpack('!BBHHH',packetData[(headerLength * 4):(headerLength * 4) + 8]) #ICMP header 
                sequenceNumber = icmpHeader[4]
                packetID = icmpHeader[3]
                totalLength = ipHeader[2] # in Bytes
                timeToLive = ipHeader[5] 
                # 5. Check that the Identifier (ID) matches between the request and reply
                if (packetID == ID):
                    # 6. Return time of receipt, TTL, packetSize, sequence number
                    return[timeOfReceipt,timeToLive,totalLength,sequenceNumber]
                else:
                    print("Wrong ID")
                    pass
            except socket.timeout:
                print("Timed out")
                pass
# 3. Call doOnePing function, approximately every second, below is just an example
    def sendOnePing(self, icmpSocket, destinationAddress,ID,seq_num):
        # 1. Build ICMP header
        icmpHeader = struct.pack('!BBHHH',8,0,0,ID,seq_num)
        # 2. Checksum ICMP packet using given function
        checksum = socket.ntohs(self.checksum(icmpHeader))
        # 3. Insert checksum into packet
        icmpHeader = struct.pack('!BBHHH',8,0,checksum,ID,seq_num)
        # 4. Send packet using socket
        icmpSocket.connect((destinationAddress,80))
        icmpSocket.sendall(icmpHeader)
        # 5. Return time of sending
        return time.time()

    def doOnePing(self, destinationAddress, packetID, seq_num, timeout):
        # 1. Create ICMP socket

        pingSocket = socket.socket (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        # 2. Call sendOnePing function
        timeSentAt = self.sendOnePing(pingSocket,destinationAddress,packetID,seq_num)
        # 3. Call receiveOnePing function
        data = self.receiveOnePing(pingSocket,destinationAddress,packetID,timeout)
        # 4. Close ICMP socket
        pingSocket.close()
        # 5. Print out the delay (and other relevant details) using the printOneResult method, below is just an example.
        self.printOneResult(destinationAddress, data[2],((data[0] - timeSentAt) * 1000) , data[3], data[1]) 
        pass

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        # 1. Look up hostname, resolving it to an IP address
        ipAddress = socket.gethostbyname(args.hostname)#
        # 2. Repeat below args.count times
        reps = 1
        timeout = 20
        if hasattr(args,'count'):
            reps = args.count
        if hasattr(args, 'timeout'):
            timeout = args.timeout
        for x in range(reps):
            # 3. Call doOnePing function, approximately every second
            time.sleep(1)
            self.doOnePing(ipAddress, 10, x, 2)

class Traceroute(NetworkApplication):
    def __init__(self, args):
        print('Traceroute to: %s...' % (args.hostname))
        if(args.protocol == 'icmp'):
            destAddress = socket.gethostbyname(args.hostname)
            self.ICMPTraceroute(destAddress,args.timeout)
        elif (args.protocol == "udp"):
            destAddress = socket.gethostbyname(args.hostname)
            self.UDPTraceroute(destAddress,args.timeout,7)
        else:
            print("Invalid value")
        #else if (args.protocol == "udp")
    def sendOnePing(self, icmpSocket, destinationAddress,ID,seq_num): #From ICMP ping (should chnage to class Traceroute(ICMPPing)) but dk if it's allowed
        # 1. Build ICMP header
        icmpHeader = struct.pack('!BBHHH',8,0,0,ID,seq_num)
        # 2. Checksum ICMP packet using given function
        checksum = socket.ntohs(self.checksum(icmpHeader))
        # 3. Insert checksum into packet
        icmpHeader = struct.pack('!BBHHH',8,0,checksum,ID,seq_num)
        # 4. Send packet using socket
        icmpSocket.sendto(icmpHeader,(destinationAddress,80))
        # 5. Return time of sending
        return time.time()
    def recieveICMPTraceroutePacket(self, icmpSocket,timeout):
        # 1. Wait for the socket to receive a reply
        # 2. If reply received, record time of receipt, otherwise, handle timeout
        icmpSocket.settimeout(timeout)
        while True:#Similair to recieve icmp ping just return values modified
            try:
                packetData = icmpSocket.recv(65535)
                timeOfReceipt = time.time()
                # 3. Unpack the imcp and ip headers for useful information, including Identifier, TTL, sequence number 
                ipHeader = struct.unpack('!BBHHHBBHII',packetData[0:20])
                headerLength = int(bin(ipHeader[0])[5:9],2) #(in words) * 32/8  (4) for bytes
                addr = socket.inet_ntoa(struct.pack("!I",ipHeader[8]))
                icmpHeader = struct.unpack('!BBHHH',packetData[(headerLength * 4):(headerLength * 4) + 8]) #ICMP header 
                ICMPType = icmpHeader[0]
                return [ICMPType,timeOfReceipt,addr]
            except socket.timeout:
                print("Timed out")
                return []
            
    def getHostName(self,address):
            try:
                hostname = socket.gethostbyaddr(address)[0]
            except socket.herror:
                hostname = "Unkown hostname"
            return hostname #try getting hostname, if doesn't exist/not available retunrn "Unknown hostname string"
    def repeatICMP(self,mesuarements,tracertSocket,destinationAddress,timeout):
        while (len(mesuarements) < 3): #Gather 3 mesaurements 
                timeSentAt = self.sendOnePing(tracertSocket,destinationAddress,1,1)
                data = self.recieveICMPTraceroutePacket(tracertSocket,timeout)
                mesuarements.append((data[1] - timeSentAt)*1000)
        return mesuarements
    def ICMPTraceroute(self, destinationAddress, timeout):
        mesuarements = []
        # 1. Create ICMP socket
        tracertSocket = socket.socket (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        #Set TTL to 1
        tracertSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, 1)
        # 2. Initial Call of sendOnePing function
        timeSentAt = self.sendOnePing(tracertSocket,destinationAddress,1,1)
        # 3. Initial Call of recieveICMPTraceroutePacket function
        data = self.recieveICMPTraceroutePacket(tracertSocket,timeout)
        mesuarements.append((data[1] - timeSentAt)*1000)
        #if type = 0 then stop else if 11 carry on
        while (data[0] == 11):
            #While mesuarements length > 3, re-test to get more values
            mesuarements = self.repeatICMP(mesuarements,tracertSocket,destinationAddress,timeout)
            #Get current TTL 
            currentTTL = tracertSocket.getsockopt(socket.SOL_IP,socket.IP_TTL)
            self.printOneTraceRouteIteration(currentTTL,data[2],mesuarements,self.getHostName(data[2])) #Print out values
            mesuarements = []
            tracertSocket.setsockopt(socket.SOL_IP,socket.IP_TTL,currentTTL + 1)
            # 2. Call sendOnePing function
            timeSentAt = self.sendOnePing(tracertSocket,destinationAddress,1,1)
            # 3. Initial Call of recieveICMPTraceroutePacket function
            data = self.recieveICMPTraceroutePacket(tracertSocket,timeout)
            mesuarements.append((data[1] - timeSentAt) * 1000)
            
        # 4. Close ICMP Traceroute socket
        # 5. Print out the final Iteration
        currentTTL = tracertSocket.getsockopt(socket.SOL_IP,socket.IP_TTL)
        self.repeatICMP(mesuarements,tracertSocket,destinationAddress,timeout)
        tracertSocket.close()
        if (data[0] == 0): #Check actually reached host
            self.printOneTraceRouteIteration(currentTTL,data[2],mesuarements,self.getHostName(data[2])) 
        else: #If it didn't thrn host unreachable
            print("Unable to reach host")

    def sendUDPPing(self,udpSocket,destinationAddress,port):
        udpSocket.sendto("ECHO".encode(),(destinationAddress,port))
        return time.time()#Send UDP echo request,return time
    def repeatUDP(self,mesuarements,udpSocket,tracertSocket,destinationAddress,timeout,port):
        while (len(mesuarements) < 3): #get 3 mesuarements
                timeSentAt = self.sendUDPPing(udpSocket,destinationAddress,port)
                data = self.recieveICMPTraceroutePacket(tracertSocket,timeout)
                mesuarements.append((data[1] - timeSentAt)*1000)
        return mesuarements
    def UDPTraceroute(self,destinationAddress,timeout,port):
        #Create UDP Socket
        udpSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        #Set timeout
        udpSocket.settimeout(timeout)
        #Set TTL to 1
        udpSocket.setsockopt(socket.SOL_IP,socket.IP_TTL,1)
        #Initial call of sendUDPPing (Send UDP echo DGRAM)
        timeSentAt = self.sendUDPPing(udpSocket,destinationAddress,port)
        #Call recieve UDP packet and recieve data points
        tracertSocket = socket.socket (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        data = self.recieveICMPTraceroutePacket(tracertSocket,timeout)
        mesuarements = []
        mesuarements.append((data[1] - timeSentAt) * 1000) #Add 1st mesuarement of RTT time to mesaurements
        while (data[0] == 11):
            mesuarements = self.repeatUDP(mesuarements,udpSocket,tracertSocket,destinationAddress,timeout,port) #Repeat to get 3 RTT values
            currentTTL = udpSocket.getsockopt(socket.SOL_IP,socket.IP_TTL)
            self.printOneTraceRouteIteration(currentTTL,data[2],mesuarements,self.getHostName(data[2])) #Print out values
            mesuarements = [] #Reset mesaurements list
            udpSocket.setsockopt(socket.SOL_IP,socket.IP_TTL,currentTTL + 1) # TTL +=1
            timeSentAt = self.sendUDPPing(udpSocket,destinationAddress,port) 
            data = self.recieveICMPTraceroutePacket(tracertSocket,timeout)
            mesuarements.append((data[1] - timeSentAt) * 1000)#Add 1st ,RTT mesaurement to mesaurements
        if(data[0] == 3):
            mesuarements = self.repeatUDP(mesuarements,udpSocket,tracertSocket,destinationAddress,timeout)
            currentTTL = udpSocket.getsockopt(socket.SOL_IP,socket.IP_TTL)
            self.printOneTraceRouteIteration(currentTTL,data[2],mesuarements,self.getHostName(data[2])) #Print final value if destination reachable
        else:
            print("Destination unreachable") #Print unreachable if not
        tracertSocket.close()
        udpSocket.close() #Close sockets

        


    

class WebServer(NetworkApplication):

    def handleRequest(self,tcpSocket,req):
        if req == ['']:
            tcpSocket.close()
            return
        filePath = req.split("\n")[0].split(" ")[1]
        try:
            file = open(filePath[1:],"r")
            fileBuffer = file.read()
            file.close()
            httpAllOk = 'HTTP/1.1 200 All OK\n\n'
            message =(httpAllOk + fileBuffer)
        except FileNotFoundError:
            message = 'HTTP/1.1 404 Error\n\nFile does NOT exist!!!'
        tcpSocket.sendall(message.encode())
        tcpSocket.close()
        # 1. Receive request message from the client on connection socket
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        # 3. Read the corresponding file from disk
        # 4. Store in temporary buffer
        # 5. Send the correct HTTP response error
        # 6. Send the content of the 
        # file to the socket
        # 7. Close the connection socket
        pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        # 2. Bind the server socket to server address and server port
        serverSocket.bind((socket.gethostbyname(socket.gethostname()),8080))
        print(socket.gethostbyname(socket.gethostname()))
        serverSocket.listen(1)
        # 3. Continuously listen for connections to server socket
        while(True):
            clientConnection,clientAddress = serverSocket.accept()
            clientRequest = clientConnection.recv(2056).decode()
            self.handleRequest(clientConnection,clientRequest)
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        # 5. Close server socket
        serverSocket.close()


class Proxy(NetworkApplication):
    def saveToCache(self,data,FileName,hostname,cache):
            dirs = FileName.split('/')
            dirs.insert(0,hostname)
            currentPath = "Cache"
            for i in range(0,len(dirs) - 1):
                directory = dirs[i]
                if not (os.path.exists(currentPath + "/" + directory)):
                    os.mkdir(currentPath + "/" + directory)
                currentPath = currentPath + "/" + directory
            file = open((currentPath + "/" + dirs[len(dirs) - 1] + ".txt"),"w+")
            file.write(data)
            file.close()
            cache.append(currentPath + "/" + dirs[len(dirs) - 1] + ".txt")
    def handleRequest(self,tcpsocket,req,cache):
        
        hostname = req.split()[4]
        filename = req.split()[1].strip("http://")
        cachedFileName = "Cache/" + hostname + "/" + filename + ".txt"
        #Check cache here, if present call sendall,close socket else
        if cachedFileName in set(cache):
            file = open(cachedFileName)
            fileBuffer = file.read()
            file.close()
            #httpAllOk = 'HTTP/1.1 200 All OK\n\n'
            #message =(httpAllOk + fileBuffer)?
            tcpsocket.sendall(fileBuffer.encode())
            tcpsocket.close()
            return


        request = "GET / HTTP/1.1\r\nHost:" + filename +"\r\n\r\n"
        downloadSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        downloadSocket.settimeout(100)
        downloadSocket.connect((socket.gethostbyname(hostname),80))
        downloadSocket.sendall(request.encode())
        while True:
            try:
                data = downloadSocket.recv(2560000).decode()
                tcpsocket.sendall(data.encode())
                #Save to file and add to cache data structure
                self.saveToCache(data,filename,hostname,cache)
                tcpsocket.close()
                downloadSocket.close()
                return
            except socket.timeout:
                print("timeout")
                tcpsocket.close()
                downloadSocket.close()
                return
    def __init__(self, args):
        print('Web Proxy on port: %i...' % (args.port))
        #Create cache data structure
        cache = []
        #Check if cache folder exists
        if(os.path.exists("Cache")):
            #if it exists load all files and names into local memory
            for root,dirs,files in os.walk("Cache",False):
                for name in files:
                    cache.append(os.path.join(root,name))
        else:
            os.mkdir("Cache")

        
        #Create socket and bind to localhost and port
        proxySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        proxySocket.bind((socket.gethostbyname(socket.gethostname()),args.port))
        proxySocket.listen(1)
        while (True):    
            clientConnection,clientAddress = proxySocket.accept()
            clientRequest = clientConnection.recv(2056).decode()
            self.handleRequest(clientConnection,clientRequest,cache)
        proxySocket.close()
        
        #Steps:
        #1) Recieve request from proxy sender
        #2) Check in cache
        #3)If not in cache: 
        #4)     forward request to server
        #5)     Add response to cache
        #6)     Respond to proxy sender
        #7)If in cache:
        #8)     respond back to proxy sender

        #Cache Plan:
        #Save file/web page
        #Save name/reference in dictionary
        #Look up value in dictionary, return path if present else download and put it in

        #Function breakdowns:
        #Handle request
        #Save file + add to dictionary
        #load file (return as string)
    


# Do not delete or modify the code below
if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)