#! /usr/bin/python
#
# C H E C K T I M E . P Y
#
# Check the time on another device or computer on the network.
#
# Last Modified on Tue Dec 10 13:29:00 2017
#

#
# This code is based on ideas in rawScktPing.py, which in turn
# was a modification and development of a code snippet apparently
# authored by "lilydjwg".
#

import socket as _socket
import time as _time
from datetime import datetime, time
import struct
import array  # required in calcChecksum()
import os     # getpid()
import sys    # exit()
import getopt # getopt()

# RFC 792 (ICMP) Message types
ICMP_ECHO_REPLY = 0
ICMP_DESTINATION_UNREACHABLE = 3
ICMP_SOURCE_QUENCH = 4
ICMP_REDIRECT = 5
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11
ICMP_PARAMETER_PROBLEM = 12
ICMP_TIMESTAMP_REQUEST = 13
ICMP_TIMESTAMP_REPLY = 14
ICMP_INFORMATION_REQUEST = 15
ICMP_INFORMATION_REPLY = 16

_d_size = struct.calcsize('d')
options = {"dgram" : False, "debug" : False, "help" : False, "reverse" : False, "verbose" : False}


# Get the most accurate time available on the local system
def getClockTime():
  if sys.platform == 'win32':
    systemWallClockTime = _time.clock()
  else:
    systemWallClockTime = _time.time()  # best on most platforms is time.time
  return systemWallClockTime


# Calculate the number of milliseconds since midnight UTC
def calcTimeSinceUTC_Midnight():
  utcnow = datetime.utcnow()
  midnightUTC = datetime.combine(utcnow.date(), time(0))
  delta = utcnow - midnightUTC
  millisecondsSinceMidnight = delta.seconds * 1000 + delta.microseconds / 1000
  return millisecondsSinceMidnight


# Convert milliseconds to hours, minutes and seconds format
def convertMillisecondsSinceMidnight( milliseconds ):
  msecs = milliseconds % 1000L
  hrs = milliseconds / 3600000L
  mins = ( milliseconds - ( hrs * 3600000L )) / 60000L
  secs = ( milliseconds - ( hrs * 3600000L + mins * 60000L )) / 1000L
  mS_Time = { "hours" : hrs, "minutes" : mins, "seconds" : secs, "milliSeconds" : msecs }
  return mS_Time


# Calculate 16 bit check sum for a data string
#  (mostly borrowed from scapy's utils.py)
def calcChecksum(dataString):
  if len(dataString) % 2 == 1: # test for odd number of bytes in the string
      dataString += "\0"       # add extra zero to make even number of bytes
  s = sum(array.array("H", dataString))
  s = (s >> 16) + (s & 0xffff)
  s += s >> 16
  s = ~s
  if struct.pack("=H",1) == "\x01\x00":   # handle endianess of architecture
      s = (((s >> 8) & 0xff) | s << 8 )   # swap checksum bytes if little endian
  return s & 0xffff


# Construct the ICMP header and add it to the ICMP body data
def constructICMP_Datagram(icmpType, seq, payload):
  # Header is type (8), code (8), checksum (16), id (16), sequence (16)
  pid = os.getpid() & 0xffff
  headerSansCheckSum = struct.pack('!BBHHH', icmpType, 0, 0, pid, seq)
  chckSum = calcChecksum(headerSansCheckSum + payload)
  header = struct.pack('!BBHHH', icmpType, 0, chckSum, pid, seq)
  return header + payload


# Construct an ICMP Echo Request
def constructICMP_ECHO_REQUEST_Packet(seq, packetsize=56):
  padding = (packetsize - _d_size) * b'Q'
  timeinfo = struct.pack('!d', getClockTime())
  return constructICMP_Datagram(ICMP_ECHO_REQUEST, seq, timeinfo + padding)


# Construct an ICMP Time Stamp Request
def constructICMP_TIMESTAMP_REQUEST_Packet(seq):
  originateTime = struct.pack('!L', calcTimeSinceUTC_Midnight())  #put timestamp as unsigned long in network order
  receiveTime = struct.pack('!L', 0L)
  transmitTime = struct.pack('!L', 0L)
  return constructICMP_Datagram(ICMP_TIMESTAMP_REQUEST, seq, originateTime + receiveTime + transmitTime )


# Print a Hex dump of a string of data
def printDataStringInHex(dataString):
  length = len(dataString)
  for cnt in xrange(0, length, 1):
    if (cnt % 16) == 0:
      print '\n%04u: %02x' % ( cnt, ord(dataString[ cnt ])),
    else:
      print '%02x' % ord(dataString[ cnt ]),
  print


def labelAndPrintDataStringInHex(label,dataString):
  print label,
  printDataStringInHex(dataString)


# Compare two strings of data up to the length of the shorter data string
def compareDataStrings(dataStr1,dataStr2):
  result = True
  length = len(dataStr1)
  len2 = len(dataStr2)
  if length > len2:  # choose shortest string
    length = len2
  length -= 1  # use length variable as an index
  while length >= 0:
    if dataStr1[length] != dataStr2[length]:
      result = False
      length = -1  # force exit of while loop
    length -= 1
  return result


# Print the header part of a version 4 IP packet
def printIP4_Header(header):
  print 'IP ver .. ', header["ver"]
  print 'IP hdr len', header["hdr_len"]
  print 'dscp ... 0x%02x ' % header["dscp"]
  print 'totl len %u' % header["totl_len"]
  print 'id ..... 0x%04x ' % header["pkt_id"]
  print 'frag ... 0x%04x ' % header["frag"]
  print 'ttl ....', header["ttl"]
  print 'proto .. 0x%02x ' % header["prot"]
  print 'csum ... 0x%04x ' % header["csum"]
  print 'src IP . %03u.%03u.%03u.%03u' % (header["s1"], header["s2"], header["s3"], header["s4"])
  print 'dst IP . %03u.%03u.%03u.%03u' % (header["d1"], header["d2"], header["d3"], header["d4"])
  return


# Unpack the header of a version 4 IP packet
def parseIP4_PacketHeader(data, options):
# Unpack the IPv4 Header
  ver, dscp, totl_len, pkt_id, frag, ttl, prot, csum, s1, s2, s3, s4, d1, d2, d3, d4 = struct.unpack('!BBHHHBBHBBBBBBBB', data[:20])
  hdr_len = (ver & 0xf) * 4
  ver = (ver >> 4) & 0xf
  ipv4Hdr = { "ver" : ver, "hdr_len" : hdr_len, "dscp" : dscp, "totl_len" : totl_len, "pkt_id" : pkt_id, "frag" : frag,
    "ttl" : ttl, "prot" : prot, "csum" : csum,
    "s1" : s1, "s2" : s2, "s3" : s3, "s4" : s4,
    "d1" : d1, "d2" : d2, "d3" : d3, "d4" : d4 }
  return ipv4Hdr, data[hdr_len:]


# Uncook the header on a Mac
def uncookIP4_PacketHeaderIfRequired(inData):
  if sys.platform == 'darwin':  # Undo MacOS cooking some IP4 header fields
    ver, dscp, tl1, tl2, b1, b2, fragLen = struct.unpack('=BBBBBBH', inData[:8])
    totalLen = 256 * tl2 + tl1 + ((ver & 0xf) * 4)
    tmpData = struct.pack('!BBHBBH', ver, dscp, totalLen, b1, b2, fragLen)
    return tmpData + inData[8:]
  else:
    return inData


# Unpack and Check the header of a version 4 IP packet
def parseAndCheckIP4_PacketHeader(data, optns):
  data = uncookIP4_PacketHeaderIfRequired(data)
  parsedIPv4_Hdr, parsedIPv4_Payload = parseIP4_PacketHeader(data, options)
# Check to see if the local interface is being used; i.e. src == dest
  srcAddr, destAddr = struct.unpack('!LL', data[12:20])
# If local interface then don't check the checksum of the packet
  if srcAddr == destAddr:
    chckSum = 0
  else:
    chckSum = calcChecksum(data)
  if chckSum != 0:
    print '\n?? The IPv4 packet check sum calculates to 0x%04x not zero' % chckSum
  if optns["debug"]:
    print 'The header of the IPv4 packet received was; -'
    printIP4_Header(parsedIPv4_Hdr)
    labelAndPrintDataStringInHex('The IPv4 packet received in hex format; -',data)
  return parsedIPv4_Hdr, parsedIPv4_Payload


def printICMP_Header(header):
  print 'ICMP type ... 0x%02x ' % header["ICMP_Type"]
  print 'ICMP code ... 0x%02x ' % header["code"]
  print 'ICMP checksum 0x%04x ' % header["checksum"]
  print 'ICMP id ..... 0x%04x ' % header["id"]
  print 'ICMP sequence 0x%04x ' % header["sequence"]
  return
  

def parseICMP_Data(data):
  chckSum = calcChecksum(data)
  type, code, checksum, id, sequence = struct.unpack('!BBHHH', data[:8])
  ICMP_Header = {"ICMP_Type":type,"code":code,"checksum":checksum,"id":id,"sequence":sequence}
  if chckSum != 0:
    print '\n?? The ICMP check sum test failed (it calculates to 0x%04x, not 0)' % chckSum
  if options["debug"]:
    print 'The header of the ICMP datagram is; -'
    printICMP_Header(ICMP_Header)
    labelAndPrintDataStringInHex('The ICMP datagram in hex format is; -',data)
  return ICMP_Header, data[8:]


def parseICMP_ECHO_REPLY_PacketWithTimeStamp(data, optns):
#  print 'Entering parseICMP_ECHO_REPLY_PacketWithTimeStamp()'
  if optns["dgram"]:  # Process all SOCK_DGRAM socket returned packets
    if sys.platform == 'linux2': # linux SOCK_DGRAM socket returns do not have IP4 header
      hdr, payload = parseICMP_Data(data)
    else:  # non-linux SOCK_DGRAM socket returns have an IP4 header
      _, icmpData = parseAndCheckIP4_PacketHeader(data, optns)
      hdr, payload = parseICMP_Data(icmpData)
  else:  # Process all SOCK_RAW socket returned information
    _, icmpData = parseAndCheckIP4_PacketHeader(data, optns)
    hdr, payload = parseICMP_Data(icmpData)
  if hdr["ICMP_Type"] == ICMP_ECHO_REPLY:
    timeStamp = struct.unpack('!d', payload[:_d_size])[0]
    if optns["debug"]:
      print '\nICMP (type %d, code %d) packet received is an ICMP Echo Reply' % (hdr["ICMP_Type"], hdr["code"])
  else:
    timeStamp = 0
    if optns["debug"]:
      print '----------- Reply to ICMP Echo Request was; -'
      print '?? ICMP (type %d) packet received is not an ICMP Echo Reply' % hdr["ICMP_Type"]
      printICMP_Header(hdr)
      labelAndPrintDataStringInHex('The data in the unexpected ICMP datagram is; -',payload)
#  print 'Leaving parseICMP_ECHO_REPLY_PacketWithTimeStamp()'
  return timeStamp


def informUserAboutTimestamp( msg, timeStamp ):
  print msg, 'timestamp returned was',
  tsTm = convertMillisecondsSinceMidnight(timeStamp)
  print '%02ld:%02ld:%02ld.%03ld' % (tsTm["hours"],tsTm["minutes"],tsTm["seconds"],tsTm["milliSeconds"]),
  if options["verbose"]:
    print '- (%ld (0x%08x) mS since midnight UTC)' % (timeStamp, timeStamp)
  else:
    print


def informUserAboutTimestamps( timestamps ):
  informUserAboutTimestamp('Originate', timestamps["originate"])
  informUserAboutTimestamp('Received', timestamps["received"])
  informUserAboutTimestamp('Transmit', timestamps["transmit"])


def informUserAboutTimestampProblem( msg, timeStamps ):
  print "\n?? ", msg
  informUserAboutTimestamps( timeStamps )
  print '!! Hint: If target computer is running MS Windows try the -r (--reverse) option'


def parseICMP_TIMESTAMP_REPLY_Packet(hdr, payload, optns):
  timeDiff = 999999l
  if optns["debug"]:
    print '\n----------- ICMP Time Stamp Reply is; -'
    printICMP_Header(hdr)
    labelAndPrintDataStringInHex('The data in the ICMP datagram is; -',payload)
  if len(payload) < 12:  # Check length of data which should contain 3 timestamps
    print "?? Expected at least 3 * 4 byte reply, but got", len(payload)
    if optns["verbose"]:
      labelAndPrintDataStringInHex('The truncated ICMP data in hex is; -',payoad)
  else:
    ot, rt, tt = struct.unpack('!lll', payload[:12])  # unpack in standard network order
    tmStmps = { "originate" : ot, "received" : rt, "transmit" : tt }
    if optns["reverse"]:  # MS Windows uses little endian byte order in sent timestamps
      rot, rrt, rtt = struct.unpack('<lll', payload[:12])  # unpack in little endian order
      tmStmps["received"] = rrt
      tmStmps["transmit"] = rtt
    if tmStmps["transmit"] < 0:
      informUserAboutTimestampProblem('Non-standard transmit timestamp returned', tmStmps)
    elif tmStmps["transmit"] > 86400000l:
      informUserAboutTimestampProblem('timestamp returned is greater than the maximum mS in day', tmStmps)
    else:
      timeDiff = tmStmps["transmit"] - tmStmps["originate"]
      if optns["debug"]:
        informUserAboutTimestamps( tmStmps )
  return tmStmps, timeDiff


# Use a Raw Socket (SOCK_RAW) by default, but use SOCK_DGRAM if on Apple Mac OSX
# or forced by the dgram option
def socket():
  if options["dgram"]:
    return _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM, _socket.IPPROTO_ICMP)
  elif sys.platform != 'darwin':
    return _socket.socket(_socket.AF_INET, _socket.SOCK_RAW, _socket.IPPROTO_ICMP)
  else:
    return _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM, _socket.IPPROTO_ICMP)


def printTargetNameAndOrIP_Address(name,ipAddress):
  print '"%s"' % name,
  if name != str(ipAddress):
    print '(%s)' % str(ipAddress),


def informUserIfRequired(level, message, data):
  if options["debug"]:
    labelAndPrintDataStringInHex(message,data)
  elif options["verbose"]:
    if level > 1:
      print message
  elif level > 0:
    print message

def isNotAnIPv4_Packet( data ):
  if len(data) < 2:
    return True
  versionHdrLen, _ = struct.unpack('!BB', data[:2])
  return (versionHdrLen & 0xf0) != 0x40


def getHdrLengthOfAnIPv4_Packet( data ):
  if isNotAnIPv4_Packet(data):
    return 0
  elif len(data) < 2:
    return len(data)
  versionHdrLen, _ = struct.unpack('!BB', data[:2])
  return (versionHdrLen & 0xf) * 4


def isNotAnIPv4_ICMP_Packet( data ):
  if isNotAnIPv4_Packet(data):
    return True
  elif len(data) < 12:
    return True
  protocolByte, _ = struct.unpack('!BH', data[9:12])
  return protocolByte != 0x1


def isNotAnIPv4_ICMP_EchoReplyPacket( data ):
  if isNotAnIPv4_ICMP_Packet(data):
    return True
  hdrLength = getHdrLengthOfAnIPv4_Packet(data)
  if len(data) < (hdrLength + 2):
    return True
  icmpType, icmpCode = struct.unpack('!BB', data[hdrLength:hdrLength + 2])
  if options["debug"]:
    print 'isNotAnIPv4_ICMP_EchoReplyPacket(): icmpType', icmpType, 'icmpCode', icmpCode
  return icmpType != ICMP_ECHO_REPLY


def isAnIPv4_ICMP_OfType( ICMP_TYPE, data ):
  if isNotAnIPv4_ICMP_Packet(data):
    return False
  hdrLength = getHdrLengthOfAnIPv4_Packet(data)
  if len(data) < (hdrLength + 8):
    return False
  icmpType, icmpCode = struct.unpack('!BB', data[hdrLength:hdrLength + 2])
  if options["debug"]:
    print 'isAnIPv4_ICMP_OfType(', ICMP_TYPE, '): icmpType', icmpType, 'icmpCode', icmpCode
  return icmpType == ICMP_TYPE


def isAnIPv4_ICMP_EchoReplyPacket( data ):
  return isAnIPv4_ICMP_OfType( ICMP_ECHO_REPLY, data )


def isAnIPv4_ICMP_TimestampReplyPacket( data ):
  return isAnIPv4_ICMP_OfType( ICMP_TIMESTAMP_REPLY, data )


def isAnIPv4_ICMP_DestinationUnreachablePacket( data ):
  return isAnIPv4_ICMP_OfType( ICMP_DESTINATION_UNREACHABLE, data )


def isThisDestinationUnreachableA_ResponseToThePacketWeSent( transmittedPacket, receivedPacket, peer ):
  result = False
  if options["debug"]:
    print 'Entering isThisDestinationUnreachableA_ResponseToThePacketWeSent()'
  ip4_Hdr, ip4_Data = parseIP4_PacketHeader(receivedPacket, options)
  if ip4_Hdr["prot"] == 0x01:  # Should be redundant, but ignore the received packet if it is not ICMP
    icmpHdr, icmpPayload = parseICMP_Data(ip4_Data)
    if options["debug"]:
      print 'Received an ICMP (%d (0x%02x)) packet from %s' % (icmpHdr["ICMP_Type"],icmpHdr["ICMP_Type"],peer[0])
    if icmpHdr["ICMP_Type"] == ICMP_DESTINATION_UNREACHABLE:  # Should be redundant, but check for Unreachable Error Indication
      icmpPayload = uncookIP4_PacketHeaderIfRequired(icmpPayload)  # Unwind possible MacOS X changes to header info
      errPktHdr, errPktPayload = parseIP4_PacketHeader(icmpPayload, options)
      if options["debug"]:
        print 'Received the following ICMP Destination Unreachable packet; -'
        printIP4_Header(errPktHdr)
        printDataStringInHex(errPktPayload)
      if errPktHdr["prot"] == 0x01:  # Was the sent packet that resulted in this reply an ICMP packet
        errPktPayloadAsICMP_Hdr, _ = parseICMP_Data(errPktPayload)
        if options["debug"]:
          print 'The ICMP header that caused the Destination Unreachable reply is; -'
          printICMP_Header(errPktPayloadAsICMP_Hdr)
        result = compareDataStrings(errPktPayload,transmittedPacket)  # Compare sent packet ICMP header with reply
  return result


def pingWithICMP_ECHO_REQUEST_Packet(address, addr, optns):
  exitLoopFlag = False
  if optns["debug"]:
    print '\n--- Attempting to get ICMP echo (ping) from',
    printTargetNameAndOrIP_Address(address, addr)
    print
  try:
    s = socket()
    s.settimeout(2)
  # Build an ICMP Echo Request Packet
    pingPacket = constructICMP_ECHO_REQUEST_Packet(1)
    if optns["debug"]:
      print '\n----------- ICMP Echo Request is; -'
      ICMP_Hdr, ICMP_Payload = parseICMP_Data(pingPacket)
      printICMP_Header(ICMP_Hdr)
      printDataStringInHex(ICMP_Payload)
  # Send the ICMP Echo Request
    sentTime = getClockTime()
    s.sendto(pingPacket, (addr, 0))
  # Loop until we get an ICMP Echo Reply Packet or time out
    while True:
    # Note: It appears that Win10 does not send Destination Unreachable ICMP packets
    #  back to through this socket recvfrom() call. This loop code just times out.
      packet, peer = s.recvfrom(2048)
      recvTime = getClockTime()
      if peer[0] != addr:  # Ignore the packet if it is not from the target machine
        informUserIfRequired(0,'Received a packet from another network device',packet)
      elif len(packet) < 28:  # Ignore packets that are too small
        informUserIfRequired(0,'Received a packet that is too small',packet)
      elif isNotAnIPv4_Packet(packet):  # Ignore packets that are not IP v4 packets
        informUserIfRequired(0,'Received a packet that is not IP version 4',packet)
      elif isNotAnIPv4_ICMP_Packet(packet):  # Ignore packets that are not ICMP encapsulated in IP v4
        informUserIfRequired(0,'Received a packet that is not an ICMP datagram',packet)
      elif isAnIPv4_ICMP_EchoReplyPacket(packet):  # Process any packets that are ICMP Echo Reply
      # This is very likely the packet we have been waiting for
        informUserIfRequired(0,'Received a packet that is an ICMP Echo Reply',packet)
        ICMP_EchoRequestTimeStamp = parseICMP_ECHO_REPLY_PacketWithTimeStamp(packet, optns)
        if ICMP_EchoRequestTimeStamp != 0:
          s.close()
          break
      elif isAnIPv4_ICMP_DestinationUnreachablePacket(packet):  # Process any packets that are ICMP Destination Unreachable
      # This is not the packet we have been waiting for but it still shows that the target is alive
        informUserIfRequired(0,'Received a packet that is an ICMP Destination Unreachable',packet) 
        if isThisDestinationUnreachableA_ResponseToThePacketWeSent( pingPacket, packet, peer ):
          ICMP_EchoRequestTimeStamp = 9.9999
          s.close()
          break  
      else:
        informUserIfRequired(0,'Received an ICMP packet, but not an Echo Reply or Destination Unreachable',packet)
    return recvTime - sentTime
  except _socket.error, msg:
    if optns["verbose"]:
      print '?? An error occurred in the Ping',
      printTargetNameAndOrIP_Address(address,addr)
      print 'attempt:', msg
    return 9.999999


def pingWithICMP_TIMESTAMP_REQUEST_Packet(address, addr, optns):
  tDiff = 999999l
  if optns["debug"]:
    print '\n--- Attempting to get ICMP timestamp from',
    printTargetNameAndOrIP_Address(address, addr)
    print
  try:
    s = socket() # Attempt to open a socket
    s.settimeout(2)
  # Build an ICMP Timestamp Request Packet
    originateSequenceNumber = 1
    icmpPacket = constructICMP_TIMESTAMP_REQUEST_Packet(originateSequenceNumber)
    if optns["debug"]:
      print '\n----------- ICMP Timestamp Request is; -'
      ICMP_Hdr, ICMP_Payload = parseICMP_Data(icmpPacket)
      printICMP_Header(ICMP_Hdr)
      printDataStringInHex(ICMP_Payload)
    sentTime = getClockTime()
    s.sendto(icmpPacket, (addr, 0))
  # Loop until we get an ICMP datagram from the target computer
    while True:
      receivedPacket, peer = s.recvfrom(2048)
      recvTime = getClockTime()
      if peer[0] != addr:  # Ignore the packet if it is not from the target machine
        informUserIfRequired(0,'Received a packet from another network device',receivedPacket)
      elif len(receivedPacket) < 28:  # Ignore packets that are too small
        informUserIfRequired(0,'Received a packet that is too small',receivedPacket)
      elif isNotAnIPv4_Packet(receivedPacket):  # Ignore packets that are not IP v4 packets
        informUserIfRequired(0,'Received a packet that is not IP version 4',receivedPacket)
      elif isNotAnIPv4_ICMP_Packet(receivedPacket):  # Ignore packets that are not ICMP encapsulated in IP v4
        informUserIfRequired(0,'Received a packet that is not an ICMP datagram',receivedPacket)
      elif isAnIPv4_ICMP_TimestampReplyPacket(receivedPacket):  # Process any packets that are ICMP Timestamp Reply
      # This is very likely the packet we have been waiting for
        ip4_Hdr, ip4_Data = parseAndCheckIP4_PacketHeader(receivedPacket, optns)
        icmpHdr, icmpPayload = parseICMP_Data(ip4_Data)
        if optns["debug"]:
          printICMP_Header(icmpHdr)
          labelAndPrintDataStringInHex('ICMP Timestamp reply data',icmpPayload)
        if icmpHdr["sequence"] != originateSequenceNumber:  # Ignore the icmp data if sequence number does not match
          if optns["verbose"]:
            print 'Received an ICMP timestamp reply datagram, but the sequence number 0x%04x does not match' % icmpHdr["sequence"]
        else:
          tStamps, tDiff = parseICMP_TIMESTAMP_REPLY_Packet(icmpHdr, icmpPayload, optns)
          if tDiff != 999999l:
            s.close()
            print '"%s"' % address,
            informUserAboutTimestamp('Transmit', tStamps["transmit"])
            break
      elif isAnIPv4_ICMP_DestinationUnreachablePacket(receivedPacket):  # Process any packets that are ICMP Destination Unreachable
      # This is not the packet we have been waiting for but it still shows that the target is alive
        informUserIfRequired(0,'Received a packet that is an ICMP Destination Unreachable',receivedPacket) 
        if isThisDestinationUnreachableA_ResponseToThePacketWeSent( icmpPacket, receievedPacket, peer ):
          s.close()
          break  
      else:
        informUserIfRequired(0,'Received an ICMP packet, but not a Timestamp Reply or Destination Unreachable',receivedPacket)
  except _socket.error, msg:
    if optns["verbose"]:
      print 'Unable to get ICMP timestamp due to:', msg, '\n'
  finally:
    return tDiff


# Obtain the local machines IPv4 address
def getLocalIP():
  s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
  try:
    s.connect(('10.255.255.255', 1))
    localIP = s.getsockname()[0]
  except:
    localIP = '127.0.0.1'  # Susbstitute the loopback address
  finally:
    s.close
  return localIP


def usage():
  print 'Usage:\n%s [-dDhrv] [targetMachine ..[targetMachineN]]' % sys.argv[0]
  print ' where; -\n   -d or --dgram    selects SOCK_DGRAM socket instead of SOCK_RAW socket'
  print '   -D or --debug    prints out Debug information'
  print '   -h or --help     outputs this usage message'
  print '   -r or --reverse  reverses byte order of receive and transmit timestamps (suits MS Windows)'
  print '   -v or --verbose  prints verbose output'
  print '   targetMachine is either the name or IP address of the computer to ping'


# Get options and arguments from the command line
def processCommandLine():
  try:
    opts, args = getopt.getopt(sys.argv[1:], "dDhrv", ["dgram","debug","help","reverse","verbose"])
  except getopt.GetoptError as err:
    print str(err)
    usage()
    sys.exit()
  for o, a in opts:
    if o in ("-d", "--dgram"):
      options["dgram"] = True
    elif o in ("-D", "--debug"):
      options["debug"] = True
    elif o in ("-h", "--help"):
      options["help"] = True
    elif o in ("-r", "--reverse"):
      options["reverse"] = True
    elif o in ("-v", "--verbose"):
      options["verbose"] = True
  if options["debug"]:
  	options["verbose"] = True  # Debug implies verbose output
  return args
 

def printPingTime( trgtAddr, startTime ):
  try:
# Turn Target Computer name into an IP Address if a name was specified
    trgtIP_Addr = _socket.gethostbyname(trgtAddr)
# Ping the specified computer
    travelTime = pingWithICMP_ECHO_REQUEST_Packet(trgtAddr, trgtIP_Addr, options)
    if travelTime <= (getClockTime() - startTime):  # If Ping fails then the travel time is deliberatly set large
      if options["verbose"]:
	print 'Ping round trip time to "%s" was: %9.3f mS.' % (trgtAddr,travelTime * 1000)
    else:
      print 'ping',
      printTargetNameAndOrIP_Address(trgtAddr, trgtIP_Addr)
      print 'failed'
# Get Timestamp from the specified computer
    osTimeDiff = pingWithICMP_TIMESTAMP_REQUEST_Packet(trgtAddr, trgtIP_Addr, options)
    if osTimeDiff != 999999l:  # If icmp timestamp request fails then the time difference is deliberatly set large
      print '"%s" Transmit - Originate timestamps time difference was: %ld mS' % (trgtAddr,osTimeDiff)
    else:
      print 'timestamp request to',
      printTargetNameAndOrIP_Address(trgtAddr, trgtIP_Addr)
      print 'failed'
  except _socket.error, msg:
    print 'Target Computer "%s"' % trgtAddr,
    print 'problem; -'
    print ' "%s"' %  msg


def main():
  startTime = getClockTime()
  args = processCommandLine()
  if options["debug"]:
    print '\nCheck the time on one or more networked devices'
    print '"checktime.py" Python script running on system type "%s"' % sys.platform
  if len(args) < 1:
    print '\n?? Please specify the computer to ping?\n'
    usage()
    localInterface =  getLocalIP()
    print '\nDefaulting to ping the local interface (%s)' % localInterface 
    printPingTime(localInterface, startTime)  # If there is no target specified then use local Interface IP
  else:
    if options["help"]:
      usage()
# Step through timestamp targets specified on the command line
  for trgtAddr in args:
    printPingTime(trgtAddr, startTime)
  if options["debug"]:
    print '\nchecktime.py execution time was: %9.3f mS.\n' % ((getClockTime() - startTime) * 1000)


if __name__ == '__main__':
  main()
