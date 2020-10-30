#! /usr/bin/python2
#
# C H E C K T I M E . P Y
#
# Check the time on another device or computer on the network.
#
# Last Modified on Wed Oct 28 22:40:06 2020
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
import os  # getpid()
import sys  # exit()
import getopt  # getopt()

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

_d_size = struct.calcsize("d")
options = {
    "count": int(1),
    "correction": False,
    "debug": False,
    "dgram": False,
    "file": "",
    "help": False,
    "pause": float(1),
    "noPing": False,
    "rawSck": False,
    "reverse": False,
    "standard": False,
    "noTimeStamp": False,
    "verbose": False,
    "wait": float(2),
}


# Get the most accurate time available on the local system
def getClockTime():
    if sys.platform == "win32":
        systemWallClockTime = _time.clock()
    else:
        systemWallClockTime = _time.time()  # best on most platforms is time.time
    return systemWallClockTime


# Calculate the number of milliseconds since midnight UTC
def calcTimeSinceUTC_Midnight():
    utcnow = datetime.utcnow()
    midnightUTC = datetime.combine(utcnow.date(), time(0))
    delta = utcnow - midnightUTC
    millisecondsSinceMidnight = int(delta.seconds * 1000.0 + delta.microseconds / 1000.0)
    return millisecondsSinceMidnight


# Convert milliseconds to hours, minutes and seconds format
def convertMillisecondsSinceMidnight(milliseconds):
    msecs = milliseconds % 1000L
    hrs = milliseconds / 3600000L
    mins = (milliseconds - (hrs * 3600000L)) / 60000L
    secs = (milliseconds - (hrs * 3600000L + mins * 60000L)) / 1000L
    mS_Time = {"hours": hrs, "minutes": mins, "seconds": secs, "milliSeconds": msecs}
    return mS_Time


# Calculate 16 bit check sum for a data string
#  (mostly borrowed from scapy's utils.py)
def calcChecksum(dataString):
    if len(dataString) % 2 == 1:  # test for odd number of bytes in the string
        dataString += "\0"  # add extra zero to make even number of bytes
    s = sum(array.array("H", dataString))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    s = ~s
    if struct.pack("=H", 1) != struct.pack("!H", 1):  # handle endianess of architecture
        s = ((s >> 8) & 0xFF) | s << 8  # swap checksum bytes if little endian
    return s & 0xFFFF


# Construct the ICMP header and add it to the ICMP body data
def constructICMP_Datagram(icmpType, pid, seq, payload):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    headerSansCheckSum = struct.pack("!BBHHH", icmpType, 0, 0, pid, seq)
    chckSum = calcChecksum(headerSansCheckSum + payload)
    header = struct.pack("!BBHHH", icmpType, 0, chckSum, pid, seq)
    return header + payload


# Construct an ICMP Echo Request
def constructICMP_ECHO_REQUEST_Packet(pid, seq, packetsize=56):
    padding = (packetsize - _d_size) * b"Q"
    timeinfo = struct.pack("!d", getClockTime())
    return constructICMP_Datagram(ICMP_ECHO_REQUEST, pid, seq, timeinfo + padding)


# Construct an ICMP Time Stamp Request
def constructICMP_TIMESTAMP_REQUEST_Packet(pid, seq):
    originateTime = struct.pack(
        "!L", calcTimeSinceUTC_Midnight()
    )  # put timestamp as unsigned long in network order
    receiveTime = struct.pack("!L", 0L)
    transmitTime = struct.pack("!L", 0L)
    return constructICMP_Datagram(
        ICMP_TIMESTAMP_REQUEST, pid, seq, originateTime + receiveTime + transmitTime
    )


# Print a Hex dump of a string of data
def printDataStringInHex(dataString):
    length = len(dataString)
    for cnt in xrange(0, length, 1):
        if (cnt % 16) == 0:
            print "\n%04u: %02x" % (cnt, ord(dataString[cnt])),
        else:
            print "%02x" % ord(dataString[cnt]),
    print


def labelAndPrintDataStringInHex(label, dataString):
    print label,
    printDataStringInHex(dataString)


# Compare two strings of data up to the length of the shorter data string
def compareDataStrings(dataStr1, dataStr2):
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
    print "IP ver .. ", header["ver"]
    print "IP hdr len", header["hdr_len"]
    print "dscp ... 0x%02x " % header["dscp"]
    print "totl len %u" % header["totl_len"]
    print "id ..... 0x%04x " % header["pkt_id"]
    print "frag ... 0x%04x " % header["frag"]
    print "ttl ....", header["ttl"]
    print "proto .. 0x%02x " % header["prot"]
    print "csum ... 0x%04x " % header["csum"]
    print "src IP . %03u.%03u.%03u.%03u" % (
        header["s1"],
        header["s2"],
        header["s3"],
        header["s4"],
    )
    print "dst IP . %03u.%03u.%03u.%03u" % (
        header["d1"],
        header["d2"],
        header["d3"],
        header["d4"],
    )
    return


# Unpack the header of a version 4 IP packet
def parseIP4_PacketHeader(data, options):
    # Unpack the IPv4 Header
    (
        ver,
        dscp,
        totl_len,
        pkt_id,
        frag,
        ttl,
        prot,
        csum,
        s1,
        s2,
        s3,
        s4,
        d1,
        d2,
        d3,
        d4,
    ) = struct.unpack("!BBHHHBBHBBBBBBBB", data[:20])
    hdr_len = (ver & 0xF) * 4
    ver = (ver >> 4) & 0xF
    ipv4Hdr = {
        "ver": ver,
        "hdr_len": hdr_len,
        "dscp": dscp,
        "totl_len": totl_len,
        "pkt_id": pkt_id,
        "frag": frag,
        "ttl": ttl,
        "prot": prot,
        "csum": csum,
        "s1": s1,
        "s2": s2,
        "s3": s3,
        "s4": s4,
        "d1": d1,
        "d2": d2,
        "d3": d3,
        "d4": d4,
    }
    return ipv4Hdr, data[hdr_len:]


# Uncook the header on a Mac
def uncookIP4_PacketHeaderIfRequired(inData):
    if sys.platform == "darwin":  # Undo MacOS cooking some IP4 header fields
        ver, dscp, tl1, tl2, b1, b2, fragLen = struct.unpack("=BBBBBBH", inData[:8])
        totalLen = 256 * tl2 + tl1 + ((ver & 0xF) * 4)
        tmpData = struct.pack("!BBHBBH", ver, dscp, totalLen, b1, b2, fragLen)
        return tmpData + inData[8:]
    else:
        return inData


# Unpack and Check the header of a version 4 IP packet
def parseAndCheckIP4_PacketHeader(data, optns):
    data = uncookIP4_PacketHeaderIfRequired(data)
    parsedIPv4_Hdr, parsedIPv4_Payload = parseIP4_PacketHeader(data, options)
    # Check to see if the local interface is being used; i.e. src == dest
    srcAddr, destAddr = struct.unpack("!LL", data[12:20])
    # If local interface then don't check the checksum of the packet
    if srcAddr == destAddr:
        chckSum = 0
    else:
        chckSum = calcChecksum(data)
    if chckSum != 0:
        print "\n?? The IPv4 packet check sum calculates to 0x%04x not zero" % chckSum
    if optns["debug"]:
        print "The header of the IPv4 packet received was; -"
        printIP4_Header(parsedIPv4_Hdr)
        labelAndPrintDataStringInHex("The IPv4 packet received in hex format; -", data)
    return parsedIPv4_Hdr, parsedIPv4_Payload


def printICMP_Header(header):
    print "ICMP type ... 0x%02x " % header["ICMP_Type"]
    print "ICMP code ... 0x%02x " % header["code"]
    print "ICMP checksum 0x%04x " % header["checksum"]
    print "ICMP id ..... 0x%04x " % header["id"]
    print "ICMP sequence 0x%04x " % header["sequence"]
    return


def parseICMP_Data(data):
    type, code, checksum, id, sequence = struct.unpack("!BBHHH", data[:8])
    ICMP_Header = {
        "ICMP_Type": type,
        "code": code,
        "checksum": checksum,
        "id": id,
        "sequence": sequence,
    }
    return ICMP_Header, data[8:]


def parseAndCheckICMP_Data(data):
    ICMP_Header, ICMP_Payload = parseICMP_Data(data)
    chckSum = calcChecksum(data)
    if chckSum != 0:
        print "\n?? The ICMP check sum test failed (it calculates to 0x%04x, not 0)" % chckSum
        chckSum = calcChecksum(data[:8])
        print "?? The ICMP Header check sum calculates to 0x%04x" % chckSum
    if options["debug"]:
        print "The header of the ICMP datagram is; -"
        printICMP_Header(ICMP_Header)
        labelAndPrintDataStringInHex("The ICMP datagram in hex format is; -", data)
    return ICMP_Header, ICMP_Payload


def parseICMP_ECHO_REPLY_PacketWithTimeStamp(data, optns):
    #  print 'Entering parseICMP_ECHO_REPLY_PacketWithTimeStamp()'
    if optns["dgram"]:  # Process all SOCK_DGRAM socket returned packets
        if (
            sys.platform == "linux2"
        ):  # linux SOCK_DGRAM socket returns do not have IP4 header
            hdr, payload = parseAndCheckICMP_Data(data)
        else:  # non-linux SOCK_DGRAM socket returns have an IP4 header
            _, icmpData = parseAndCheckIP4_PacketHeader(data, optns)
            hdr, payload = parseAndCheckICMP_Data(icmpData)
    else:  # Process all SOCK_RAW socket returned information
        _, icmpData = parseAndCheckIP4_PacketHeader(data, optns)
        hdr, payload = parseAndCheckICMP_Data(icmpData)
    if hdr["ICMP_Type"] == ICMP_ECHO_REPLY:
        timeStamp = struct.unpack("!d", payload[:_d_size])[0]
        if optns["debug"]:
            print "\nICMP (type %d, code %d) packet received is an ICMP Echo Reply" % (
                hdr["ICMP_Type"],
                hdr["code"],
            )
    else:
        timeStamp = 0
        if optns["debug"]:
            print "----------- Reply to ICMP Echo Request was; -"
            print "?? ICMP (type %d) packet received is not an ICMP Echo Reply" % hdr[
                "ICMP_Type"
            ]
            printICMP_Header(hdr)
            labelAndPrintDataStringInHex(
                "The data in the unexpected ICMP datagram is; -", payload
            )
    #  print 'Leaving parseICMP_ECHO_REPLY_PacketWithTimeStamp()'
    return timeStamp


def printTimeStampAsHrsMinSecsSinceMidnight(timeStamp):
    tsTm = convertMillisecondsSinceMidnight(timeStamp)
    print "%02ld:%02ld:%02ld.%03ld" % (
        tsTm["hours"],
        tsTm["minutes"],
        tsTm["seconds"],
        tsTm["milliSeconds"],
    ),


def informUserAboutTimestamp(msg, timeStamp):
    print msg, "timestamp returned was",
    printTimeStampAsHrsMinSecsSinceMidnight(timeStamp)
    if options["verbose"]:
        print "(%ld (0x%08x) mS since midnight UTC)" % (timeStamp, timeStamp)
    else:
        print


def informUserAboutTimestamps(timestamps):
    informUserAboutTimestamp("Originate", timestamps["originate"])
    informUserAboutTimestamp("Received", timestamps["received"])
    informUserAboutTimestamp("Transmit", timestamps["transmit"])


def informUserAboutTimestampProblem(msg, timeStamps):
    print "\n?? ", msg
    informUserAboutTimestamps(timeStamps)
    print "!! Hint: If target computer is running MS Windows try the -m (--microsoft) option"


def parseICMP_TIMESTAMP_REPLY_Packet(hdr, payload, optns):
    parsedOk = False
    tmStmps = {
        "originate": 0L,
        "received": 0L,
        "transmit": 0L,
        "compensation": 0L,
        "difference": 0L,
    }  # preset timestamps to 0
    if optns["debug"]:
        print "\n----------- ICMP Time Stamp Reply is; -"
        printICMP_Header(hdr)
        labelAndPrintDataStringInHex("The data in the ICMP datagram is; -", payload)
    if len(payload) < 12:  # Check length of data which should contain 3 timestamps
        print "?? Expected at least 3 * 4 byte reply, but got", len(payload)
        if optns["verbose"]:
            labelAndPrintDataStringInHex("The truncated ICMP data in hex is; -", payoad)
    else:
        ot, rt, tt = struct.unpack(
            "!lll", payload[:12]
        )  # unpack in signed standard network order
        uot, urt, utt = struct.unpack(
            "!LLL", payload[:12]
        )  # unpack in unsigned standard network order
        rot, rrt, rtt = struct.unpack(
            "<lll", payload[:12]
        )  # unpack in signed little endian order
        ruot, rurt, rutt = struct.unpack(
            "<LLL", payload[:12]
        )  # unpack in unsigned little endian order
        if (tt <= 86400000 and tt >= 0) and (
            rtt <= 86400000 and rtt >= 0
        ):  # if both big and little endian representations are in the valid range then
            optns["standard"] = (
                abs(tt - ot) <= abs(rtt - ot) and not optns["reverse"]
            )  # force big endian if it gives smaller diff unless -m was specified
        if optns["standard"] or (
            (not optns["reverse"]) and (tt <= 86400000 and tt >= 0)
        ):  # use Big endian byte order
            tmStmps[
                "originate"
            ] = ot  # set signed originate value, which is assumed to be in proper format
            tmStmps["received"] = rt  # set signed received stamp value
            tmStmps["transmit"] = tt  # set signed transmit stamp value
            utmStmps = {
                "originate": uot,
                "received": urt,
                "transmit": utt,
            }  # set (at least) originate
            if optns["debug"]:
                print "Big endian byte order used to process returned timestamps"
        elif optns["reverse"] or (
            rtt <= 86400000 and rtt >= 0
        ):  # use Little endian byte order on returned timestamps
            tmStmps[
                "originate"
            ] = ot  # set signed originate value, which is assumed to be in proper format
            tmStmps["received"] = rrt  # set signed received stamp value
            tmStmps["transmit"] = rtt  # set signed transmit stamp value
            utmStmps = {
                "originate": ruot,
                "received": rurt,
                "transmit": rutt,
            }  # set (at least) originate
            if optns["debug"]:
                print "Little endian byte order used to process returned timestamps"
        else:  # Catch all is to assume big endian even though out of valid range
            tmStmps[
                "originate"
            ] = ot  # set signed originate value, which is assumed to be in proper format
            tmStmps["received"] = rt  # set signed big endian received stamp value
            tmStmps["transmit"] = tt  # set signed big endian transmit stamp value
            utmStmps = {
                "originate": uot,
                "received": urt,
                "transmit": utt,
            }  # set (at least) originate
            if optns["debug"]:
                print "Big endian byte order used to process returned timestamps"
        if (
            tmStmps["transmit"] < 0
        ):  # A minus value indicates a non-standard timestamp is flagged
            informUserAboutTimestampProblem(
                "Non-standard transmit timestamp returned", utmStmps
            )
            tmStmps["received"] = long(
                0x7FFFFFFF & utmStmps["received"]
            )  # try removing non-standard bit
            tmStmps["transmit"] = long(
                0x7FFFFFFF & utmStmps["transmit"]
            )  # try removing non-standard bit
        if (
            tmStmps["transmit"] > 86400000
        ):  # 86400000 mS is a normal day but could be in too low on special days when leap seconds are added
            informUserAboutTimestampProblem(
                "timestamp returned is greater than the maximum mS in day", tmStmps
            )
        else:
            parsedOk = True
            if optns["debug"]:
                informUserAboutTimestamps(tmStmps)
    return parsedOk, tmStmps


# Use a Raw Socket (SOCK_RAW) by default, but use SOCK_DGRAM if on Apple Mac OSX
# or forced by the dgram option
def socket():
    if options["dgram"]:
        return _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM, _socket.IPPROTO_ICMP)
    elif options["rawSck"]:
        return _socket.socket(_socket.AF_INET, _socket.SOCK_RAW, _socket.IPPROTO_ICMP)
    elif sys.platform != "darwin":
        return _socket.socket(_socket.AF_INET, _socket.SOCK_RAW, _socket.IPPROTO_ICMP)
    else:
        return _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM, _socket.IPPROTO_ICMP)


def printTargetNameAndOrIP_Address(name, ipAddress):
    print '"%s"' % name,
    if name != str(ipAddress):
        print "(%s)" % str(ipAddress),


def informUserIfRequired(level, message, data):
    if options["debug"]:
        labelAndPrintDataStringInHex(message, data)
    elif options["verbose"]:
        if level > 1:
            print message
    elif level > 0:
        print message


def isNotAnIPv4_Packet(data):
    if len(data) < 2:
        return True
    versionHdrLen, _ = struct.unpack("!BB", data[:2])
    return (versionHdrLen & 0xF0) != 0x40


def getHdrLengthOfAnIPv4_Packet(data):
    if isNotAnIPv4_Packet(data):
        return 0
    elif len(data) < 2:
        return len(data)
    versionHdrLen, _ = struct.unpack("!BB", data[:2])
    return (versionHdrLen & 0xF) * 4


def isNotAnIPv4_ICMP_Packet(data):
    if isNotAnIPv4_Packet(data):
        return True
    elif len(data) < 12:
        return True
    protocolByte, _ = struct.unpack("!BH", data[9:12])
    return protocolByte != 0x1


def isNotAnIPv4_ICMP_EchoReplyPacket(data):
    if isNotAnIPv4_ICMP_Packet(data):
        return True
    hdrLength = getHdrLengthOfAnIPv4_Packet(data)
    if len(data) < (hdrLength + 2):
        return True
    icmpType, icmpCode = struct.unpack("!BB", data[hdrLength : hdrLength + 2])
    if options["debug"]:
        print "isNotAnIPv4_ICMP_EchoReplyPacket(): icmpType", icmpType, "icmpCode", icmpCode
    return icmpType != ICMP_ECHO_REPLY


def isAnIPv4_ICMP_OfType(ICMP_TYPE, data):
    if isNotAnIPv4_ICMP_Packet(data):
        return False
    hdrLength = getHdrLengthOfAnIPv4_Packet(data)
    if len(data) < (hdrLength + 8):
        return False
    icmpType, icmpCode = struct.unpack("!BB", data[hdrLength : hdrLength + 2])
    if options["debug"]:
        print "isAnIPv4_ICMP_OfType(", ICMP_TYPE, "): icmpType", icmpType, "icmpCode", icmpCode
    return icmpType == ICMP_TYPE


def isAnIPv4_ICMP_EchoReplyPacket(data):
    return isAnIPv4_ICMP_OfType(ICMP_ECHO_REPLY, data)


def isAnIPv4_ICMP_TimestampReplyPacket(data):
    return isAnIPv4_ICMP_OfType(ICMP_TIMESTAMP_REPLY, data)


def isAnIPv4_ICMP_DestinationUnreachablePacket(data):
    return isAnIPv4_ICMP_OfType(ICMP_DESTINATION_UNREACHABLE, data)


def isThisDestinationUnreachableA_ResponseToThePacketWeSent(
    transmittedPacket, receivedPacket, peer
):
    result = False
    if options["debug"]:
        print "Entering isThisDestinationUnreachableA_ResponseToThePacketWeSent()"
    ip4_Hdr, ip4_Data = parseIP4_PacketHeader(receivedPacket, options)
    if (
        ip4_Hdr["prot"] == 0x01
    ):  # Should be redundant, but ignore the received packet if it is not ICMP
        icmpHdr, icmpPayload = parseAndCheckICMP_Data(ip4_Data)
        if options["debug"]:
            print "Received an ICMP (%d (0x%02x)) packet from %s" % (
                icmpHdr["ICMP_Type"],
                icmpHdr["ICMP_Type"],
                peer[0],
            )
        if (
            icmpHdr["ICMP_Type"] == ICMP_DESTINATION_UNREACHABLE
        ):  # Should be redundant, but check for Unreachable Error Indication
            icmpPayload = uncookIP4_PacketHeaderIfRequired(
                icmpPayload
            )  # Unwind possible MacOS X changes to header info
            errPktHdr, errPktPayload = parseIP4_PacketHeader(icmpPayload, options)
            if options["debug"]:
                print "Received the following ICMP Destination Unreachable packet; -"
                printIP4_Header(errPktHdr)
                printDataStringInHex(errPktPayload)
            if (
                errPktHdr["prot"] == 0x01
            ):  # Was the sent packet that resulted in this reply an ICMP packet
                errPktPayloadAsICMP_Hdr, _ = parseAndCheckICMP_Data(errPktPayload)
                if options["debug"]:
                    print "The ICMP header that caused the Destination Unreachable reply is; -"
                    printICMP_Header(errPktPayloadAsICMP_Hdr)
                result = compareDataStrings(
                    errPktPayload, transmittedPacket
                )  # Compare sent packet ICMP header with reply
    return result


def pingWithICMP_ECHO_REQUEST_Packet(address, addr, optns, pid):
    exitLoopFlag = False
    if optns["debug"]:
        print "\n--- Attempting to get ICMP echo (ping) from",
        printTargetNameAndOrIP_Address(address, addr)
        print
    try:
        s = socket()
        s.settimeout(optns["wait"])
        # Build an ICMP Echo Request Packet
        pingPacket = constructICMP_ECHO_REQUEST_Packet(pid, 1)
        if optns["debug"]:
            print "\n----------- ICMP Echo Request is; -"
            ICMP_Hdr, ICMP_Payload = parseAndCheckICMP_Data(pingPacket)
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
            if (
                peer[0] != addr
            ):  # Ignore the packet if it is not from the target machine
                informUserIfRequired(
                    0, "Received a packet from another network device", packet
                )
            elif len(packet) < 28:  # Ignore packets that are too small
                informUserIfRequired(0, "Received a packet that is too small", packet)
            elif isNotAnIPv4_Packet(
                packet
            ):  # Ignore packets that are not IP v4 packets
                informUserIfRequired(
                    0, "Received a packet that is not IP version 4", packet
                )
            elif isNotAnIPv4_ICMP_Packet(
                packet
            ):  # Ignore packets that are not ICMP encapsulated in IP v4
                informUserIfRequired(
                    0, "Received a packet that is not an ICMP datagram", packet
                )
            elif isAnIPv4_ICMP_EchoReplyPacket(
                packet
            ):  # Process any packets that are ICMP Echo Reply
                # This is very likely the packet we have been waiting for
                informUserIfRequired(
                    0, "Received a packet that is an ICMP Echo Reply", packet
                )
                ICMP_EchoRequestTimeStamp = parseICMP_ECHO_REPLY_PacketWithTimeStamp(
                    packet, optns
                )
                if ICMP_EchoRequestTimeStamp != 0:
                    s.close()
                    break
            elif isAnIPv4_ICMP_DestinationUnreachablePacket(
                packet
            ):  # Process any packets that are ICMP Destination Unreachable
                # This is not the packet we have been waiting for but it still shows that the target is alive
                informUserIfRequired(
                    0,
                    "Received a packet that is an ICMP Destination Unreachable",
                    packet,
                )
                if isThisDestinationUnreachableA_ResponseToThePacketWeSent(
                    pingPacket, packet, peer
                ):
                    informUserIfRequired(
                        0,
                        "The ICMP Destination Unreachable was in response to our Echo Request",
                        packet,
                    )
                    ICMP_EchoRequestTimeStamp = 9.9999
                    s.close()
                    break
                else:
                    informUserIfRequired(
                        0,
                        "The ICMP Destination Unreachable was not in response to our Echo Request",
                        packet,
                    )
            else:
                informUserIfRequired(
                    0,
                    "Received an ICMP packet, but not an Echo Reply or Destination Unreachable",
                    packet,
                )
        return recvTime - sentTime
    except _socket.timeout, msg:
        if optns["verbose"]:
            printTargetNameAndOrIP_Address(address, addr)
            print "%s sec wait for ping reply %s" % (optns["wait"], msg)
        return 9.999999
    except _socket.error, msg:
        if optns["verbose"]:
            printTargetNameAndOrIP_Address(address, addr)
            print "ping attempt failed due to: %s" % msg
        return 9.999999


def calculateMostLikelyTimeDifference(
    remote_ms_sinceMidnight, local_ms_sinceMidnight, compensation
):
    tDiff = remote_ms_sinceMidnight - local_ms_sinceMidnight - compensation
    if abs(tDiff) > 43200000L:
        if remote_ms_sinceMidnight < 43200000L:
            tDiff += 86400000L
        else:
            tDiff -= 86400000L
    return tDiff


def pingWithICMP_TIMESTAMP_REQUEST_Packet(
    address, addr, optns, pid, originateSequenceNumber
):
    success = False
    tStamps = {
        "originate": 0L,
        "received": 0L,
        "transmit": 0L,
        "compensation": 0L,
        "difference": 0L,
    }  # preset timestamps to 0
    if optns["debug"]:
        print "\n--- Attempting to get ICMP timestamp from",
        printTargetNameAndOrIP_Address(address, addr)
        print
    try:
        s = socket()  # Attempt to open a socket
        s.settimeout(optns["wait"])
        # Build an ICMP Timestamp Request Packet
        icmpTsReqPckt = constructICMP_TIMESTAMP_REQUEST_Packet(
            pid, originateSequenceNumber
        )
        ICMP_TsReqHdr, ICMP_TsReqPayload = parseAndCheckICMP_Data(icmpTsReqPckt)
        if optns["debug"]:
            print "\n----------- ICMP Timestamp Request is; -"
            printICMP_Header(ICMP_TsReqHdr)
            printDataStringInHex(ICMP_TsReqPayload)
        sentTime = getClockTime()
        s.sendto(icmpTsReqPckt, (addr, 0))
        # Loop until we get an ICMP datagram from the target computer
        while True:
            receivedPacket, peer = s.recvfrom(2048)
            recvTime = getClockTime()
            if (
                peer[0] != addr
            ):  # Ignore the packet if it is not from the target machine
                informUserIfRequired(
                    0, "Received a packet from another network device", receivedPacket
                )
            elif len(receivedPacket) < 28:  # Ignore packets that are too small
                informUserIfRequired(
                    0, "Received a packet that is too small", receivedPacket
                )
            elif isNotAnIPv4_Packet(
                receivedPacket
            ):  # Ignore packets that are not IP v4 packets
                informUserIfRequired(
                    0, "Received a packet that is not IP version 4", receivedPacket
                )
            elif isNotAnIPv4_ICMP_Packet(
                receivedPacket
            ):  # Ignore packets that are not ICMP encapsulated in IP v4
                informUserIfRequired(
                    0, "Received a packet that is not an ICMP datagram", receivedPacket
                )
            elif isAnIPv4_ICMP_TimestampReplyPacket(
                receivedPacket
            ):  # Process any packets that are ICMP Timestamp Reply
                # This is very likely the packet we have been waiting for
                ip4_Hdr, ip4_Data = parseAndCheckIP4_PacketHeader(receivedPacket, optns)
                icmpHdr, icmpPayload = parseAndCheckICMP_Data(ip4_Data)
                if optns["debug"]:
                    printICMP_Header(icmpHdr)
                    labelAndPrintDataStringInHex(
                        "ICMP Timestamp reply data", icmpPayload
                    )
                if (
                    icmpHdr["sequence"] != originateSequenceNumber
                ):  # Ignore the icmp data if sequence number does not match
                    if optns["verbose"]:
                        print "Received an ICMP timestamp reply datagram, but the sequence number 0x%04x does not match" % icmpHdr[
                            "sequence"
                        ]
                else:
                    success, tStamps = parseICMP_TIMESTAMP_REPLY_Packet(
                        icmpHdr, icmpPayload, optns
                    )
                    if success:
                        travelTime = recvTime - sentTime
                        if optns["correction"]:
                            # Calculate time difference in mS as straight forward subtraction - correction 0 mS
                            tStamps["compensation"] = 0L
                        else:
                            # Calculate time difference using naive correction of half the Round Trip Time in mS
                            tStamps["compensation"] = long(500.0 * travelTime)
                        tStamps["difference"] = calculateMostLikelyTimeDifference(
                            tStamps["transmit"],
                            tStamps["originate"],
                            tStamps["compensation"],
                        )
                        s.close()
                        if options["debug"]:
                            print "icmp timestamp round trip time was %9.3f mS" % (
                                travelTime * 1000
                            )
                        break
            elif isAnIPv4_ICMP_DestinationUnreachablePacket(
                receivedPacket
            ):  # Process any packets that are ICMP Destination Unreachable
                # This is not the packet we have been waiting for but it still shows that the target is alive
                informUserIfRequired(
                    0,
                    "Received a packet that is an ICMP Destination Unreachable",
                    receivedPacket,
                )
                if isThisDestinationUnreachableA_ResponseToThePacketWeSent(
                    icmpTsReqPckt, receivedPacket, peer
                ):
                    informUserIfRequired(
                        0,
                        "The ICMP Destination Unreachable was in response to our Timestamp Request",
                        receivedPacket,
                    )
                    s.close()
                    break
                else:
                    informUserIfRequired(
                        0,
                        "The ICMP Destination Unreachable was not in response to our Timestamp Request",
                        receivedPacket,
                    )
            else:
                informUserIfRequired(
                    0,
                    "Received an ICMP packet, but not a Timestamp Reply or Destination Unreachable",
                    receivedPacket,
                )
    except _socket.timeout, msg:
        if optns["verbose"]:
            printTargetNameAndOrIP_Address(address, addr)
            print "%s sec wait for timestamp reply %s" % (optns["wait"], msg)
    except _socket.error, msg:
        if optns["verbose"]:
            printTargetNameAndOrIP_Address(address, addr)
            print "timestamp acquisition failed due to: %s" % msg
    finally:
        return success, tStamps


# Obtain the local machines IPv4 address
def getLocalIP():
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        localIP = s.getsockname()[0]
    except:
        localIP = "127.0.0.1"  # Susbstitute the loopback address
    finally:
        s.close
    return localIP


def usage():
    print "Usage:\n%s [-cXCdDhmpX.XrvwX.X] [targetMachine ..[targetMachineN]]" % sys.argv[
        0
    ]
    print " where; -\n   -cX              send count timestamp requests with pause separation"
    print "   -C or --correction   disable naive half RTT correction to time difference"
    print "   -d or --dgram    selects SOCK_DGRAM socket instead of SOCK_RAW socket"
    print "   -D or --debug    prints out Debug information"
    print "   -fABC.DEF        specify target machines in a text file"
    print "   -h or --help     outputs this usage message"
    print "   -m or --microsoft  reverses byte order of receive and transmit timestamps (suits MS Windows)"
    print "   -pX.X            pause X.X sec between multiple timestamp requests"
    print "   -P or --no-ping  don't send ICMP echo request"
    print "   -r or --raw      selects SOCK_RAW but is over-ridden by -d or --dgram"
    print "   -s or --standard selects SOCK_DGRAM"
    print "   -T or --no-time-stamp  don't send ICMP time stamp request"
    print "   -v or --verbose  prints verbose output"
    print "   -wX.X            wait X.X sec instead of default 2 sec before timing-out"
    print "   targetMachine is either the name or IP address of the computer to ping"
    print " E.g.; -"
    print "   ", sys.argv[0], " -v -w5 127.0.0.1"


# Get options and arguments from the command line
def processCommandLine():
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "c:CdDf:hmp:PrsTvw:",
            [
                "",
                "correction",
                "dgram",
                "debug",
                "",
                "help",
                "microsoft",
                "",
                "no-ping",
                "raw",
                "standard",
                "no-time-stamp",
                "verbose",
                "",
            ],
        )
    except getopt.GetoptError as err:
        print str(err)
        usage()
        sys.exit()
    for o, a in opts:
        if o in ("-c", "--count"):
            options["count"] = int(a)
            if options["count"] < 1:
                options["count"] = 1
        elif o in ("-C", "--correction"):
            options["correction"] = True
        elif o in ("-d", "--dgram"):
            options["dgram"] = True
        elif o in ("-D", "--debug"):
            options["debug"] = True
        elif o in ("-f", "--file"):
            options["file"] = a
        elif o in ("-h", "--help"):
            options["help"] = True
        elif o in ("-m", "--microsoft"):
            options["reverse"] = True
        elif o in "-p":
            options["pause"] = float(a)
            if options["pause"] < 0.0:
                options["pause"] = 0.0
        elif o in ("-P", "--no-ping"):
            options["noPing"] = True
        elif o in ("-r", "--raw"):
            options["rawSck"] = True
        elif o in ("-s", "--standard"):
            options["standard"] = True
        elif o in ("-T", "--no-time-stamp"):
            options["noTimeStamp"] = True
        elif o in ("-v", "--verbose"):
            options["verbose"] = True
        elif o in "-w":
            options["wait"] = float(a)
            if options["wait"] < 0.0:
                options["wait"] = 0.0
    if options["debug"]:
        options["verbose"] = True  # Debug implies verbose output
    if options["standard"] and options["reverse"]:
        options["reverse"] = False  # standard option mutually exclusive of reverse
    return args


def pingAndPrintTimeStamp(trgtAddr, startTime, pid):
    try:
        # Turn Target Computer name into an IP Address if a name was specified
        trgtIP_Addr = _socket.gethostbyname(trgtAddr)
        # Ping the specified computer unless noPing option is true
        if not options["noPing"]:
            travelTime = pingWithICMP_ECHO_REQUEST_Packet(
                trgtAddr, trgtIP_Addr, options, pid
            )
            if travelTime <= (
                getClockTime() - startTime
            ):  # If Ping fails then the travel time is deliberately set large
                if options["verbose"]:
                    printTargetNameAndOrIP_Address(trgtAddr, trgtIP_Addr)
                    print "ping round trip time was: %9.3f mS." % (travelTime * 1000)
            else:
                # If the verbose flag was specified then this print is superfluous
                if not options["verbose"]:
                    printTargetNameAndOrIP_Address(trgtAddr, trgtIP_Addr)
                    print "ping failed (elapsed time %6.3f sec)" % (
                        getClockTime() - startTime
                    )
        # Get Timestamp from the specified computer count times with delay between attempts
        if not options["noTimeStamp"]:
            for cnt in range(options["count"]):
                successful, timeStamps = pingWithICMP_TIMESTAMP_REQUEST_Packet(
                    trgtAddr, trgtIP_Addr, options, pid, cnt + 1
                )
                if successful:
                    print '"%s" (%s)' % (trgtAddr, trgtIP_Addr),
                    informUserAboutTimestamp("Transmit", timeStamps["transmit"])
                    print '"%s"' % trgtAddr,
                    printTimeStampAsHrsMinSecsSinceMidnight(timeStamps["transmit"])
                    print "-",
                    printTimeStampAsHrsMinSecsSinceMidnight(timeStamps["originate"])
                    if options["correction"]:
                        print "-> difference: %ld mS" % (timeStamps["difference"],)
                    else:
                        print "- %ld" % (timeStamps["compensation"]),
                        print "-> est'd difference: %ld mS" % (
                            timeStamps["difference"],
                        )
                else:
                    # If the verbose flag was specified then this print is superfluous
                    if not options["verbose"]:
                        printTargetNameAndOrIP_Address(trgtAddr, trgtIP_Addr)
                        print "timestamp acquisition failed"
                if cnt + 1 < options["count"]:
                    _time.sleep(options["pause"])
    except _socket.gaierror, msg:
        print '"%s" Target Name problem: %s' % (trgtAddr, msg)
    except _socket.error, msg:
        print '"%s" Target Computer problem: %s' % (trgtAddr, msg)


def main():
    startTime = getClockTime()
    process_id = os.getpid() & 0xFFFF
    args = processCommandLine()
    if options["debug"]:
        print
    if options["debug"] or options["verbose"]:
        print "checktime.py 0v11, Oct 2020"
    if options["debug"]:
        print "\nCheck the time on one or more networked devices"
        print '\n"%s" Python script running on system type "%s"' % (
            sys.argv[0],
            sys.platform,
        )
        print '\nArgument List "%s"\nbeing executed by Python version "%s"' % (
            sys.argv,
            sys.version,
        )
        print '\n"%s" (truncated) process identifier is 0x%04x' % (
            sys.argv[0],
            process_id,
        )
    #
    args = processCommandLine()
    #
    # if there are no targets specified on command line and no file then
    # default to ping the local interface
    if (len(options["file"]) < 1) & (len(args) < 1):
        print "\n?? Please specify the computer to ping?\n"
        usage()
        localInterface = getLocalIP()
        print "\nDefaulting to ping the local interface (%s)" % localInterface
        pingAndPrintTimeStamp(
            localInterface, getClockTime(), process_id
        )  # If there is no target specified then use local Interface IP
    else:
        if options["help"]:
            usage()
    #
    # Step through timestamp targets from a file specified with the -f option
    if len(options["file"]) > 0:
        if options["debug"]:
            print 'Reading machine names from file named "%s"' % options["file"]
        with open(options["file"]) as f:
            for trgtAddr in f:
                if options["debug"]:
                    print 'Read machine name "%s" from file' % trgtAddr.strip()
                if (len(trgtAddr.strip()) > 0) & (trgtAddr[0] != "#"):
                    pingAndPrintTimeStamp(trgtAddr.strip(), getClockTime(), process_id)
    #
    # Step through timestamp targets specified on the command line
    for trgtAddr in args:
        pingAndPrintTimeStamp(trgtAddr, getClockTime(), process_id)
    if options["debug"]:
        print
    if options["debug"] or options["verbose"]:
        print "checktime.py execution time was: %9.3f mS." % (
            (getClockTime() - startTime) * 1000
        )
    if options["debug"]:
        print


if __name__ == "__main__":
    main()
