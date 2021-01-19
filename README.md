# checktime.py
Check the time on another networked computer or network device, by sending an IPv4 ICMP timestamp request
(Please see RFC 792 pages 16 & 17 for ICMP timestamp documentation (https://tools.ietf.org/html/rfc792)).
This timestamp request expects to trigger an ICMP timestamp reply from the remote device. The expected
reply contains the number of milliseconds since midnight on the remote device at the time the request
arrived. Consequently if the remote device happens to be more than 24 hours different, any program using
ICMP timestamp, including checktime.py, cannot detect this, so the answer given will be mod 24 hours.
Initially checktime.py pings (IPv4 ICMP Echo Request) the specified computer or network device and then
waits for an ICMP Echo Reply. If it does not receive an echo reply within 2 seconds it prints a "failed"
message. No message is printed on success, unless --verbose option is used when the program is run. After
the ping, checktime.py sends an IPv4 ICMP Timestamp Request to the specified computer or network device
and waits for an ICMP Timestamp Reply. If it does not receive an ICMP timestamp reply within 2 seconds it
prints a "failed" message. Two lines are printed when the specified device or computer sends a properly
formatted timestamp reply; the first of which shows the timestamp reply time in hours, minutes, seconds
and milliseconds since mid-night GMT, and the second line shows the estimated difference between the
timestamp of the requesting and replying network devices or computers. By default naive compensation
in the form of half the round trip time (rtt) is applied to the calculated difference. This relies on the
assumption that the time out to and then back from the target device is equal. Some devices do not
return a timestamp in big-endian form, opting instead for little-endian number representation. This
program chooses the smallest time difference, if both forms yield valid timestamps. On some occasions
this assumption that the smallest time difference is the most likely the best choice, will be false.
Command line options can be used to force the timestamp to be interpreted either big or little endian.
Options are outlined by using the --help command line option. This program requires privileged access
to the network interface to facilitate the use of a raw socket, except on Apple Mac OSX, where by default
a datagram socket is used. Privileged network interface access is normally facilitated by using the sudo
command on Linux or running as Administrator on Windows.

The checktime.py command has a number of options which are outlined in the useage information.

```
$ ./checktime.py --help
Usage:
./checktime.py [-cXCdDfA.ZhHmMpX.XPqrsTvwX.X] [targetMachine ..[targetMachineN]]
 where; -
   -cX              send count timestamp requests with pause separation
   -C or --correction   disable naive half RTT correction to time difference
   -d or --dgram    selects SOCK_DGRAM socket instead of SOCK_RAW socket
   -D or --debug    prints out Debug information
   -fABC.DEF        specify target machines in a text file
   -h or --help     outputs this usage message
   -H or --hours    sets output format to HH:MM:SS.SSS
   -m or --microsoft  reverses byte order of timestamp reply (suits remote MS Windows)
   -M or --milliseconds  sets output format to milliseconds
   -pX.X            pause X.X sec between multiple timestamp requests
   -P or --no-ping  don't send ICMP echo request
   -q or --quiet    prints difference output value and units, but nothing else
   -r or --raw      selects SOCK_RAW but is over-ridden by -d or --dgram
   -s or --standard suggests normal byte order of timestamps be used
   -T or --no-time-stamp  don't send ICMP time stamp request
   -v or --verbose  prints verbose output
   -wX.X            wait X.X sec instead of default 2 sec before timing-out
   targetMachine is either the name or IP address of the computer to ping
 E.g.; -
    ./checktime.py  -v www.python.org
```
The same ICMP based time difference information can be obtained with greater confidence in (at least)
Ubuntu 18.04/20.04 LTS Linux by installing the  clockdiff  program. For example; -

```
xx@yy:~$ clockdiff www.python.org
Command 'clockdiff' not found, but can be installed with:
sudo apt install iputils-clockdiff
xx@yy:~$ sudo apt install iputils-clockdiff
..<apt install output text removed>..
xx@yy:~$ date; sudo ./checktime.py www.python.org; date; clockdiff www.python.org; date
Sun 27 Dec 19:24:42 AEDT 2020
www.python.org (151.101.80.223) Transmit timestamp returned was 08:24:42.666
www.python.org 30282666 - 30282662 - 4 -> est'd difference:  0 mS
Sun 27 Dec 19:24:42 AEDT 2020
..................................................
host=dualstack.python.map.fastly.net rtt=8(0)ms/8ms delta=0ms/0ms Sun Dec 27 19:24:49 2020
Sun 27 Dec 19:24:49 AEDT 2020
```
I do not know of an equivalent of clockdiff that is native to Microsoft Windows based machines. A ping
program for Windows that can send ICMP timestamp requests and receive timestamp replies is hrPing from
cFos Software GmbH. There maybe other Windows software out there that is more specific to determining
the time difference between machines, but I am not aware of any. There are also no Apple specific
programs using ICMP timestamp, that I am aware of. 

checktime.py releases from v1.0 to v1.02 (i.e. python2 code) appear to work on the following systems; -
```
Ubuntu 18.04 LTS with Python version 2.7.17
Apple macOS 10.13.6 (High Sierra) with Python version 2.7.16
Microsoft Windows 10.0.19042.685 and Python version 2.7.14
```
checktime.py release v1.03 (i.e. python3 code) appears to work on just the following system; -
```
Ubuntu 20.04-1 LTS with Python version 3.8.5
```
checktime.py and associated files can be downloaded from; -
https://github.com/dutchLuck/checktime/
and some level of confidence of correct operation can be gained by running the chk or chk.bat
scripts in the test folder. Some sites block ICMP timestamp and firewalls on machines
may cause a failure to reply, so no matter how well this program works the end goal of
obtaining time information from a remote device may simply be unattainable.

Further reading; -
1. ICMP Timestamp Request and Reply  (section 6.4 from TCP/IP Illustrated Vol 1 by W.R. Stevens)
( viewed at https://flylib.com/books/en/3.223.1.79/1/ )
2. Sundials in the Shade - An Internet-wide Perspective on ICMP Timestamps by E.C. Rye and R. Beverly
( viewed as PDF from https://rbeverly.net/research/papers/sundials-pam19.pdf )
