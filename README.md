# checktime.py
Check the time on another networked computer or network device, by sending an IPv4 ICMP timestamp request.
This request expects to trigger an ICMP timestamp reply of the number of milliseconds since midnight.
If the other network device is more than 24 hours different, checktime.py cannot detect this error.
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
to the network interface, except on Apple Mac OSX. This is normally provided by using the sudo command
on linux and running as Administrator on Windows.

The checktime.py command has a number of options which are outlined in the useage information.

```
$ ./checktime.py --help

Usage:
./checktime.py [-cXCdDfA.ZhHmpX.XrsTvwX.X] [targetMachine ..[targetMachineN]]
 where; -
   -cX              send count timestamp requests with pause separation
   -C or --correction   disable naive half RTT correction to time difference
   -d or --dgram    selects SOCK_DGRAM socket instead of SOCK_RAW socket
   -D or --debug    prints out Debug information
   -fABC.DEF        specify target machines in a text file
   -h or --help     outputs this usage message
   -H or --hours    outputs time on HH:MM:SS.SSS format
   -m or --microsoft  reverses byte order of receive and transmit timestamps (suits MS Windows)
   -pX.X            pause X.X sec between multiple timestamp requests
   -P or --no-ping  don't send ICMP echo request
   -r or --raw      selects SOCK_RAW but is over-ridden by -d or --dgram
   -s or --standard selects SOCK_DGRAM
   -T or --no-time-stamp  don't send ICMP time stamp request
   -v or --verbose  prints verbose output
   -wX.X            wait X.X sec instead of default 2 sec before timing-out
   targetMachine is either the name or IP address of the computer to ping
 E.g.; -
    ./checktime.py  -v -w5 127.0.0.1
```

