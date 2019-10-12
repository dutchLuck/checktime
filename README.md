# checktime.py
Check the time on another networked computer or on a network device, using IPv4 ICMP timestamp request.
Initially checktime.py pings (IPv4 ICMP Echo Request) the specified computer or network device and then
waits for an ICMP Echo Reply. If it does not receive an echo reply within 2 seconds it prints a "failed"
message. No message is printed on success, unless --verbose option is used when the program is run. After
the ping, checktime.py sends an IPv4 ICMP Timestamp Request to the specified computer or network device
and waits for an ICMP Timestamp Reply. If it does not receive an ICMP timestamp reply within 2 seconds it
prints a "failed" message. Two lines are printed when the specified device or computer sends a properly
formatted timestamp reply; the first of which shows the timestamp reply time in hours, minutes, seconds
and milliseconds since mid-night GMT, and the second line shows the difference between the timestamp of
the requesting and replying network devices or computers in milliseconds. Naive compensation in the
form of half the round trip time (rtt) is applied to the calculated difference. This relies on the
assumption that the time out to and then back from the target device is equal. Some devices do not
return a timestamp in big-endian form, opting instead for little-endian number representation. This
program chooses the smallest time difference, if both forms yield valid timestamps. On some occasions
this assumption that the smallest time difference is the most likely the best choice, will be false.
Command line options can be used to force the timestamp to be interpreted either big or little endian.
Options are outlined by using the --help command line option. This program requires privileged access
to the network interface, except on Apple Mac OSX.
