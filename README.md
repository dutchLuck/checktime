# checktime
Check the time on another networked computer or on a network device.
This check is to print out whatever representation of time may be obtained from the remote device. 
Initially checktime.py pings (IPv4 ICMP Echo Request) the specified computer or network device and then
waits for an ICMP Echo Reply. If it does not receive an echo reply within 2 seconds it prints a "failed"
message. No message is printed on success, unless --verbose option is used when the program is run. After
the ping, checktime.py sends an IPv4 ICMP Timestamp Request to the specified computer or network device
and waits for an ICMP Timestamp Reply. If it does not receive an ICMP timestamp reply within 2 seconds it
prints a "failed" message. Two lines are printed when the specified device or computer sends a properly
formatted timestamp reply; the first of which shows the timestamp reply time in hours, minutes, seconds
and milliseconds, and the second line shows the difference between the timestamp of the requesting and
replying network devices or computers in milliseconds.
