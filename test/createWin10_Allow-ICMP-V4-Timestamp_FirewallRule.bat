netsh advfirewall firewall add rule name="Allow-ICMP-V4-Timestamp" protocol=icmpv4:13,0 dir=in action=allow