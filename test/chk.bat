@ECHO OFF
REM #! /bin/sh 
REM # 
REM # C H K 
REM # 
REM # Last modified on Wed Dec 28 21:14:19 2017  
REM # 
REM # 
REM # 
REM # Linux and other similar systems need sudo, 
REM #  however Mac OSX does not need sudo 
REM # 
ECHO  ----------- Successful 
REM #### 
REM #### Local ADSL Router 
REM # $PROG_UNDER_TEST $1 10.0.0.138 
REM #### 
REM #### Local Windows XP SP3 computer, after ensuring echo+timestamp is on with; - 
REM ####  netsh firewall set icmpsetting 13 enable 
REM ####  netsh firewall set icmpsetting 8 enable 
REM # $PROG_UNDER_TEST $1 -r 10.0.0.84 
REM #### 
REM #### Local Windows 10 Home computer, after ensuring timestamp is on with; - 
REM ####  netsh advfirewall firewall add rule name="Allow-ICMP-V4-Timestamp" protocol=icmpv4:13,0 dir=in action=allow 
REM # $PROG_UNDER_TEST $1 -r 10.0.0.62 
REM #### 
REM #### Local Android Phone 
REM # $PROG_UNDER_TEST $1 android-ae6a6ccb5592abd3 
REM ## 
REM ## ISP time sources 
python ..\checktime.py %1 tic.ntp.telstra.net toc.ntp.telstra.net 
REM #### 
REM #### Other ISP time sources 
REM # $PROG_UNDER_TEST $1 time.optus.net clock.exetel.com.au ntp.internode.on.net ntp.iprimus.com.au 
REM #### 
REM #### Australian National Measurements Institute (Australian Time Standard) 
REM # $PROG_UNDER_TEST $1 ntp.sydney.nmi.gov.au ntp.melbourne.nmi.gov.au ntp.adelaide.nmi.gov.au ntp.brisbane.nmi.gov.au 
REM #### 
REM #### Swedish time sources 
REM # $PROG_UNDER_TEST $1 ntp1.sp.se time1.stupi.se 
REM #### 
REM #### Three DNS names, but one IP Address 
REM # $PROG_UNDER_TEST $1 time.apple.asia.com time.microsoft.asia.com time.linux.asia.com 
REM #### 
REM #### Hosted in the cloud (by akamai?, akamaiedge?) 
REM # $PROG_UNDER_TEST $1 www.vodafone.com.au www.optus.com.au www.abc.net.au www.commbank.com.au 
REM ## 
REM ## FreeBSD and NetBSD machines 
python ..\checktime.py %1 www.freebsd.com www.netbsd.org 
REM ## 
REM ## Seems like a python program should naturally team up with www.python.org 
python ..\checktime.py %1 www.python.org  
REM # 
REM # 
ECHO  ---------- Mostly 
REM ## 
REM ## Ping and timestamp succeed, but timestamp has non-standard flag set 
python ..\checktime.py %1 58.96.102.9  
REM # 
REM # 
ECHO  ---------- Unsuccessful 
REM ## 
REM ## Ping succeeds but timestamp gets a destination unreachable reply 
python ..\checktime.py %1 time.iinet.com.au  
REM ## 
REM ## Both Ping and timestamp get a destination unreachable reply 
python ..\checktime.py %1 www.openbsd.org  
REM # 
REM # 
ECHO  ---------- Unsuccessful 
REM #### 
REM #### Local Windows XP SP3 computer, after ensuring timestamp is off with; - 
REM ####  netsh firewall set icmpsetting 13 disable 
REM #### and ensure Ping (echo) is on with; - 
REM ####  netsh firewall set icmpsetting 8 enable 
REM # $PROG_UNDER_TEST $1 -r 10.0.0.84 
REM #### 
REM #### Local Windows 10 Home computer, after ensuring previously created firewall 
REM #### rule allowing timestamp is removed with; - 
REM ####  netsh advfirewall firewall delete rule name="Allow-ICMP-V4-Timestamp" protocol=icmpv4:13,0 dir=in 
REM # $PROG_UNDER_TEST $1 -r 10.0.0.62 
REM #### 
REM #### Local Apple iPad tablet 
REM # $PROG_UNDER_TEST $1 iPad 
REM #### 
REM # $PROG_UNDER_TEST $1 time.google.com 
REM ## 
python ..\checktime.py %1 ntp.tpg.com.au www.telstra.com.au 
REM #### 
REM # $PROG_UNDER_TEST $1 ntp.aussiebroadband.com.au 
REM ## 
python ..\checktime.py %1 time.asia.apple.com  
REM #### 
REM # $PROG_UNDER_TEST $1 time.apple.com time.apple.com.au 
REM #### 
REM # $PROG_UNDER_TEST $1 ntp.adam.com.au 
REM # 
REM # 
ECHO  ---------- Unsuccessful 
REM ## 
python ..\checktime.py %1 time.windows.com  
REM ## 
python ..\checktime.py %1 ntp.perth.nmi.gov.au  
REM #### 
REM #### Local Windows XP SP3 computer, after ensuring echo+timestamp is off with; - 
REM ####  netsh firewall set icmpsetting 13 disable 
REM ####  netsh firewall set icmpsetting 8 disable 
REM # $PROG_UNDER_TEST $1 -r 10.0.0.84 
REM # 
REM # 
ECHO  ---------- Unsuccessful 
python ..\checktime.py %1 time.microsoft.com  
REM # 
