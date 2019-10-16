@ECHO OFF
REM #! /bin/sh 
REM # 
REM # C H K 
REM # 
REM # Last modified on Sat Oct 12 19:56:59 2019  
REM # 
REM # 
REM # 
REM # Linux and other similar systems need sudo, 
REM #  however Mac OSX does not need sudo 
REM # 
REM # 
ECHO  ----------- Successful 
REM #### 
REM ## Low (6-7mS) RTT ISP time source 
python ..\checktime.py %1 tic.ntp.telstra.net  
REM ## 
REM ## Med (18-19mS) RTT ISP time source 
python ..\checktime.py %1 time.optus.net  
REM ## 
REM ## 42-43mS RTT NZ time source 
python ..\checktime.py %1 s2.ntp.net.nz  
REM ## 
REM ## 226-227mS RTT US time source 
python ..\checktime.py %1 clock.he.net  
REM ## 
REM ## 309-312mS RTT French time source 
python ..\checktime.py %1 ntp.obspm.fr  
REM ## 
REM ## 348-364mS RTT Swedish time source 
python ..\checktime.py %1 time1.stupi.se  
REM # 
REM # 
ECHO  ---------- Successful 
REM #### 
REM ## FreeBSD and Ubuntu machines 
python ..\checktime.py %1 www.freebsd.org www.ubuntu.org 
REM ## 
REM ## Seems like a python program should naturally team up with www.python.org 
python ..\checktime.py %1 www.python.org  
REM # 
REM # 
ECHO  ---------- Successful 
REM #### 
REM ## Ping and timestamp succeed, but timestamp is non-standard (little endian) 
python ..\checktime.py %1 wwh-2.onthe.net.au  
REM # 
REM # 
ECHO  ---------- Mostly 
REM #### 
REM ## Ping and timestamp succeed, but timestamp has non-standard flag set 
python ..\checktime.py %1 58.96.102.9  
REM # 
REM # 
ECHO  ---------- Mostly 
REM #### 
REM ## Ping succeeds but timestamp gets a destination unreachable reply 
python ..\checktime.py %1 time.iinet.com.au  
REM ## 
REM ## Both Ping and timestamp get a destination unreachable reply 
python ..\checktime.py %1 www.openbsd.org  
REM # 
REM # 
ECHO  ---------- Unsuccessful 
REM #### 
REM ## Ping fails, but timestamp succeeds 
python ..\checktime.py %1 ntp-m.obspm.fr  
REM # 
REM # 
ECHO  ---------- Unsuccessful 
REM #### 
REM ## Ping succeeds, but timestamp fails 
python ..\checktime.py %1 ntp.tpg.com.au  
REM # 
REM # 
ECHO  ---------- Unsuccessful 
REM #### 
REM ## DNS ok, but no replies 
python ..\checktime.py %1 time.windows.com  
REM # 
REM # 
ECHO  ---------- Unsuccessful 
REM #### 
REM ## DNS fails 
python ..\checktime.py %1 time.microsoft.com  
REM # 
