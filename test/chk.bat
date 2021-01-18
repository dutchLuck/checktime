@Echo Off
Rem #! /bin/sh 
Rem # 
Rem # C H K 
Rem # 
Rem # Last modified on Tue Dec 29 21:40:58 2020  
Rem # 
Rem # 
Rem # 
Rem # Linux and other similar systems need sudo, 
Rem #  however Mac OSX does not need sudo 
Rem # 
Rem # 
Echo ----------- House keeping tests: Version Number ----------------
Rem #### 
Rem ## Show version number 
python3 ..\checktime.py %1 --verbose --no-ping --no-time-stamp localhost
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo ----------- House keeping tests: Basic Debug Info ----------------
Rem #### 
Rem ## Show Most Basic Debug Info 
python3 ..\checktime.py %1 -v --debug -P -T localhost
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo "----------- Successful --Multiple (3) pings (2.5 S) apart ----------------"
Rem #### 
Rem ## Test option to do count pings, pause apart 
python3 ..\checktime.py %1 -c 3 -p 2.5 www.python.org
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo "----------- Unsuccessful --Multiple (3) pings fail ----------------"
Rem #### 
Rem ## Test option to do count pings, pause apart 
python3 ..\checktime.py %1 -c 3 time.windows.com
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo ----------- Successful --Read DUT names from a file ----------------
Rem #### 
Rem ## Test option to read DUT names from a file 
python3 ..\checktime.py %1 -f lnx.txt
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo "----------- Successful -- Compare -C (Correction) supression -------"
Rem #### 
Rem ## Low (6-7mS) RTT ISP time source 
python3 ..\checktime.py %1 tic.ntp.telstra.net
Echo Error Level %ERRORLEVEL% returned 
Rem ## 
Rem ## Low (6-7mS) RTT ISP time source 
python3 ..\checktime.py %1 -C tic.ntp.telstra.net
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo ----------- Successful -- Timestamps from ISPs or Time Sources -------
Rem #### 
Rem ## Low (6-7mS) RTT ISP time source 
python3 ..\checktime.py %1 tic.ntp.telstra.net
Echo Error Level %ERRORLEVEL% returned 
Rem ## 
Rem ## Med (18-19mS) RTT ISP time source 
python3 ..\checktime.py %1 time.optus.net
Echo Error Level %ERRORLEVEL% returned 
Rem ## 
Rem ## 42-43mS RTT NZ time source 
python3 ..\checktime.py %1 s2.ntp.net.nz
Echo Error Level %ERRORLEVEL% returned 
Rem ## 
Rem ## 226-227mS RTT US time source 
python3 ..\checktime.py %1 clock.he.net
Echo Error Level %ERRORLEVEL% returned 
Rem ## 
Rem ## 309-312mS RTT French time source 
python3 ..\checktime.py %1 ntp.obspm.fr
Echo Error Level %ERRORLEVEL% returned 
Rem ## 
Rem # 
Echo "---------- Successful -- Multiple DUT's from command line --------"
Rem #### 
Rem ## FreeBSD and Ubuntu machines 
python3 ..\checktime.py %1 www.freebsd.org www.ubuntu.org
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo "---------- Successful -- Use of --quiet option for www.python.org --------"
Rem #### 
Rem ## Seems like a python program should naturally team up with www.python.org 
python3 ..\checktime.py %1 --quiet www.python.org
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo "---------- Successful -- Use of --hours option for www.python.org --------"
Rem #### 
Rem ## Seems like a python program should naturally team up with www.python.org 
python3 ..\checktime.py %1 --hours www.python.org
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo "---------- Successful -- Use of --milliseconds option for www.python.org --------"
Rem #### 
Rem ## Seems like a python program should naturally team up with www.python.org 
python3 ..\checktime.py %1 --milliseconds www.python.org
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo ---------- Successful -- Little Endian timestamps returned--------
Rem #### 
Rem ## Ping and timestamp succeed, but timestamp is non-standard (little endian) 
python3 ..\checktime.py %1 wwh-2.onthe.net.au
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo ---------- Mostly successful -- Non-Standard timestamp indication--
Rem #### 
Rem ## Ping and timestamp succeed, but timestamp has non-standard flag set 
python3 ..\checktime.py %1 58.96.102.9
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo ---------- Mostly unsuccessful -- Packet corruption ? ------
Rem #### 
Rem ## Ping succeeds but timestamp gets a destination unreachable reply 
python3 ..\checktime.py %1 --verbose time.iinet.com.au
Echo Error Level %ERRORLEVEL% returned 
Rem ## 
Rem # 
Rem # 
Echo ---------- Unsuccessful -- Ping fails, but Timestamp works--
Rem #### 
Rem ## Ping fails, but timestamp succeeds 
python3 ..\checktime.py %1 ntp-m.obspm.fr
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo ---------- Unsuccessful -- Ping works, but no Timestamp--
Rem #### 
Rem ## Ping succeeds, but timestamp fails 
python3 ..\checktime.py %1 ntp.tpg.com.au
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo ---------- Unsuccessful on purpose -- Both Ping and Timestamp fail, but DNS ok--
Rem #### 
Rem ## DNS ok, but no replies 
python3 ..\checktime.py %1 --verbose time.windows.com
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo ---------- Unsuccessful on purpose -- Both Ping and Timestamp fail, but wait longer--
Rem #### 
Rem ## DNS ok, but no replies 
python3 ..\checktime.py %1 -w 2.5 --verbose time.windows.com
Echo Error Level %ERRORLEVEL% returned 
Rem # 
Rem # 
Echo ---------- Unsuccessful on purpose -- Test response to non-existant name--
Rem #### 
Rem ## DNS fails 
python3 ..\checktime.py %1 time.microsoft.com
Echo Error Level %ERRORLEVEL% returned 
Rem # 
