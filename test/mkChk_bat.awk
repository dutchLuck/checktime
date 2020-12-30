#
#
BEGIN { print "@Echo Off\r"}
/^#/{ print "Rem", $0, "\r"}
/^echo [-"]---/{ printf "Echo";for(cnt=2;cnt<=NF;cnt++){printf " %s", $cnt}; print "\r"}
/^echo /&&/\$\?/{ print "Echo Error Level %ERRORLEVEL% returned", "\r"}
/^\$PROG_UNDER_TEST \$1/{ printf "python ..\\checktime.py %1";for(cnt=3;cnt<=NF;cnt++){printf " %s", $cnt}; print "\r"}
