#
#
BEGIN { print "@ECHO OFF\r"}
/^#/{ print "REM", $0, "\r"}
/^echo /{ print "ECHO ", $2, $3, "\r"}
/^\$PROG_UNDER_TEST \$1/{ print "python ..\\checktime.py %1", $3, $4, "\r"}
