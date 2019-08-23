# example program from alex@bofh.torun.pl
# BEGIN { IGNORECASE=1 }
/[[:alnum:]]+@([[:alnum:]]+\.)+[[:alnum:]]+[[:blank:]]+/ {print $0}
