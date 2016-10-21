#! /usr/bin/ksh
#
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

# Copyright 2015, Richard Lowe.

# Verify that aslr messes things up, by comparing the mappings of 2 identical
# processes

LC_ALL=C                        # Collation is important

/usr/bin/psecflags -s aslr $$

tmpdir=/tmp/test.$$

mkdir $tmpdir
cd $tmpdir

cleanup() {
    cd /
    rm -fr $tmpdir
}

trap 'cleanup' EXIT

check() {
    typeset name=$1
    typeset command=$2
    
    for (( i=0; i < 1000; i++ )); do
        $command > out.$i
    done

    cat out.* | sort | uniq -c | sort -nk 1 | nawk '
	BEGIN { 
		tot = 0
		colls = 0
	}

	$2 != "text:" {
		tot += $1
		if ($1 > 1) {
			colls += $1
		}
	}

	END {
		prc = (colls / tot) * 100
		printf "'$name' Collisions: %d/%d (%g%%)\n", colls, tot, prc
		exit prc
	}
'
    return $?
}

# Somewhat arbitrary
ACCEPTABLE=70

ret=0
check 32bit /opt/os-tests/tests/secflags/addrs-32
(( $? > $ACCEPTABLE )) && ret=1
check 64bit /opt/os-tests/tests/secflags/addrs-64
(( $? > $ACCEPTABLE )) && ret=1

exit $ret
