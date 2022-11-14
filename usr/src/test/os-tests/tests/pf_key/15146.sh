#!/usr/bin/ksh

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

#
# Copyright 2022 MNX Cloud, Inc.
#

# Clear and load SADB, logs.
echo "Clearing and loading SADB"
/usr/sbin/ipseckey flush || echo "PROBLEM: ipseckey flush failed" > /dev/stderr
echo "add esp spi 0x2112 dst 127.0.0.1 encralg aes encrkey 1234567890abcdef1234567890abcdef" | /usr/sbin/ipseckey
/usr/sbin/ipseckey dump || echo "PROBLEM: ipseckey dump failed" > /dev/stderr
/bin/rm -f /tmp/15146-$$-del-*

# Launch DTrace trap
# I hope .5sec is enough chill()
/usr/sbin/dtrace -wn 'sadb_delget_sa:entry { self->trace = 1; } get_ipsa_pair:return /self->trace == 1/ { if (arg1 == 0) chill(500000000); self->trace = 0; exit(0); }' &
dtracepid=$!

# sleep for 20sec to give DTrace time, and as a starting pistol...
/usr/bin/sleep 20 &
pistol=$!

for a in 0 1 2 3 4 5 6 7 8 9; do
        ( pwait $pistol ; \
                /usr/sbin/ipseckey delete esp spi 0x2112 dst 127.0.0.1 \
                2>&1 > /tmp/15146-$$-del-$a ) &
done

# All background jobs will finish; if they don't, let the test hang, which
# clearly indicates a problem with IPsec or DTrace.
wait

# If we reach here we haven't panicked the kernel per illumos#15146.
# Only way otherwise we "fail" is by not seeing the race.

# Check that we did delete the SA...
/usr/sbin/ipseckey get esp spi 0x2112 dst 127.0.0.1 2>&1 > /dev/null
if [[ $? == 0 ]]; then
	echo "10 delete processes didn't delete ESP(spi=0x2112, dst=127.0.0.1)" \
		> /dev/stderr
	exit 1
fi

# See that more than one of the above processes successfully peformed DELETE.
count=$( grep Fatal /tmp/15146-$$-del-* | wc -l )
if [[ $count > 8 ]]; then
	echo "Only 1 or 0 ipseckey delete processes succeeded." > /dev/stderr
	exit 1
fi

/bin/rm -f /tmp/15146-$$-del-*
echo "15146 appears to not affect this kernel. Good."
exit 0
