#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright (c) 2011, Joyent, Inc. All rights reserved.
#

if [ $# != 1 ]; then
	echo expected one argument: '<'dtrace-path'>'
	exit 2
fi

dtrace=$1
DIR=/var/tmp/dtest.$$

mkdir $DIR
cd $DIR

expected=`od -t u8 -N 8 /dev/urandom | head -1 | cut -d ' ' -f2`

$dtrace -x bufpolicy=ring -x bufsize=10k -qs /dev/stdin > /dev/null 2>&1 <<EOF &
	tick-1ms
	/i < 10000/
	{
		printf("%d: expected is $expected!\n", i++);
	}

	tick-1ms
	/i >= 10000/
	{
		exit(0);
	}
EOF

background=$!

#
# Give some time for the enabling to get there...
#
sleep 2

echo "::walk dtrace_state | ::dtrace" | mdb -k | tee test.out
grep "expected is $expected" test.out 2> /dev/null 1>&2
status=$?

kill $background

cd /
/usr/bin/rm -rf $DIR

exit $status
