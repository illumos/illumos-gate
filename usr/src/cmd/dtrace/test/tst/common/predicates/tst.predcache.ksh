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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

unload()
{
	#
	# Get the list of services whose processes have USDT probes.  Ideally
	# it would be possible to unload the fasttrap provider while USDT
	# probes exist -- once that fix is integrated, this hack can go away
	#
	pids=$(dtrace -l | \
	    perl -ne 'print "$1\n" if (/^\s*\S+\s+\S*\D(\d+)\s+/);' | \
	    sort | uniq | tr '\n' ',')

	ctids=$(ps -p $pids -o ctid | tail +2 | sort | uniq)
	svcs=

	for ct in $ctids
	do
		line=$(svcs -o fmri,ctid | grep " $ct\$")
		svc=$(echo $line | cut -d' ' -f1)
		svcs="$svcs $svc"
	done

	for svc in $svcs
	do
		svcadm disable -ts $svc
	done

	modunload -i 0
	modunload -i 0
	modunload -i 0

	if ( modinfo | grep dtrace ); then
		for svc in $svcs
		do
			svcadm enable -ts $svc
		done
		echo $tst: could not unload dtrace
		exit 1
	fi

	for svc in $svcs
	do
		svcadm enable -ts $svc
	done
}

script1()
{
	$dtrace -s /dev/stdin <<EOF
	syscall:::entry
	/pid != $ppid/
	{
		@a[probefunc] = count();
	}

	tick-1sec
	/i++ == 5/
	{
		exit(0);
	}
EOF
}

script2()
{
	$dtrace -s /dev/stdin <<EOF

	#pragma D option statusrate=1ms

	syscall:::entry
	/pid == $ppid/
	{
		ttl++;
	}

	tick-1sec
	/i++ == 5/
	{
		exit(2);
	}

	END
	/ttl/
	{
		printf("success; ttl is %d", ttl);
		exit(0);
	}

	END
	/ttl == 0/
	{
		printf("error -- total should be non-zero");
		exit(1);
	}
EOF
}

if [ $# != 1 ]; then
	echo expected one argument: '<'dtrace-path'>'
	exit 2
fi

ppid=$$
dtrace=$1

unload
script1 &
child=$!

let waited=0

while [ "$waited" -lt 5 ]; do
	seconds=`date +%S`

	if [ "$seconds" -ne "$last" ]; then
		last=$seconds
		let waited=waited+1
	fi
done

wait $child
status=$?

if [ "$status" -ne 0 ]; then
	echo $tst: first dtrace failed
	exit $status
fi

unload
script2 &
child=$!

let waited=0

while [ "$waited" -lt 10 ]; do
	seconds=`date +%S`

	if [ "$seconds" -ne "$last" ]; then
		last=$seconds
		let waited=waited+1
	fi
done

wait $child
status=$?

exit $status
