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
# Copyright (c) 2017, Joyent, Inc. All rights reserved.
#

#
# This test attempts to reproduce a three-way deadlock between mod_lock,
# dtrace_lock and P_PR_LOCK that is induced by shmsys having to go through
# mod_hold_stub.
#
if [ $# != 1 ]; then
	echo expected one argument: '<'dtrace-path'>'
	exit 2
fi

dtrace=$1
DIR=/var/tmp/dtest.$$

mkdir $DIR
cd $DIR

cat > prov.d <<EOF
provider test_prov {
	probe ripraf();
};
EOF

$dtrace -h -s prov.d
if [ $? -ne 0 ]; then
	print -u2 "failed to generate header file"
	exit 1
fi

cat > test.c <<EOF
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <stdlib.h>
#include "prov.h"

void
main(int argc)
{
	void *addr;
	int shmid;

	if (argc > 1) {
		TEST_PROV_RIPRAF();
		exit(0);
	}

	shmid = shmget(IPC_PRIVATE, sizeof (int), IPC_CREAT | 0666);

	if (shmid == -1) {
		perror("shmget: ");
		exit(1);
	}

	if ((addr = shmat(shmid, NULL, 0)) == (void *)-1) {
		perror("shmat: ");
		exit(1);
	}

	printf("%p\n", addr);

	for (;;) {
		TEST_PROV_RIPRAF();
		sleep(1);
	}
}
EOF

gcc -m32 -c test.c
if [ $? -ne 0 ]; then
	print -u2 "failed to compile test.c"
	exit 1
fi

$dtrace -G -32 -s prov.d test.o

if [ $? -ne 0 ]; then
	print -u2 "failed to create DOF"
	exit 1
fi

gcc -m32 -o test test.o prov.o

if [ $? -ne 0 ]; then
	print -u2 "failed to link final executable"
	exit 1
fi

#
# Kick off the victim program.
#
./test &

victim=$!

#
# Kick off a shell that will do nothing but read our victim's /proc map
#
( while true ; do read foo < /proc/$victim/map ; done ) &
stubby=$!

#
# Kick off a shell that will do nothing but instrument (and de-instrument)
# the victim
#
( while true; do \
    $dtrace -q -P test_prov$victim -n BEGIN'{exit(0)}' > /dev/null ; done ) &
inst=$!

#
# Finally, kick off a shell that will cause lots of provider registration and
# (importantly) de-registration
#
( while true; do ./test foo ; done) &
reg=$!

echo $DIR
echo victim: $victim
echo stubby: $stubby
echo inst: $inst
echo reg: $reg

sleep 120

kill $reg
sleep 1
kill $inst
sleep 1
kill $stubby
sleep 1
kill $victim

#
# If we're deadlocked, this DTrace enabling won't work (if we even make it this
# far, which seems unlikely).  In the spirit of the deadlock, we denote our
# success by emiting a classic Faulknerism.
#
raf="Maybe you're not so worthless!"
dtrace -qn BEGIN"{printf(\"$raf\"); exit(0)}"

cd /
/usr/bin/rm -rf $DIR

exit 0
