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
# Copyright 2025 Oxide Computer Company
#

#
# Verify that we can reasonably print and walk various anonymous unions and
# structs.
#

if (( $# != 1 )); then
        printf "%s\n" "expected one argument: <dtrace-path>" >&2
        exit 2
fi

dtrace=$1
$dtrace -c ./tst.anon.exe -qs /dev/stdin <<EOF
pid\$target::mandos:entry
{
	print(*args[0]);
	printf("\n");
	print(args[0]->turgon);
	print(args[0]->balrog);
	print(args[0]->elrond);
	print(args[0]->silmaril);
	print(*(userland struct pid\`elves *)arg0);
	printf("\n");
	printf("feanor: 0x%x\n", args[0]->feanor);
	printf("fingolfin: 0x%x\n", args[0]->fingolfin);
	printf("maedhros: 0x%x\n", args[0]->maedhros);
	printf("aredhel: 0x%x\n", args[0]->maedhros);
	printf("fingon: 0x%x\n", args[0]->fingon);
	printf("turgon: 0x%x\n", args[0]->turgon);
	printf("tuor: 0x%x\n", args[0]->tuor);
	printf("idril: 0x%x\n", args[0]->idril);
	printf("earendil: 0x%x\n", args[0]->earendil);
	printf("elwing: 0x%x\n", args[0]->elwing);
	printf("silamril: 0x%x\n", args[0]->silmaril);
	printf("maeglin: 0x%x\n", args[0]->maeglin);
	printf("morgoth: 0x%x\n", args[0]->morgoth);
	printf("balrog: 0x%x\n", args[0]->balrog);
	printf("gondolin: 0x%x\n", args[0]->gondolin);
	printf("glorfindel: 0x%x\n", args[0]->glorfindel);
	printf("elrond: 0x%x\n", args[0]->elrond);
	printf("elros: 0x%x\n", args[0]->elros);
	exit(0);
}
EOF
