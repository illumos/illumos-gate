#!/bin/ksh
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

# Copyright 2022, Richard Lowe.

TESTDIR=$(dirname $0)

tmpdir=/tmp/test.$$
mkdir $tmpdir
cd $tmpdir

cleanup() {
	cd /
	rm -fr $tmpdir
}

trap 'cleanup' EXIT

if [[ $PWD != $tmpdir ]]; then
	print -u2 "Failed to create temporary directory: $tmpdir"
	exit 1;
fi

if [[ -n $PROTO ]]; then
	export LD_ALTEXEC=$PROTO/bin/ld
fi

gas -c ${TESTDIR}/sections.s -o obj1.o
if (( $? != 0 )); then
	print -u2 "Couldn't assemble ${TESTDIR}/sections.s (obj1)"
	exit 1;
fi

gas -c ${TESTDIR}/sections.s -o obj2.o
if (( $? != 0 )); then
	print -u2 "Couldn't assemble ${TESTDIR}/sections.s (obj2)"
	exit 1;
fi

/bin/ld -r obj1.o obj2.o -o test-obj.o
if (( $? != 0 )); then
	print -u2 "Couldn't link ${TESTDIR}/test-obj.o"
	exit 1;
fi

# section_content <index> <file>
section_content() {
	elfdump -I$1 -w /dev/stdout $2 | tr '\0' '\n'
}

# find_in_group <group> <section> <file>
find_in_group() {
	elfdump -g $3 | awk -v group="${1}\$" -v section=$2 '
		BEGIN { slurp = 0 };
		$0 ~ group { slurp = 1 };
		slurp && $0 ~ section {
			gsub(/[\[\]]/, "", $3);
			print $3;
			exit;
		}' | read index
	if [[ -z $index ]] || (( index <= 0 )); then
		print -u2 "Couldn't find $2 in $1"
		exit 1
	fi
	print $index;
}

# The first test_data_conflict, a member of group1 unmerged with only one
# copy kept.
GROUP1_INDEX=$(find_in_group group1 test_data_conflict test-obj.o)

# The first test_data_conflict, a member of group2 unmerged with only one
# copy kept.
GROUP2_INDEX=$(find_in_group group2 test_data_conflict test-obj.o)

# The un-grouped test_data_conflict, with both copies kept
elfdump -cN.test_data_conflict test-obj.o | \
    awk	 -v group1=$GROUP1_INDEX -v group2=$GROUP2_INDEX '
	/^Section Header/ {
		gsub(/[^0-9]/, "", $2);
		if (($2 != group1) && ($2 != group2)) {
			print $2
		}
	}' | read UNGROUP_INDEX
if [[ -z $UNGROUP_INDEX ]] || (( UNGROUP_INDEX <= 0 )); then
	print -u2 "Couldn't find ungrouped .test_data_conflict"
	exit 1
fi

if (( GROUP1_INDEX == GROUP2_INDEX )); then
	print -u2 "FAIL: group1 and group2 contain the same section";
	exit 1
fi

cmp -s <(section_content $GROUP1_INDEX test-obj.o) /dev/stdin <<EOF
2: test_data_conflict (group 1)
EOF
if (( $? != 0 )); then
	print -u2 "FAIL: the .test_data_conflict section in group1 has the wrong content"
	exit 1;
fi

cmp -s <(section_content $GROUP2_INDEX test-obj.o) /dev/stdin <<EOF
3: test_data_conflict (group 2)
EOF
if (( $? != 0 )); then
	print -u2 "FAIL: the .test_data_conflict section in group2 has the wrong content"
	exit 1;
fi

cmp -s <(section_content $UNGROUP_INDEX test-obj.o) /dev/stdin <<EOF
4: test_data_conflict (two copies not in group)
4: test_data_conflict (two copies not in group)
EOF
if (( $? != 0 )); then
	print -u2 "FAIL: the ungrouped .test_data_conflict has the wrong content"
	exit 1;
fi
