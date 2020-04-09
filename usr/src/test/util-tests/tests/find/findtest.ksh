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

#
# Copyright 2020 Joyent, Inc.
#

#
# Clearly, grossly incomplete.
#

export LC_ALL=C.UTF-8

set -o pipefail
unalias -a

find_prog=/usr/bin/find
find_prog_xpg4=/usr/xpg4/bin/find
find_exit=0

# make sure we don't end in 1 or 2, which breaks the tests
find_dir=/tmp/findtest.$$.dir

mkdir $find_dir

testfind()
{
	exp=$1
	shift
	cmd="$@"

	echo "TEST: $cmd"

	out=$(eval $cmd | tr '\n' ',')

	[[ "$exp" = "$out" ]] || {
		echo "TEST FAILED: $cmd" >&2
		echo "expected: $exp" >&2
		echo "got: $out" >&2
		find_exit=1
	}
}

mkdir -p $find_dir/1
mkdir -p $find_dir/.2
touch $find_dir/.2/1
touch $find_dir/.2/c

testfind "$find_dir/1,$find_dir/.2/1," \
    $find_prog $find_dir -name \"1\"
testfind "$find_dir/1,$find_dir/.2/1," \
    $find_prog $find_dir -path \"*1\"

cd $find_dir

testfind "" $find_prog . -name \"*2\"
testfind "./.2," $find_prog_xpg4 . -name \"*2\"
testfind "./.2," $find_prog . -name \".*2\"
testfind "./.2," $find_prog_xpg4 . -name \".*2\"
testfind "./1,./.2/1," $find_prog . -path \"*1\"
testfind "./.2," $find_prog . -path \"*2\"
testfind "./.2,./.2/1,./.2/c," $find_prog . -path \"*2*\"

cd -
rm -rf $find_dir

exit $find_exit
