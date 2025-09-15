#! /usr/bin/ksh
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
# Copyright 2025 Edgecast Cloud LLC
#

. "$(dirname $0)/du.kshlib"

du="/bin/du"

function fail {
	echo "FAIL $@"
	((fail++))
}

function pass {
	echo "PASS $@"
}

function A_flag
{
	typeset size
	typeset fn="$0"
	typeset errors=$fail

	require_sparse_file_support

	truncate -s 10g sparse.file

	set -- $($du -s sparse.file)
	size=$1

	if [[ "$size" != "1" ]]; then
		fail "$fn unexpected size: \"$size\""
	fi

	set -- $($du -Ah sparse.file)
	size="$1"

	if [[ "$size" != "10G" ]]; then
		fail "$fn unexpected size \"$size\""
	fi
	rm sparse.file
	(( errors == fail )) && pass $fn
}

function H_flag
{
	typeset paths1='testdir/A/B testdir/A testdir/C testdir'
        typeset paths2='testdir/C/B testdir/C'
	typeset lineprefix=$'^[0-9]+\t'
	typeset sep="\$\n${lineprefix}"
	typeset fn="$0"
	typeset errors=$fail

	mkdir testdir
	(cd testdir && mkdir A && touch A/B && ln -s A C)
	$du -aAH testdir > du.out
	egrep "${lineprefix}$(echo $paths1 | sed -e "s/ /$sep/g")\$" \
	    du.out > egrep.out
	if ! cmp -s du.out egrep.out
	then
		fail "$fn unexpected output"
	fi
	# Check that the output doesn't contain any lines (i.e. paths) that we
	# did not expect it to contain from $paths1.
	egrep -v "${lineprefix}$(echo $paths1 | sed -e "s/ /$sep/g")\$" \
	    du.out > egrep.out
	if [[ -s egrep.out ]]
	then
		fail "$fn unexpected output"
	fi
	$du -aAH testdir/C > du.out

	egrep "${lineprefix}$(echo $paths2 | sed -e "s/ /$sep/g")\$" \
	    du.out > egrep.out
	if ! cmp -s du.out egrep.out
	then
		fail "$fn unexpected output"
	fi
	# Check that the output doesn't contain any lines (i.e. paths) that we
	# did not expect it to contain from $paths2.
	egrep -v "${lineprefix}$(echo $paths2 | sed -e "s/ /$sep/g")\$" \
	    du.out > egrep.out
	if [[ -s egrep.out ]]
	then
		fail "$fn unexpected output"
	fi
	rm -rf testdir du.out egrep.out
	(( errors == fail )) && pass $fn
}

function L_flag
{
	typeset fn="$0"
	typeset errors=$fail

	mkdir testdir
	truncate -s 8192 testdir/A
	ln -s A testdir/B

	if [[ $($du -A testdir) != $(printf "17\ttestdir\n") ]]; then
		fail "$fn unexpected size"
	fi
	if [[ $($du -AL testdir) != $(printf "17\ttestdir\n") ]]; then
		fail "$fn unexpected size"
	fi
	rm -rf testdir
	(( errors == fail )) && pass $fn
}

function a_flag
{
	typeset fn="$0"
	typeset errors=$fail

	mkdir testdir
	truncate -s 0 testdir/A

	if [[ $($du -A testdir) != $(printf "1\ttestdir\n") ]]; then
		fail "$fn unexpected size"
	fi
	if [[ $($du -Aa testdir) != $(printf "0\ttestdir/A\n1\ttestdir\n") ]]
	then
		fail "$fn unexpected size"
	fi

	rm -rf testdir
	(( errors == fail )) && pass $fn
}

function h_flag
{
	typeset fn="$0"
	typeset errors=$fail

	require_sparse_file_support

	truncate -s 1k A
	truncate -s 1m B
	truncate -s 1g C
	truncate -s 1t D

	if [[ $($du -Ah A B C D) != $(printf "1K\tA\n1M\tB\n1G\tC\n1T\tD\n") ]]
	then
		fail "$fn unexpected size"
	fi

	rm A B C D
	(( errors == fail )) && pass $fn
}

function k_flag
{
	typeset fn="$0"
	typeset errors=$fail

	require_sparse_file_support

	truncate -s 1k A
	truncate -s 1m B

	if [[ $($du -Ak A B) != $(printf "1\tA\n1024\tB\n") ]]; then
		fail "$fn unexpected size"
	fi

	rm A B
	(( errors == fail )) && pass $fn
}

function m_flag
{
	typeset fn="$0"
	typeset errors=$fail

	require_sparse_file_support

	truncate -s 1k A
	truncate -s 1m B
	truncate -s 1g C

	if [[ $($du -Am A B C) != $(printf "1\tA\n1\tB\n1024\tC\n") ]]; then
		fail "$fn unexpected size"
	fi

	rm A B C
	(( errors == fail )) && pass $fn
}

function s_flag
{
	typeset fn="$0"
	typeset errors=$fail

	require_sparse_file_support

	mkdir -p testdir/testdir1
	truncate -s 0 testdir/testdir1/A testdir/testdir1/B

	if [[ $($du -As testdir) != $(printf "1\ttestdir\n") ]]; then
		fail "$fn unexpected size"
	fi
	if [[ $($du -As testdir/A) != $(printf "0\ttestdir/A\n") ]]; then
		fail "$fn unexpected size"
	fi
	if [[ $($du -As testdir/testdir1) != \
	    $(printf "1\ttestdir/testdir1\n") ]]; then
		fail "$fn unexpected size"
	fi
	if [[ $($du -As testdir/testdir1/B) != \
	    $(printf "0\ttestdir/testdir1/B\n") ]]; then
		fail "$fn unexpected size"
	fi

	rm -rf testdir
	(( errors == fail )) && pass $fn
}

mkdir -p $test_dir
cd $test_dir

A_flag
H_flag
L_flag
a_flag
h_flag
k_flag
m_flag
s_flag

cd -
rm -rf $test_dir

exit $fail
