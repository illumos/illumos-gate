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
# Copyright 2024 Oxide Computer Company
#

#
# Wrap up the aligned_alloc() tests with the different malloc libraries
# that make sense to test as this calls into their implementation of
# memalign. Currently we test libc, libumem, and libmtmalloc. mapmalloc
# is skipped because it doesn't implement memalign. libmtmalloc
# currently doesn't have an ENOMEM/EAGAIN test strategy.
#

unalias -a
set -o pipefail
export LANG=C.UTF-8

alloc_arg0="$(basename $0)"
alloc_dir="$(dirname $0)"
alloc_exit=0
alloc_file="aligned_alloc"
alloc_libraries="none
libumem.so
libmtmalloc.so"
alloc_archs="32
64"

function warn
{
	typeset msg="$*"
	echo "TEST FAILED: $msg" >&2
	alloc_exit=1
}

function run_one
{
	typeset preload="$1"
	typeset suffix="$2"

	if [[ "$1" != none ]]; then
		export LD_PRELOAD=$preload
	fi

	printf "Running %u-bit tests with library %s\n" $suffix "$preload"

	if ! $alloc_dir/$alloc_file.$suffix; then
		alloc_exit=1
	fi

	unset LD_PRELOAD
}

for lib in ${alloc_libraries[@]}; do
	for arch in ${alloc_archs[@]}; do
		run_one "$lib" "$arch"
	done
done

if ((alloc_exit != 0)); then
	printf "Some library/architecture variants failed!\n" >&2
fi

exit $alloc_exit
