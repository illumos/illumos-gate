#!/bin/bash
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
# Copyright (c) 2012, Joyent, Inc.
#

#
# This test validates that the -zassert-deflib option of ld(1) works correctly.
# It requires that some cc is in your path and that you have passed in the path
# to the proto area with the new version of libld.so.4. One thing that we have
# to do is be careful with using LD_LIBRARY_PATH. Setting LD_LIBRARY_PATH does
# not change the default search path so we want to make sure that we use a
# different ISA (e.g. 32-bit vs 64-bit) from the binary we're generating.
#
unalias -a

TESTDIR=$(dirname $0)

sh_path=
sh_lib="lib"
sh_lib64="$sh_lib/64"
sh_soname="libld.so.4"
sh_cc="gcc"
sh_cflags="-m32"
sh_file="${TESTDIR}/link.c"
sh_arg0=$(basename $0)

function fatal
{
        local msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "$sh_arg0: $msg" >&2
        exit 1
}


#
# Validate that everything we need is in our path. That includes having cc
# and the proto area libld.
#
function validate
{
	[[ -f $sh_path/$sh_lib/$sh_soname ]] || fatal "missing 32-bit $sh_soname"
	[[ -f $sh_path/$sh_lib64/$sh_soname ]] ||
	    fatal "missing 64-bit $sh_soname"
	which $sh_cc >/dev/null || fatal "cc not in path"
}

#
# $1 is a series of flags to append
# $2 is expected exit status
# $3 is pre-test message
# $4 is the failure message
#
function run
{
	local ret

	echo $3
	LD_LIBRARY_PATH_64="$sh_path/$sh_lib64" $sh_cc $sh_cflags $sh_file $1
	if [[ $? -eq $2 ]]; then
		printf "success\n\n"
	else
		fatal $4
	fi
}

sh_path=${1:-/}
validate

run "-Wl,-zassert-deflib" 0 \
    "Testing basic compilation succeeds with warnings..." \
    "failed to compile with warnings"

run "-Wl,-zassert-deflib -Wl,-zfatal-warnings" 1 \
    "Testing basic compilation fails if warning are fatal..." \
    "linking succeeeded, expected failure"

run "-Wl,-zassert-deflib=libc.so -Wl,-zfatal-warnings" 0 \
    "Testing basic exception with fatal warnings..." \
    "linking failed despite exception"

run "-Wl,-zassert-deflib=libc.so -Wl,-zfatal-warnings" 0 \
    "Testing basic exception with fatal warnings..." \
    "linking failed despite exception"


run "-Wl,-zassert-deflib=lib.so -Wl,-zfatal-warnings" 1 \
    "Testing invalid library name..." \
    "ld should not allow invalid library name"

run "-Wl,-zassert-deflib=libf -Wl,-zfatal-warnings" 1 \
    "Testing invalid library name..." \
    "ld should not allow invalid library name"

run "-Wl,-zassert-deflib=libf.s -Wl,-zfatal-warnings" 1 \
    "Testing invalid library name..." \
    "ld should not allow invalid library name"

run "-Wl,-zassert-deflib=libc.so -Wl,-zfatal-warnings -lelf" 1 \
    "Errors even if one library is under exception path..." \
    "one exception shouldn't stop another"

args="-Wl,-zassert-deflib=libc.so -Wl,-zassert-deflib=libelf.so"
args="$args -Wl,-zfatal-warnings -lelf"

run "$args" 0 \
    "Multiple exceptions work..." \
    "multiple exceptions don't work"

args="-Wl,-zassert-deflib=libc.so -Wl,-zassert-deflib=libelfe.so"
args="$args -Wl,-zfatal-warnings -lelf"

run "$args" 1 \
    "Exceptions only catch the specific library" \
    "exceptions caught the wrong library"

args="-Wl,-zassert-deflib=libc.so -Wl,-zassert-deflib=libel.so"
args="$args -Wl,-zfatal-warnings -lelf"

run "$args" 1 \
    "Exceptions only catch the specific library" \
    "exceptions caught the wrong library"

echo "Tests passed."
exit 0
