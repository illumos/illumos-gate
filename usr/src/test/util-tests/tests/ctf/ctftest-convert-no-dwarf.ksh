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
# Copyright (c) 2019, Joyent, Inc.
#

set -e

result=0

progname=$(basename $0)

fail()
{
	echo "Failed: $*" 2>&1
	result=1
}

fail_no_debug()
{
	cmd="$@"
	set +e
	out=$($ctf_convert $cmd 2>&1)

	if [[ $? -eq 0 ]]; then
		fail "$cmd succeeded but should have failed"
		set -e
		return;
	fi

	set -e

	if echo "$out" | grep "is missing debug info" >/dev/null; then
		return;
	fi

	if echo "$out" | grep "does not contain DWARF data" >/dev/null; then
		return;
	fi
	fail "$cmd: incorrect output $out"
}

has_ctf()
{
	for f in "$@"; do
		if ! elfdump -c -N .SUNW_ctf "$f" |
		    grep '.SUNW_ctf' >/dev/null; then
			fail "$f lacks CTF section"
			return
		fi
	done
}

cat <<EOF >file1.c
#include <stdio.h>
struct foo { int a; };
int main(void) { struct foo foo = { 4 }; printf("%d\n", foo.a); }
EOF

cat <<EOF >file2.c
#include <stdio.h>
char myfunc(int a) { printf("%d\n", a); }
EOF

cat <<EOF >file3.cc
struct bar { char *tar; };
void mycxxfunc(char *c) { c[0] = '9'; };
EOF

cat <<EOF >file4.s
.globl caller
.type caller,@function
caller:
	movl 4(%ebp), %eax
	ret
EOF

echo "$progname: An empty file should fail conversion due to no DWARF"
echo >emptyfile.c

$ctf_cc -c -o emptyfile.o emptyfile.c
fail_no_debug emptyfile.o
$ctf_cc -c -o emptyfile.o emptyfile.c
$ctf_convert -m emptyfile.o

$ctf_cc $ctf_debugflags -c -o emptyfile.o emptyfile.c
fail_no_debug emptyfile.o
$ctf_cc $ctf_debugflags -c -o emptyfile.o emptyfile.c
$ctf_convert -m emptyfile.o

echo "$progname: A file missing DWARF should fail conversion"

$ctf_cc -c -o file1.o file1.c
fail_no_debug file1.o
$ctf_cc -c -o file1.o file1.c
$ctf_convert -m file1.o

echo "$progname: A binary with DWARF but 0 debug dies should fail conversion"

$ctf_cc -o mybin file1.c
fail_no_debug mybin
$ctf_cc -o mybin file1.c
$ctf_convert -m mybin

echo "$progname: One C file missing DWARF should fail ctfconvert"

$ctf_cc -c -o file1.o file1.c
$ctf_cc $ctf_debugflags -c -o file2.o file2.c
ld -r -o files.o file2.o file1.o
fail_no_debug files.o
ld -r -o files.o file2.o file1.o
$ctf_convert -m files.o
has_ctf files.o

echo "$progname: One .cc file missing DWARF should pass"

$ctf_cc $ctf_debugflags -c -o file1.o file1.c
$ctf_cc $ctf_debugflags -c -o file2.o file2.c
$ctf_cxx -c -o file3.o file3.cc
ld -r -o files.o file1.o file2.o file3.o
$ctf_convert files.o
has_ctf files.o

echo "$progname: One .s file missing DWARF should pass"
$ctf_cc $ctf_debugflags -c -o file1.o file1.c
$ctf_cc $ctf_debugflags -c -o file2.o file2.c
$ctf_as -o file4.o file4.s
$ctf_cc -o mybin file1.o file2.o file4.o
$ctf_convert mybin
has_ctf mybin

echo "result is $result"
exit $result
