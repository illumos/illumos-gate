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

fail_no_ctf()
{
	cmd="$@"
	set +e
	out=$($cmd 2>&1)

	if [[ $? -eq 0 ]]; then
		fail "$cmd succeeded but should have failed"
		set -e
		return;
	fi

	set -e

	if ! echo "$out" | \
	    grep "File does not contain CTF data" >/dev/null; then
		fail "$cmd: incorrect output $out"
		return;
	fi
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
struct foo foos[400];
int main(void) { struct foo foo = { 4 }; printf("%d\n", foo.a); }
EOF

cat <<EOF >file2.c
#include <stdio.h>
struct foo { char b; float c; };
struct foo stuff[90];
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

echo "$progname: ctfmerge should fail if one C-source lacks CTF"

$ctf_cc $ctf_debugflags -c -o file1.o file1.c
$ctf_convert file1.o
$ctf_cc -c -o file2.o file2.c
ld -r -o files.o file2.o file1.o
fail_no_ctf $ctf_merge -o files.o file2.o file1.o
ld -r -o files.o file2.o file1.o
$ctf_merge -m -o files.o file2.o file1.o
has_ctf files.o
$ctf_cc -o mybin file2.o file1.o
fail_no_ctf $ctf_merge -o mybin file2.o file1.o
$ctf_cc -o mybin file2.o file1.o
$ctf_merge -m -o mybin file2.o file1.o


echo "$progname: ctfmerge should allow a .cc file to lack CTF"
$ctf_cxx -c -o file3.o file3.cc
ld -r -o files.o file1.o file3.o
$ctf_merge -o files.o file1.o file3.o
ld -r -o files.o file1.o file3.o
$ctf_merge -m -o files.o file1.o file3.o

echo "$progname: ctfmerge should allow an .s file to lack CTF"
$ctf_as -o file4.o file4.s
ld -r -o files.o file4.o file1.o
$ctf_merge -o files.o file4.o file1.o
ld -r -o files.o file4.o file1.o
$ctf_merge -m -o files.o file4.o file1.o

echo "result is $result"
exit $result
