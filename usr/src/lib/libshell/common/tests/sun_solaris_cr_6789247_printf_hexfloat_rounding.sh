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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# This test checks whether arithmetric math correctly supports
# negative zero values
#
# This was reported as CR #6789247 ("libast/ksh93 1-digit hexfloat base conversion rounds incorrectly"):
# ---- snip ----
# Description
#   [The same issue was described in http://mail.opensolaris.org/pipermail/ksh93-integration-discuss/2008-December/006737.html]
#   This is basically a spin-off of http://bugs.opensolaris.org/view_bug.do?bug_id=6773712 ("1-digit hex fp
#   base conversion of long double rounds incorrectly").
#   The bug description for Solaris libc says this:
#   > The first line of output from this program is correct.  The second line
#   > is not.
#   > 
#   > leviathan% cat a.c
#   > #include <stdio.h>
#   > 
#   > int main()
#   > {
#   >     printf("%.0a\n", 1.5);
#   >     printf("%.0La\n", 1.5L);
#   >     return 0;
#   > }
#   > leviathan% cc -o a a.c
#   > leviathan% a
#   > 0x1p+1
#   > 0x1p+0
#   > leviathan%
#   If I compile the testcase with libast on Solaris 11/B84 SPARC (which
#   matches ast-open.2008-11-04) I get this:
#   -- snip --
#   $ cc -xc99=%all -I/usr/include/ast -last a.c -o a &&
#   ./a                                             
#   0x1p+00
#   0x1p+00
#   -- snip --
#   ... which seems to be incorrect per the bugs comment above and should
#   be:
#   -- snip --
#   0x1p+1
#   0x1p+1
#   -- snip --
#   ksh93 has the same problem:
#   $ ksh93 -c 'float r=1.5 ; printf "%.0a\n" r'
#   0x1p+00
# Steps to Reproduce
#    Compile and run testcase like this:
#    -- snip --
#    $ cc -xc99=%all -I/usr/include/ast -last a.c -o a &&
#    ./a                                             
#    -- snip --
# Expected Result
#    0x1p+1
#    0x1p+1
# Actual Result
#    0x1p+00
#    0x1p+00
# ---- snip ----
#

# test setup
function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors < 127 && Errors++ ))
}
alias err_exit='err_exit $LINENO'

set -o nounset
Command=${0##*/}
integer Errors=0


float r
float result
typeset str

# Test #001/a - check whether the result of a rounded 1.5 is 2.0
r=1.5
result=$(printf "%.0a\n" r) || err_exit "printf returned non-zero exit code"
(( result == 2.0 )) || err_exit "result expected to be 2.0, got ${result}"


# Test #001/b - same as test #001/a but uses "%.0A\n" instead of "%.0a\n"
r=1.5
result=$(printf "%.0A\n" r) || err_exit "printf returned non-zero exit code"
(( result == 2.0 )) || err_exit "result expected to be 2.0, got ${result}"


# Test #002/a - check whether the hexfloat string value matches the expected pattern
r=1.5
str=$(printf "%.0a\n" r) || err_exit "printf returned non-zero exit code"
[[ "${str}" == ~(Glri)0x0*1p\+0*1 ]] || err_exit "str expected to match ~(Glri)0x0*1p\+0*1, got |${str}|"


# Test #002/b - same as test #002/a but uses "%.0A\n" instead of "%.0a\n"
r=1.5
str=$(printf "%.0A\n" r) || err_exit "printf returned non-zero exit code"
[[ "${str}" == ~(Glri)0x0*1p\+0*1 ]] || err_exit "str expected to match ~(Glri)0x0*1p\+0*1, got |${str}|"


# tests done
exit $((Errors))
