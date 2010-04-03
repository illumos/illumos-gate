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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# Test whether the ksh93/libcmd sum builtin is compatible to
# Solaris/SystemV /usr/bin/sum
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


typeset x

builtin sum || err_exit "sum builtin not found"

# Basic tests
x="$(print 'hello' | /usr/bin/sum)" || err_exit "/usr/bin/sum pipe failed."
[[ "$x" == "542 1" ]] || err_exit "print 'hello' | /usr/bin/sum did not return 542 1, got $x"
x="$(print 'hello' | sum)" || err_exit "sum builtin pipe failed."
[[ "$x" == "542 1" ]] || err_exit "print 'hello' | sum builtin did not return 542 1, got $x"
x="$(print 'hello' | sum -x md5)" || err_exit "sum md5 builtin pipe failed."
[[ "$x" == "b1946ac92492d2347c6235b4d2611184" ]] || err_exit "print 'hello' | sum md5 builtin did not return b1946ac92492d2347c6235b4d2611184, got $x"
x="$(print 'hello' | sum -x sha1)" || err_exit "sum sha1 builtin pipe failed."
[[ "$x" == "f572d396fae9206628714fb2ce00f72e94f2258f" ]] || err_exit "print 'hello' | sum sha1 builtin did not return f572d396fae9206628714fb2ce00f72e94f2258f, got $x"
x="$(print 'hello' | sum -x sha256)" || err_exit "sum sha256 builtin pipe failed."
[[ "$x" == "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03" ]] || err_exit "print 'hello' | sum sha256 builtin did not return 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03, got $x"
x="$(print 'hello' | sum -x sha512)" || err_exit "sum sha512 builtin pipe failed."
[[ "$x" == "e7c22b994c59d9cf2b48e549b1e24666636045930d3da7c1acb299d1c3b7f931f94aae41edda2c2b207a36e10f8bcb8d45223e54878f5b316e7ce3b6bc019629" ]] || err_exit "print 'hello' | sum sha512 builtin did not return e7c22b994c59d9cf2b48e549b1e24666636045930d3da7c1acb299d1c3b7f931f94aae41edda2c2b207a36e10f8bcb8d45223e54878f5b316e7ce3b6bc019629, got $x"
# note that Solaris /usr/bin/cksum outputs $'3015617425\t6' (which may be a bug in Solaris /usr/bin/cksum)
x="$(print 'hello' | sum -x cksum)" || err_exit "sum cksum builtin pipe failed."
[[ "$x" == $'3015617425 6' ]] || err_exit "print 'hello' | sum cksum builtin did not return \$'3015617425 6', got $(printf "%q\n" "$x")"

[[ "$(print 'hello'	| /usr/bin/sum)" == "$(print 'hello'	 | sum)" ]] || err_exit "sum hello != /usr/bin/sum hello"
[[ "$(print 'fish' 	| /usr/bin/sum)" == "$(print 'fish'	 | sum)" ]] || err_exit "sum fish != /usr/bin/sum fish"
[[ "$(print '12345'	| /usr/bin/sum)" == "$(print '12345'	 | sum)" ]] || err_exit "sum 12345 != /usr/bin/sum 12345"
[[ "$(print '\n\r\n \v'	| /usr/bin/sum)" == "$(print '\n\r\n \v' | sum)" ]] || err_exit "sum spaces != /usr/bin/sum spaces"

# Test some binary files...
x="/usr/bin/ls"
[[ "$(cat "$x" | /usr/bin/sum)" == "$(cat "$x" | sum)" ]]	|| err_exit "pipe: /usr/bin/sum $x != sum $x"
[[ "$(/usr/bin/sum "$x")" == "$(sum "$x")" ]]			|| err_exit "file: /usr/bin/sum $x != sum $x"

x="/usr/bin/chmod"
[[ "$(cat "$x" | /usr/bin/sum)" == "$(cat "$x" | sum)" ]]	|| err_exit "pipe: /usr/bin/sum $x != sum $x"
[[ "$(/usr/bin/sum "$x")" == "$(sum "$x")" ]]			|| err_exit "file: /usr/bin/sum $x != sum $x"

x="/usr/bin/tee"
[[ "$(cat "$x" | /usr/bin/sum)" == "$(cat "$x" | sum)" ]]	|| err_exit "pipe: /usr/bin/sum $x != sum $x"
[[ "$(/usr/bin/sum "$x")" == "$(sum "$x")" ]]			|| err_exit "file: /usr/bin/sum $x != sum $x"

x="/usr/bin/grep"
[[ "$(cat "$x" | /usr/bin/sum)" == "$(cat "$x" | sum)" ]]	|| err_exit "pipe: /usr/bin/sum $x != sum $x"
[[ "$(/usr/bin/sum "$x")" == "$(sum "$x")" ]]			|| err_exit "file: /usr/bin/sum $x != sum $x"

x="/usr/bin/egrep"
[[ "$(cat "$x" | /usr/bin/sum)" == "$(cat "$x" | sum)" ]]	|| err_exit "pipe: /usr/bin/sum $x != sum $x"
[[ "$(/usr/bin/sum "$x")" == "$(sum "$x")" ]]			|| err_exit "file: /usr/bin/sum $x != sum $x"

x="/usr/bin/awk"
[[ "$(cat "$x" | /usr/bin/sum)" == "$(cat "$x" | sum)" ]]	|| err_exit "pipe: /usr/bin/sum $x != sum $x"
[[ "$(/usr/bin/sum "$x")" == "$(sum "$x")" ]]			|| err_exit "file: /usr/bin/sum $x != sum $x"

x="/usr/bin/nawk"
[[ "$(cat "$x" | /usr/bin/sum)" == "$(cat "$x" | sum)" ]]	|| err_exit "pipe: /usr/bin/sum $x != sum $x"
[[ "$(/usr/bin/sum "$x")" == "$(sum "$x")" ]]			|| err_exit "file: /usr/bin/sum $x != sum $x"

x="/usr/bin/ksh"
[[ "$(cat "$x" | /usr/bin/sum)" == "$(cat "$x" | sum)" ]]	|| err_exit "pipe: /usr/bin/sum $x != sum $x"
[[ "$(/usr/bin/sum "$x")" == "$(sum "$x")" ]]			|| err_exit "file: /usr/bin/sum $x != sum $x"

x="/usr/bin/sh"
[[ "$(cat "$x" | /usr/bin/sum)" == "$(cat "$x" | sum)" ]]	|| err_exit "pipe: /usr/bin/sum $x != sum $x"
[[ "$(/usr/bin/sum "$x")" == "$(sum "$x")" ]]			|| err_exit "file: /usr/bin/sum $x != sum $x"


# tests done
exit $((Errors))
