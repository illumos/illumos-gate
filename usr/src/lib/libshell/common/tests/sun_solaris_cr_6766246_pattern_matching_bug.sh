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
# Test whether CR #6766246 ("bug in pattern matching") has been fixed.
# 
# Quote from CR #6766246: 
# ---- snip ----
# The bootstrap script of pkgsrc contains this code
# checkarg_sane_absolute_path() {
#   case "$1" in
#     "") ;; # the default value will be used.
#     *[!-A-Za-z0-9_./]*)
#       die "ERROR: Invalid characters in path $1 (from $2)." ;;
#     /*) ;;
#     *) die "ERROR: The argument to $2 must be an absolute path." ;;
#   esac
# }
# It turns out, the leading "!" in the pattern is not interpreted
# as negation, and the first "-" not as a literal. Instead the
# character range  "! to A" is constructed. Paths containing "%"
# or "@" are accepted, but paths containing "-" are rejected.
# Note that this interpretation makes the whole pattern
# syntactically wrong, which isn't noticed either.
# 
# Test case:
# -- snip --
# !/bin/sh
# case "$1" in
# *[!-A-Za-z0-9_./]*)
#         echo invalid characters used in $1
#         ;;
# *)
#         echo only valid characters used in $1
#         ;;
# esac
# -- snip --
# Expected Result:
#    strings containing a "-" should be accepted, strings containing
#    a "@" should be rejected
# Actual Result:
#    strings containing a "-" are rejected, strings containing a
#    "@" are accepted
# Workaround
#    The pattern "*[!A-Za-z0-9_./-]*" (i.e. shifting the dash to
#    the end) works as expected.
# ---- snip ----


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


## test 1 (based on the bug report):

function do_match
{
	case "$1" in
		*[!-A-Za-z0-9_./]*)
			print "match"
			;;
		*)
			print "nomatch"
			;;
	esac
	return 0
}

typeset pat

pat="foo-bar" ; [[ "$(do_match "${pat}")" == "nomatch" ]] || err_exit "${pat} matched."
pat="foo+bar" ; [[ "$(do_match "${pat}")" == "match"   ]] || err_exit "${pat} not matched."
pat="foo/bar" ; [[ "$(do_match "${pat}")" == "nomatch" ]] || err_exit "${pat} matched."
pat="foo_bar" ; [[ "$(do_match "${pat}")" == "nomatch" ]] || err_exit "${pat} matched."
pat="foo@bar" ; [[ "$(do_match "${pat}")" == "match"   ]] || err_exit "${pat} not matched."
pat="foobar-" ; [[ "$(do_match "${pat}")" == "nomatch" ]] || err_exit "${pat} matched."
pat="foobar+" ; [[ "$(do_match "${pat}")" == "match"   ]] || err_exit "${pat} not matched."
pat="foobar/" ; [[ "$(do_match "${pat}")" == "nomatch" ]] || err_exit "${pat} matched."
pat="foobar_" ; [[ "$(do_match "${pat}")" == "nomatch" ]] || err_exit "${pat} matched."
pat="foobar@" ; [[ "$(do_match "${pat}")" == "match"   ]] || err_exit "${pat} not matched."
pat="-foobar" ; [[ "$(do_match "${pat}")" == "nomatch" ]] || err_exit "${pat} matched."
pat="+foobar" ; [[ "$(do_match "${pat}")" == "match"   ]] || err_exit "${pat} not matched."
pat="/foobar" ; [[ "$(do_match "${pat}")" == "nomatch" ]] || err_exit "${pat} matched."
pat="_foobar" ; [[ "$(do_match "${pat}")" == "nomatch" ]] || err_exit "${pat} matched."
pat="@foobar" ; [[ "$(do_match "${pat}")" == "match"   ]] || err_exit "${pat} not matched."


## test 2 (gsf's test chain):

# Make sure LC_COLLATE has a value
if [[ "${LC_COLLATE}" == "" ]] ; then
	if [[ ${LANG} != "" && "${LC_ALL}" == "" ]] ; then
		LC_COLLATE="${LANG}"
	fi
fi

if [[ "${LC_ALL}" != "" ]] ; then
	LC_COLLATE="${LC_ALL}"
fi

[[ "${LC_COLLATE}" != "" ]] || err_exit "LC_COLLATE empty."

set -- \
        'A'   0 1 1   0 1 1      1 0 0   1 0 0   \
        'Z'   0 1 1   0 1 1      1 0 0   1 0 0   \
        '/'   0 0 0   0 0 0      1 1 1   1 1 1   \
        '.'   0 0 0   0 0 0      1 1 1   1 1 1   \
        '_'   0 0 0   0 0 0      1 1 1   1 1 1   \
        '-'   1 1 1   1 1 1      0 0 0   0 0 0   \
        '%'   0 0 0   0 0 0      1 1 1   1 1 1   \
        '@'   0 0 0   0 0 0      1 1 1   1 1 1   \
        '!'   0 0 0   0 0 0      1 1 1   1 1 1   \
        '^'   0 0 0   0 0 0      1 1 1   1 1 1   \
        # retain this line #
while (( $# >= 13 )) ; do
	c=$1
	shift
	for p in \
		'[![.-.]]' \
		'[![.-.][:upper:]]' \
		'[![.-.]A-Z]' \
		'[!-]' \
		'[!-[:upper:]]' \
		'[!-A-Z]' \
		'[[.-.]]' \
		'[[.-.][:upper:]]' \
		'[[.-.]A-Z]' \
		'[-]' \
		'[-[:upper:]]' \
		'[-A-Z]' \
		# retain this line #
	do      e=$1
		shift
		[[ $c == $p ]]
		g=$?
		[[ $g == $e ]] || err_exit "[[ '$c' == $p ]] for LC_COLLATE=$l failed -- expected $e, got $g"
	done
done


# tests done
exit $((Errors))
