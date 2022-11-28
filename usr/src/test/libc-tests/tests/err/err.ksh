#!/bin/ksh

#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source. A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

# Copyright 2022 OmniOS Community Edition (OmniOSce) Association.

set -o errexit
set -o pipefail

builtin print

typeset -r ROOT=$(dirname $0)
typeset -ri MAX_VARIANT=5

typeset -i failures=0

function fatal
{
	echo "Test Failed: $@" >&2
	exit 1
}

function fail
{
	((failures++))
	echo "FAIL: $*" >&2
}

function pass
{
	echo "PASS:  $*"
}

function run
{
	typeset key="$1"
	typeset keyf="$ROOT/data/$key"
	shift;

	stderr=${ { stdout=$("$@"); } 2>&1; }
	exit=$?
	output=${
		cat <<- EOM
			::STDOUT::
			$stdout
			::STDERR::
			$stderr
			::EXIT::
			$exit
		EOM
	}
	if [[ -r "$keyf" ]]; then
		expect=$(<$keyf)
	else
		fatal "Data file $keyf is not readable"
	fi

	if [[ "$expect" != "$output" ]]; then
		fail "$key"
		diff -u <(print "$output") <(print "$expect") || true
	else
		pass "$key"
	fi
}

for v in {0..$MAX_VARIANT}; do
	((errcode = 3 + v * 2))
	((exitcode = 4 + v * 2))
	key="${v}.${errcode}.${exitcode}"

	# err(3C) family
	cmd="$ROOT/err -v $v -e $errcode -x $exitcode"
	run "E.$key" $cmd

	# warn(3C) family
	cmd="$ROOT/err -v $v -e $errcode"
	run "W.$key" $cmd
done

exit $failures

