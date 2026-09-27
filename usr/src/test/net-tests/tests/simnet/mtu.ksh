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

#
# Copyright 2026 Michal Skalski
#

#
# Exercise simnet's MTU bounds and property metadata on both temporary and
# persistent links, including changing the MTU to the maximum supported
# value from a lower value.
# No IP interfaces or peers are needed. Only links created here are removed.
#

export PATH=/usr/sbin:/usr/bin
export LC_ALL=C.UTF-8
unalias -a
typeset -a links=()
typeset -i failures=0
typeset -i nextlink=0

function fail
{
	print -u2 -- "FAIL: $*"
	((failures++))
}

function cleanup
{
	typeset link
	for link in "${links[@]}"; do
		if ! dladm delete-simnet "$link"; then
			fail "delete $link"
		fi
	done
	if ((failures != 0)); then
		exit 1
	fi
}

trap cleanup EXIT

if (( $(id -u) != 0 )); then
	print -u2 'This test must run as root.'
	exit 1
fi

function check_prop
{
	typeset link=$1 field=$2 expected=$3 flags=$4 actual

	if ! actual=$(dladm show-linkprop $flags -c -o "$field" -p mtu \
	    "$link"); then
		fail "$link: read $field"
		return
	fi
	[[ "$actual" == "$expected" ]] ||
	    fail "$link: $flags $field: expected $expected, got $actual"
}

function test_link
{
	typeset media=$1 flags=$2 link="smtu$$_$nextlink" mtu before
	((nextlink++))

	print -- "Testing $media simnet ($flags): $link"
	if ! dladm create-simnet $flags -m "$media" "$link"; then
		fail "$link: create"
		return
	fi
	links+=("$link")
	check_prop "$link" possible 60-9000

	for mtu in 60 61 1499 1500 8999 9000 1500 9000; do
		if ! dladm set-linkprop $flags -p mtu=$mtu "$link"; then
			fail "$link: set MTU $mtu"
			continue
		fi
		check_prop "$link" value "$mtu"
		check_prop "$link" possible 60-9000
		if [[ -z "$flags" ]]; then
			check_prop "$link" value "$mtu" -P
		fi
	done

	if ! before=$(dladm show-linkprop -c -o value -p mtu "$link"); then
		fail "$link: read MTU before invalid requests"
		return
	fi
	for mtu in 0 59 9001; do
		if dladm set-linkprop $flags -p mtu=$mtu "$link" \
		    >/dev/null 2>&1; then
			fail "$link: accepted invalid MTU $mtu"
		fi
		check_prop "$link" value "$before"
		check_prop "$link" possible 60-9000
		if [[ -z "$flags" ]]; then
			check_prop "$link" value "$before" -P
		fi
	done
}

for media in Ethernet wifi; do
	test_link "$media" -t
	test_link "$media" ''
done

if ((failures != 0)); then
	print -u2 -- "$failures checks failed"
	exit 1
fi
print 'All simnet MTU checks passed'
