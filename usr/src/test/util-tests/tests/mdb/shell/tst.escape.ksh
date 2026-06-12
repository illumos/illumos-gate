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
# Copyright 2026 Oxide Computer Company
#

#
# A quoted shell command can contain a single quote by escaping it as \'. This
# is what lets a single-quoted command itself contain single quotes (an awk
# program being a very common example), and the double-quoted form honours the
# same escape.
#

export SHELL=/bin/sh

function check {
	typeset desc="$1" expect="$2" got="$3"

	if [[ "$got" != "$expect" ]]; then
		print -u2 "FAIL [$desc]: expected [$expect], got [$got]"
		exit 1
	fi
}

#
# \' within a single-quoted command.
#
out=$($MDB <<'EOF'
! 'echo \'hi there\''
EOF
)
check "squote" "hi there" "$out"

#
# \' within a double-quoted command.
#
out=$($MDB <<'EOF'
! "echo \'hi there\'"
EOF
)
check "dquote" "hi there" "$out"

#
# An awk program delimited and quoted with \'.
#
out=$($MDB <<'EOF'
! 'awk \'BEGIN { print "ok" }\''
EOF
)
check "awk" "ok" "$out"

exit 0
