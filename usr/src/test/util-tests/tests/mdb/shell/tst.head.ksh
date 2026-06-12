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
# A quote-delimited shell command can also stand at the head of a dcmd
# pipeline ("! 'command' | dcmd"), with no producing dcmd before it. The
# command's output is parsed as the address list for the following dcmd. As
# in tst.filter, ::map echoes each incoming address in the default
# (hexadecimal) radix.
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
# The shell command emits one address per line, which become the addresses
# consumed by ::map. The semicolons are part of the quoted command, not
# debugger command separators.
#
out=$($MDB <<'EOF'
! 'echo 1; echo 2; echo 3' | ::map .
EOF
)
check "multi" $'1\n2\n3' "$out"

#
# A single decimal address, to confirm the output is reparsed through the
# normal address syntax (0t42 is decimal 42, printed back in hexadecimal).
#
out=$($MDB <<'EOF'
! 'echo 0t42' | ::map .
EOF
)
check "decimal" "2a" "$out"

#
# An awk program at the head of the pipeline, quoted with \'.
#
out=$($MDB <<'EOF'
! 'awk \'BEGIN { print 1; print 2 }\'' | ::map .
EOF
)
check "awk" $'1\n2' "$out"

#
# A command that produces no output leaves the pipeline with nothing to
# consume, so the following dcmd does not run at all.
#
out=$($MDB <<'EOF'
! 'true' | ::map .
EOF
)
check "empty" "" "$out"

exit 0
