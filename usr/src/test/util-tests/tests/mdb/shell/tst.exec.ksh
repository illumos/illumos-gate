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
# Exercise the simple shell escape "! command", which spawns $SHELL -c and
# sends the command's output to the terminal. This drives the posix_spawn
# path in mdb_shell_exec().
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
# A plain, unquoted command. Everything up to the newline is handed to the
# shell.
#
out=$($MDB <<'EOF'
! echo spawned
EOF
)
check "plain" "spawned" "$out"

#
# A single-quoted command, which may itself contain a semicolon without it
# being taken as a debugger command separator.
#
out=$($MDB <<'EOF'
! 'echo one; echo two'
EOF
)
check "squote-semi" $'one\ntwo' "$out"

#
# A double-quoted command, whose body is subject to C escape processing.
#
out=$($MDB <<'EOF'
! "echo hello"
EOF
)
check "dquote" "hello" "$out"

#
# A double-quoted command may contain single quotes verbatim, as needed for an
# awk program.
#
out=$($MDB <<'EOF'
! "awk 'BEGIN { print 42 }'"
EOF
)
check "dquote-squote" "42" "$out"

exit 0
