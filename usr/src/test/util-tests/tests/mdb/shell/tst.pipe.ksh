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
# Exercise the "dcmd ! command" form, which sends the output of the preceding
# dcmd to $SHELL -c and the command's output to the terminal. This drives the
# posix_spawn path in mdb_shell_pipe().
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
# A plain, unquoted filter. ::echo appends a trailing space after the last
# word, which the pass-through filter preserves, so trim it before comparing.
#
out=$($MDB <<'EOF'
::echo abc ! tr a-z A-Z
EOF
)
out=${out% }
check "plain" "ABC" "$out"

#
# A single-quoted awk filter, quoted with \', as a user is most likely to
# write it.
#
out=$($MDB <<'EOF'
::echo alpha beta gamma ! 'awk \'{print $3}\''
EOF
)
check "squote-awk" "gamma" "$out"

#
# The same with the double-quoted form, where the single quotes around the awk
# program need no escaping.
#
out=$($MDB <<'EOF'
::echo alpha beta gamma ! "awk '{print $2}'"
EOF
)
check "dquote-awk" "beta" "$out"

#
# A double-quoted awk program with the inner double quotes escaped as \" and
# the field reference protected from the shell with \$, so that the $1 reaches
# awk rather than being expanded by the shell.
#
out=$($MDB <<'EOF'
::echo alpha beta gamma ! "awk \"{print \$1}\""
EOF
)
check "dquote-escdollar" "alpha" "$out"

exit 0
