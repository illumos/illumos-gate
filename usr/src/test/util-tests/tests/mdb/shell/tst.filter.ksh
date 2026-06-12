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
# A quote-delimited shell command can form a stage of a dcmd pipeline:
# "dcmd ! 'command' | dcmd". The producing dcmd's output is filtered by the
# shell command and the result is parsed as addresses for the consuming dcmd.
# ::map prints each incoming address in the current (here, the default
# hexadecimal) radix, so a value that survives the filter is echoed back
# unchanged.
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
# A filter that emits more than one address. The pipeline reads one address
# per line (::echo prints them on a single line, which would not parse), so
# the awk program prints each selected field on its own line; here it picks
# the first and third, which ::map then echoes back.
#
out=$($MDB <<'EOF'
::echo 1 2 3 ! 'awk \'{ print $1; print $3 }\'' | ::map .
EOF
)
check "multi" $'1\n3' "$out"

#
# An awk filter quoted with \', selecting one field that then becomes the
# address consumed by ::map.
#
out=$($MDB <<'EOF'
::echo 1 2 3 ! 'awk \'{print $2}\'' | ::map .
EOF
)
check "awk" "2" "$out"

#
# The same selection written with the double-quoted form: \" delimits the awk
# program and \$ stops the shell expanding the field reference before awk sees
# it (within single quotes the field reference would need no protection).
#
out=$($MDB <<'EOF'
::echo 1 2 3 ! "awk \"{print \$2}\"" | ::map .
EOF
)
check "dquote-escdollar" "2" "$out"

#
# A semicolon inside the quoted command is part of the command, not a debugger
# statement separator.
#
out=$($MDB <<'EOF'
::echo 1 2 3 ! 'awk \'{ s = $1 + $3; print s }\'' | ::map .
EOF
)
check "semicolon" "4" "$out"

exit 0
