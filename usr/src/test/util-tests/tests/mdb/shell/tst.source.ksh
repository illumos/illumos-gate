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
# Exercise the "!<" shell input escape, which runs a shell command and then
# evaluates its standard output as debugger commands. Both the bare form and
# the pipeline form (where dcmd output is first sent to the command) are
# covered. ::echo appends a trailing space after the last word, which is
# trimmed before comparing.
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
# Bare form: the command emits a debugger command, which is then sourced and
# run.
#
out=$($MDB <<'EOF'
!< echo '::echo sourced'
EOF
)
out=${out% }
check "source" "sourced" "$out"

#
# Pipeline form: the output of the dcmd is fed to the shell command, whose
# output is collected and then sourced once the pipeline has completed.
#
out=$($MDB <<'EOF'
::echo 10 20 30 !< awk '{print "::echo total " $1+$2+$3}'
EOF
)
out=${out% }
check "source-pipe" "total 60" "$out"

exit 0
