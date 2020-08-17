#!/bin/ksh -p
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source. A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.

# Copyright 2020 OmniOS Community Edition (OmniOSce) Association.

SED=${SED:=/usr/bin/sed}

function fatal {
	echo "[FATAL] $*" > /dev/stderr
	exit 1
}

function runtest {
	typeset script="$1"
	typeset expect="$2"
	typeset files="${3:-$input1}"

	typeset ef=`mktemp`
	[[ -n "$expect" ]] && printf "%s\n" $expect > $ef

	$SED -n "$script" $files > $output
	if [[ $? -eq 0 ]] && cmp -s $output $ef; then
		echo "[PASS] sed $script $files"
	else
		echo "[FAIL] sed $script $files"
		diff -u $ef $output
		err=1
	fi
	rm -f $ef
}

for f in input1 input2 output; do
	tf=`mktemp`
	[[ -n "$tf" && -f "$tf" ]] || fatal "Could not create temp file $f"
	eval $f=$tf
done

typeset err=0

printf "%s\n" a b c d e f g h a j > $input1
[[ $? -eq 0 && -s "$input1" ]] || fatal "Could not populate input1 file"
printf "%s\n" m n o p q z > $input2
[[ $? -eq 0 && -s "$input2" ]] || fatal "Could not populate input2 file"

# Simple
runtest "3p" "c"
runtest "\$p" "j"
runtest "7,\$p" "g h a j"
runtest "/d/p" "d"
runtest "/a/p" "a a"

# Ranges
runtest "5,7p" "e f g"
runtest "5,4p" "e"
runtest "/a/,4p" "a b c d a"
runtest "0,/b/p" ""
runtest "4,/a/p" "d e f g h a"
runtest "/d/,/g/p" "d e f g"

# Relative ranges
runtest "3,+0p" "c"
runtest "3,+1p" "c d"
runtest "5,+3p" "e f g h"
runtest "6,+3p" "f g h a"
runtest "7,+3p" "g h a j"
runtest "8,+3p" "h a j"
runtest "/a/,+1p" "a b a j"
runtest "/a/,+8p" "a b c d e f g h a"
runtest "/a/,+9p" "a b c d e f g h a j"

# Negative
runtest "4,7!p" "a b c h a j"
runtest "6,+3!p" "a b c d e j"
runtest "7,+3!p" "a b c d e f"
runtest "8,+3!p" "a b c d e f g"

# Branch
runtest "4,7 { /e/b
		p
	}" "d f g"
runtest "4,+3 { /e/b
		p
	}" "d f g"

# stdin
cat $input2 $input2 | runtest "\$p" "z" " "

# Multi-file
for fileset in \
	"$input1 $input2" \
	"$input1 /dev/null $input2" \
	"/dev/null $input1 $input2" \
	"$input1 $input2 /dev/null" \
	"$input1 /dev/null $input2 /dev/null" \
	"/dev/null $input1 /dev/null $input2" \
	"$input1 $input2 /dev/null /dev/null" \
	"$input1 /dev/null /dev/null $input2 /dev/null" \
	"/dev/null $input1 /dev/null /dev/null $input2" \
; do
	runtest "\$p" "z" "$fileset"
	runtest "3p" "c" "$fileset"
	runtest "13p" "o" "$fileset"
done

rm -f $input1 $input2 $output

[[ $err -eq 0 ]] && echo "--- All sed_addr tests passed"

exit $err
