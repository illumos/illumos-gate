#!/usr/bin/ksh
#
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
# Copyright 2020 Oxide Computer Company
#

HEAD=${HEAD:=/usr/bin/head}
TMPFILE=/tmp/head_test.out.$$
TMPINPUT=/tmp/head_test.in.$$

test_fail() {
	echo "$*"
	((failures++))
}

test_one() {
	typeset desc="$1"
	shift
	typeset input="$1"
	shift
	typeset output="$1"
	shift

	printf "Running %s: " "$desc"
	if [[ "$input" == "-" ]]; then
		$HEAD $* > $TMPFILE
	else
		printf "$input" | $HEAD $* > $TMPFILE
	fi

	if [[ $? -ne 0 ]]; then
		test_fail "head exited non-zero"
		return
	fi

	if [[ ! -f "$output" ]]; then
		test_fail "missing expeced output file $output"
		return
	fi

	if ! diff $output $TMPFILE >/dev/null 2>/dev/null; then
		test_fail "output mismatch"
		return
	fi

	printf "passed\n"
}

if ! cd $(dirname $0); then
	printf "failed to reach test directory!\n" 1>&2
	exit 1
fi

test_one "simple stdin 1" "a\n\n\nb\n" stdin.1.out
test_one "simple stdin 2 -n 1" "a\n\n\nb\n" stdin.2.out "-n 1"
test_one "simple stdin 3 -n 3" "a\n\n\nb\n" stdin.3.out "-n 3"
test_one "simple stdin 4 -n 10000" "a\n\n\nb\n" stdin.1.out "-n 10000"
test_one "simple stdin 5 -c 1" "a\n\n\nb\n" stdin.5.out "-c 1"
test_one "simple stdin 6 -c 230" "a\n\n\nb\n" stdin.1.out "-c 230"
test_one "simple stdin 7 -n 3 -q" "a\n\n\nb\n" stdin.3.out "-n 3" "-q"
test_one "simple stdin 8 -" "a\n\n\nb\n" stdin.2.out "-1"
test_one "simple stdin 9 -23" "a\n\n\nb\n" stdin.1.out "-23"
test_one "simple stdin 10 -q" "a\n\n\nb\n" stdin.1.out "-q"
#
# Note, different implementations have different behaviours when -v is specified
# and there is only standard input. This verifies our current choice.
#
test_one "simple stdin 11 -v" "a\n\n\nb\n" stdin.11.out "-v"
test_one "stdin nul 1" "hello\0regression\n" stdin-nul.1.out
test_one "stdin nul 2 -c 1" "hello\0regression\n" stdin-nul.2.out "-c 1"
test_one "stdin nul 3" "this\0\nwas\0an\0\n\nunfortunate\0buf\0\n" \
    stdin-nul.3.out

test_one "5221 regression" "Old\nBill Joy\nBug\n\nLasts Forever\n" 5221.out \
    5221.in /dev/stdin
test_one "/dev/stdin repeated" "Hello\n" stdin.multi.out /dev/stdin /dev/stdin
test_one "no newline -n 3" "Why do you need newlines?" stdin.nonewline.out \
    "-n 3"

test_one "simple file 1" - rings.1.out rings.in
test_one "simple file 2 -c 30" - rings.2.out "-c 30" rings.in
test_one "simple file 3 -n 7" - rings.3.out "-n 7" rings.in
test_one "simple file 4 -50" - rings.in "-50" rings.in
test_one "simple file 5 -v" - rings.5.out "-v" rings.in
test_one "multi file 1 -n 5 -q" - multi.1.out "-n 5" "-q" rings.in \
    rings.in rings.in
test_one "multi file 2 -n 5 -q -v" - multi.1.out "-n 5" "-q" "-v" "-q" \
    rings.in rings.in rings.in
test_one "multi file 3 -n 5 -q -v -q" - multi.1.out "-n 5" "-q" "-v" "-q" \
    rings.in rings.in rings.in
test_one "multi file 4 -c 100" - multi.4.out "-c 100" rings.in rings.in

#
# Construct a file larger than 8k in size without a new line to verify that we
# will do multiple reads beyond the first.
#
rm -f $TMPINPUT
for ((i = 0; i < 10000; i++)); do
	printf "Lorem ipsum" >> $TMPINPUT
done
test_one "large input" - $TMPINPUT $TMPINPUT

rm $TMPFILE $TMPINPUT

if [[ "$failures" -ne 0 ]]; then
	printf "%u tests failed\n" "$failures" 2>&1
	exit 1
fi

printf "All tests passed successfully\n"
exit 0
