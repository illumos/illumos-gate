#!/bin/bash
#
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy is of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2010 Chris Love.  All rights reserved.
# Copyright 2017, Joyent, Inc.
#

BLOCK=""
for i in {1..512}; do
	BLOCK+="."
done


checktest()
{
	local actual=$1
	local output=$2
	local test=$3

	if [[ "$actual" != "$output" ]]; then
		echo "$CMD: test $test: FAIL"
		echo -e "$CMD: test $test: expected output:\n$output"
		echo -e "$CMD: test $test: actual output:\n$actual"
	else
		echo "$CMD: test $test: pass"
	fi
}

checkfail()
{
	printf "foobar" | $PROG $* &> /dev/null

	if [[ $? -eq 0 ]]; then
		printf '%s: test "test %s": was supposed to fail\n' "$CMD" "$*"
	else
		printf '%s: test "%s": pass\n' "$CMD" "$*"
	fi
}

# 
# Test cases for 'tail', some based on CoreUtils test cases (validated
# with legacy Solaris 'tail' and/or xpg4 'tail').  Note that this is designed
# to be able to run on BSD systems as well to check our behavior against
# theirs (some behavior that is known to be idiosyncratic to illumos is
# skipped on non-illumos systems).
#
PROG=/usr/bin/tail
CMD=`basename $0`
DIR=""

while [[ $# -gt 0 ]]; do
	case $1 in
	    -x)
		PROG=/usr/xpg4/bin/tail
		shift
		;;
	    -o)
		PROG=$2
		shift 2
		;;
	    -d)
		DIR=$2
		shift 2
		;;
	    *)
		echo "Usage: tailtests.sh" \
		    "[-x][-o <override tail executable>]" \
		    "[-d <override output directory>]"
		exit 1
		;;
	esac
done

#
# Shut bash up upon receiving a term so we can drop it on our children
# without disrupting the output.
#
trap "exit 0" TERM

echo "$CMD: program is $PROG"

if [[ $DIR != "" ]]; then
	echo "$CMD: directory is $DIR"
fi

o=`echo -e "bcd"`
a=`echo -e "abcd" | $PROG +2c`
checktest "$a" "$o" 1

o=`echo -e ""`
a=`echo "abcd" | $PROG +8c`
checktest "$a" "$o" 2

o=`echo -e "abcd"`
a=`echo "abcd" | $PROG -9c`
checktest "$a" "$o" 3

o=`echo -e "x"`
a=`echo -e "x" | $PROG -1l`
checktest "$a" "$o" 4

o=`echo -e "\n"`
a=`echo -e "x\ny\n" | $PROG -1l`
checktest "$a" "$o" 5

o=`echo -e "y\n"`
a=`echo -e "x\ny\n" | $PROG -2l`
checktest "$a" "$o" 6

o=`echo -e "y"`
a=`echo -e "x\ny" | $PROG -1l`
checktest "$a" "$o" 7

o=`echo -e "x\ny\n"`
a=`echo -e "x\ny\n" | $PROG +1l`
checktest "$a" "$o" 8

o=`echo -e "y\n"`
a=`echo -e "x\ny\n" | $PROG +2l`
checktest "$a" "$o" 9

o=`echo -e "x"`
a=`echo -e "x" | $PROG -1`
checktest "$a" "$o" 10

o=`echo -e "\n"`
a=`echo -e "x\ny\n" | $PROG -1`
checktest "$a" "$o" 11

o=`echo -e "y\n"`
a=`echo -e "x\ny\n" | $PROG -2`
checktest "$a" "$o" 12

o=`echo -e "y"`
a=`echo -e "x\ny" | $PROG -1`
checktest "$a" "$o" 13

o=`echo -e "x\ny\n"`
a=`echo -e "x\ny\n" | $PROG +1`
checktest "$a" "$o" 14

o=`echo -e "y\n"`
a=`echo -e "x\ny\n" | $PROG +2`
checktest "$a" "$o" 15

o=`printf "yyz\n"`
a=`printf "xyyyyyyyyyyz\n" | $PROG +10c`
checktest "$a" "$o" 16

o=`printf "y\ny\nz\n"`
a=`printf "x\ny\ny\ny\ny\ny\ny\ny\ny\ny\ny\nz\n" | $PROG +10l`
checktest "$a" "$o" 17

o=`printf "y\ny\ny\ny\ny\ny\ny\ny\ny\nz\n"`
a=`printf "x\ny\ny\ny\ny\ny\ny\ny\ny\ny\ny\nz\n" | $PROG -10l`
checktest "$a" "$o" 18

a=`printf "o\nn\nm\nl\nk\nj\ni\nh\ng\n"`
o=`printf "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\n" | $PROG +10lr`
checktest "$a" "$o" 19

a=`printf "o\nn\nm\nl\nk\nj\ni\nh\ng\nf\n"`
o=`printf "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\n" | $PROG -10lr`
checktest "$a" "$o" 20

a=`printf "o\nn\nm\nl\n"`
o=`printf "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\n" | $PROG +10cr`
checktest "$a" "$o" 21

a=`printf "o\nn\nm\nl\nk\n"`
o=`printf "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\n" | $PROG -10cr`
checktest "$a" "$o" 22

#
# For reasons that are presumably as accidental as they are ancient, legacy
# (and closed) Solaris tail(1) allows +c, +l and -l to be aliases for +10c,
# +10l and -10l, respectively.  If we are on SunOS, verify that this silly
# behavior is functional.
#
if [[ `uname -s` == "SunOS" ]]; then
	o=`printf "yyz\n"`
	a=`printf "xyyyyyyyyyyz\n" | $PROG +c`
	checktest "$a" "$o" 16a

	o=`printf "y\ny\nz\n"`
	a=`printf "x\ny\ny\ny\ny\ny\ny\ny\ny\ny\ny\nz\n" | $PROG +l`
	checktest "$a" "$o" 17a

	o=`printf "y\ny\ny\ny\ny\ny\ny\ny\ny\nz\n"`
	a=`printf "x\ny\ny\ny\ny\ny\ny\ny\ny\ny\ny\nz\n" | $PROG -l`
	checktest "$a" "$o" 18a

	a=`printf "o\nn\nm\nl\nk\nj\ni\nh\ng\n"`

	o=`printf "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\n" | $PROG +lr`
	checktest "$a" "$o" 19a

	o=`printf "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\n" | $PROG +l -r`
	checktest "$a" "$o" 19a

	a=`printf "o\nn\nm\nl\nk\nj\ni\nh\ng\nf\n"`

	o=`printf "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\n" | $PROG -lr`
	checktest "$a" "$o" 20a

	o=`printf "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\n" | $PROG -l -r`
	checktest "$a" "$o" 20b

	a=`printf "o\nn\nm\nl\n"`

	o=`printf "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\n" | $PROG +cr`
	checktest "$a" "$o" 21a

	o=`printf "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\n" | $PROG +c -r`
	checktest "$a" "$o" 21a

	a=`printf "o\nn\nm\nl\nk\n"`

	o=`printf "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\n" | $PROG -cr`
	checktest "$a" "$o" 22a

	o=`printf "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\no\n" | $PROG -c -r`
	checktest "$a" "$o" 22b
fi

o=`echo -e "c\nb\na"`
a=`echo -e "a\nb\nc" | $PROG -r`
checktest "$a" "$o" 23

#
# Now we want to do a series of follow tests.
#
if [[ $DIR == "" ]]; then
	export TMPDIR=/var/tmp
	tdir=$(mktemp -d -t tailtest.XXXXXXXX || exit 1)
else
	tdir=$(mktemp -d $DIR/tailtest.XXXXXXXX || exit 1)
fi

follow=$tdir/follow
moved=$tdir/follow.moved
out=$tdir/out

#
# First, verify that following works in its most basic sense.
#
echo -e "a\nb\nc" > $follow
$PROG -f $follow > $out 2> /dev/null &
child=$!
sleep 2
echo -e "d\ne\nf" >> $follow
sleep 1
kill $child
sleep 1

o=`echo -e "a\nb\nc\nd\ne\nf\n"`
a=`cat $out`
checktest "$a" "$o" 24
rm $follow

#
# Now verify that following correctly follows the file being moved.
#
echo -e "a\nb\nc" > $follow
$PROG -f $follow > $out 2> /dev/null &
child=$!
sleep 2
mv $follow $moved

echo -e "d\ne\nf" >> $moved
sleep 1
kill $child
sleep 1

o=`echo -e "a\nb\nc\nd\ne\nf\n"`
a=`cat $out`
checktest "$a" "$o" 25
rm $moved

#
# And now truncation with the new offset being less than the old offset.
#
echo -e "a\nb\nc" > $follow
$PROG -f $follow > $out 2> /dev/null &
child=$!
sleep 2
echo -e "d\ne\nf" >> $follow
sleep 1
echo -e "g\nh\ni" > $follow
sleep 1
kill $child
sleep 1

o=`echo -e "a\nb\nc\nd\ne\nf\ng\nh\ni\n"`
a=`cat $out`
checktest "$a" "$o" 26
rm $follow

#
# And truncation with the new offset being greater than the old offset.
#
echo -e "a\nb\nc" > $follow
sleep 1
$PROG -f $follow > $out 2> /dev/null &
child=$!
sleep 2
echo -e "d\ne\nf" >> $follow
sleep 1
echo -e "g\nh\ni\nj\nk\nl\nm\no\np\nq" > $follow
sleep 1
kill $child
sleep 1

o=`echo -e "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\no\np\nq"`
a=`cat $out`
checktest "$a" "$o" 27
rm $follow

#
# Verify that we can follow the moved file and correctly see a truncation.
#
echo -e "a\nb\nc" > $follow
$PROG -f $follow > $out 2> /dev/null &
child=$!
sleep 2
mv $follow $moved

echo -e "d\ne\nf" >> $moved
sleep 1
echo -e "g\nh\ni\nj\nk\nl\nm\no\np\nq" > $moved
sleep 1
kill $child
sleep 1

o=`echo -e "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\no\np\nq"`
a=`cat $out`
checktest "$a" "$o" 28
rm $moved

#
# Verify that capital-F follow properly deals with truncation
#
echo -e "a\nb\nc" > $follow
$PROG -F $follow > $out 2> /dev/null &
child=$!
sleep 2
echo -e "d\ne\nf" >> $follow
sleep 1
echo -e "g\nh\ni" > $follow
sleep 1
kill $child
sleep 1

o=`echo -e "a\nb\nc\nd\ne\nf\ng\nh\ni\n"`
a=`cat $out`
checktest "$a" "$o" 29
rm $follow

#
# Verify that capital-F follow _won't_ follow the moved file and will
# correctly deal with recreation of the original file.
#
echo -e "a\nb\nc" > $follow
$PROG -F $follow > $out 2> /dev/null &
child=$!
sleep 2
mv $follow $moved

echo -e "x\ny\nz" >> $moved

#
# At this point, tail is polling on stat'ing the missing file; we need to
# be sure to sleep long enough after recreating it to know that it will pick
# it up.
#
echo -e "d\ne\nf" > $follow
sleep 5
kill $child
sleep 1

o=`echo -e "a\nb\nc\nd\ne\nf\n"`
a=`cat $out`
checktest "$a" "$o" 30
rm $moved

#
# Verify that following two files works.
#
echo -e "one" > $follow
echo -e "two" > $moved
$PROG -f $follow $moved > $out 2> /dev/null &
child=$!
sleep 2
echo -e "three" >> $follow
sleep 1
echo -e "four" >> $moved
sleep 1
echo -e "five" >> $follow
sleep 1
kill $child
sleep 1

# There is a bug where the content comes before the header lines,
# where rlines/mapprint happens before the header.  A pain to fix.
# In this test, just make sure we see both files change.
o="one

==> $follow <==
two

==> $moved <==

==> $follow <==
three

==> $moved <==
four

==> $follow <==
five"
a=`cat $out`
checktest "$a" "$o" 31
rm $follow $moved

if [[ `uname -s` == "SunOS" ]]; then
	#
	# Use DTrace to truncate the file between the return from port_get()
	# and the reassociation of the file object with the port, exposing
	# any race conditions whereby FILE_TRUNC events are lost.
	#
	cat /dev/null > $follow
	dtrace -c "$PROG -f $follow" -s /dev/stdin > $out <<EOF
		#pragma D option destructive
		#pragma D option quiet 

		pid\$target::port_get:return
		/++i == 5/
		{
			stop();
			system("cat /dev/null > $follow");
			system("prun %d", pid);
		}

		tick-1sec
		{
			system("echo %d >> $follow", j++);
		}

		tick-1sec
		/j == 10/
		{
			exit(0);
		}
EOF

	o=`echo -e "0\n1\n2\n3\n5\n6\n7\n8\n9\n"`
	a=`cat $out`
	checktest "$a" "$o" 31a
	rm $follow

	cat /dev/null > $follow
	dtrace -c "$PROG -f $follow" -s /dev/stdin > $out <<EOF
		#pragma D option destructive
		#pragma D option quiet 

		pid\$target::port_get:return
		/++i == 5/
		{
			stop();
			system("mv $follow $moved");
			system("cat /dev/null > $moved");
			system("prun %d", pid);
		}

		tick-1sec
		{
			system("echo %d >> %s", j++,
			    i < 5 ? "$follow" : "$moved");
		}

		tick-1sec
		/j == 10/
		{
			exit(0);
		}
EOF

	o=`echo -e "0\n1\n2\n3\n5\n6\n7\n8\n9\n"`
	a=`cat $out`
	checktest "$a" "$o" 31b
	rm $moved

	#
	# Verify that -F will deal properly with the file being truncated
	# not by truncation, but rather via an ftruncate() from logadm.
	#
	cat /dev/null > $follow
	( $PROG -F $follow > $out ) &
	child=$!
	echo -e "a\nb\nc\nd\ne\nf" >> $follow
	logadm -c $follow
	sleep 2
	echo -e "g\nh\ni" >> $follow
	sleep 2
	kill $child
	sleep 1

	o=`echo -e "a\nb\nc\nd\ne\nf\ng\nh\ni\n"`
	a=`cat $out`
	checktest "$a" "$o" 31c
fi

#
# We're now going to test that while we may miss output due to truncations
# occurring faster than tail can read, we don't ever repeat output.
#
cat /dev/null > $follow
( $PROG -f $follow > $out ) &
tchild=$!
( let i=0 ; while true; do echo $i > $follow ; sleep 0.1; let i=i+1 ; done ) &
child=$!
sleep 10
kill $tchild
kill $child

a=`sort $out | uniq -c | sort -n | tail -1 | awk '{ print $1 }'`
o=1

checktest "$a" "$o" 32

# Test different ways of specifying character offsets
o=`printf "d\n"`

a=`printf "hello\nworld\n" | $PROG -c2`
checktest "$a" "$o" 33

a=`printf "hello\nworld\n" | $PROG -c-2`
checktest "$a" "$o" 34

a=`printf "hello\nworld\n" | $PROG -c 2`
checktest "$a" "$o" 35

a=`printf "hello\nworld\n" | $PROG -c -2`
checktest "$a" "$o" 36

a=`printf "hello\nworld\n" | $PROG -2c`
checktest "$a" "$o" 37

o=`printf "llo\nworld\n"`

a=`printf "hello\nworld\n" | $PROG -c +3`
checktest "$a" "$o" 38

a=`printf "hello\nworld\n" | $PROG -c+3`
checktest "$a" "$o" 39

a=`printf "hello\nworld\n" | $PROG +3c`
checktest "$a" "$o" 40

# Test various ways of specifying block offsets
o=`printf "$BLOCK"`

a=`printf "${BLOCK//./x}$BLOCK" | $PROG -b1`
checktest "$a" "$o" 41

a=`printf "${BLOCK//./x}$BLOCK" | $PROG -b 1`
checktest "$a" "$o" 42

a=`printf "${BLOCK//./x}$BLOCK" | $PROG -b -1`
checktest "$a" "$o" 43

a=`printf "${BLOCK//./x}$BLOCK" | $PROG -b +2`
checktest "$a" "$o" 44

# Test that illegal arguments aren't allowed

checkfail +b2
checkfail +c3
checkfail -l3
checkfail -cz
checkfail -bz
checkfail -nz
checkfail -3n
checkfail +3n
checkfail +n3
checkfail -lfoobar

echo "$CMD: completed"

exit $errs

