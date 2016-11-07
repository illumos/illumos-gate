#! /usr/bin/ksh
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
# Copyright 2015, Richard Lowe.
#

mkdir /tmp/$$-secflags-test
cd /tmp/$$-secflags-test

/usr/bin/psecflags -s none $$   # Clear ourselves out
cat > expected <<EOF
	I:	none
EOF

/usr/bin/psecflags $$ | grep I: > output
diff -u expected output || exit 1 # Make sure the setting of 'none' worked

cleanup() {
    cd /
    rm -fr /tmp/$$-secflags-test
}
trap cleanup EXIT

## Tests of manipulating a running process (ourselves)

self_set() {
    echo "Set (self)"
    /usr/bin/psecflags -s aslr $$

    cat > expected <<EOF
	I:	aslr
EOF

    /usr/bin/psecflags $$ | grep I: > output
    diff -u expected output || exit 1
}

self_add() {
    echo "Add (self)"
    /usr/bin/psecflags -s current,noexecstack $$
    cat > expected <<EOF
	I:	aslr,noexecstack
EOF

    /usr/bin/psecflags $$ | grep I: > output
    diff -u expected output || exit 1
}

self_remove() {
    echo "Remove (self)"
    /usr/bin/psecflags -s current,-aslr $$
    cat > expected <<EOF
	I:	noexecstack
EOF

    /usr/bin/psecflags $$ | grep I: > output
    diff -u expected output || exit 1
}

self_all() {
    echo "All (self)"
    /usr/bin/psecflags -s all $$
    /usr/bin/psecflags $$ | grep -q 'I:.*,.*,' || exit 1 # This is lame, but functional
}

self_none() {
    echo "None (self)"
    /usr/bin/psecflags -s all $$
    /usr/bin/psecflags -s none $$
    cat > expected <<EOF
	I:	none
EOF
    /usr/bin/psecflags $$ | grep I: > output
    diff -u expected output || exit 1
}

child_set() {
    echo "Set (child)"

    typeset pid; 

    /usr/bin/psecflags -s aslr -e sleep 10000 &
    pid=$!
    cat > expected <<EOF
	E:	aslr
	I:	aslr
EOF
    /usr/bin/psecflags $pid | grep '[IE]:' > output
    kill $pid
    diff -u expected output || exit 1
}

child_add() {
    echo "Add (child)"

    typeset pid; 

    /usr/bin/psecflags -s aslr $$
    /usr/bin/psecflags -s current,noexecstack -e sleep 10000 &
    pid=$!
    cat > expected <<EOF
	E:	aslr,noexecstack
	I:	aslr,noexecstack
EOF
    /usr/bin/psecflags $pid | grep '[IE]:' > output
    kill $pid
    /usr/bin/psecflags -s none $$
    diff -u expected output || exit 1
}

child_remove() {
    echo "Remove (child)"

    typeset pid; 

    /usr/bin/psecflags -s aslr $$
    /usr/bin/psecflags -s current,-aslr -e sleep 10000 &
    pid=$!
    cat > expected <<EOF
	E:	none
	I:	none
EOF
    /usr/bin/psecflags $pid | grep '[IE]:' > output
    kill $pid
    /usr/bin/psecflags -s none $$
    diff -u expected output || exit 1
}

child_all() {
    echo "All (child)"

    typeset pid ret

    /usr/bin/psecflags -s all -e sleep 10000 &
    pid=$!
    /usr/bin/psecflags $pid | grep -q 'E:.*,.*,' # This is lame, but functional
    ret=$?
    kill $pid
    (( $ret != 0 )) && exit $ret
}

child_none() {
    echo "None (child)"

    typeset pid
    
    /usr/bin/psecflags -s all $$

    /usr/bin/psecflags -s none -e sleep 10000 &
    pid=$!
    cat > expected <<EOF
	E:	none
	I:	none
EOF
    /usr/bin/psecflags $pid | grep '[IE]:' > output
    kill $pid
    diff -u expected output || exit 1
}

list() {
    echo "List"
    cat > expected<<EOF
aslr
forbidnullmap
noexecstack
EOF

    /usr/bin/psecflags -l > output
    diff -u expected output || exit 1
}

self_set
self_add
self_remove
self_all
self_none
child_set
child_add
child_remove
child_all
child_none
list

exit 0
