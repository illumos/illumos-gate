#!/bin/ksh
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
# Copyright 2024 Bill Sommerfeld <sommerfeld@hamachi.org>
#

#
# Tests for find(1) that exercise file ownership tests and thus need
# to run as root to set up the test
#

# Regression test for SID operations

. "$(dirname $0)/find.kshlib"

if [ $(svcs -H -o state svc:/system/idmap) != "online" ]; then
    echo "svc:/system/idmap not enabled and online; can't do SID-to-UID mapping" >&2
    exit 4
fi

sida=S-1-5-21-11111111-22222222-33333333
sidb=S-1-5-21-44444444-55555555-66666666

mkdir -p $find_dir/a
mkdir -p $find_dir/b

# Functional test for -usid and -gsid

chown -s $sida $find_dir/a
chgrp -s $sidb $find_dir/b

cd $find_dir

testfind "./a", $find_prog . -usid ${sida}
testfind "./b", $find_prog . -gsid ${sidb}

# Functional test for -usidacl and -gsidacl

chmod A+groupsid:${sidb}:read_set:allow $find_dir/a
chmod A+usersid:${sida}:read_set:allow $find_dir/b

testfind "./a", $find_prog . -gsidacl ${sidb}
testfind "./b", $find_prog . -usidacl ${sida}

# Functional test for -sidacl

mkdir $find_dir/c
mkdir $find_dir/d

chmod A+groupsid:${sida}:read_set:allow $find_dir/c
chmod A+usersid:${sidb}:read_set:allow $find_dir/d

testfind "./b,./c," $find_prog . -sidacl ${sida}
testfind "./a,./d," $find_prog . -sidacl ${sidb}

cd -
rm -rf $find_dir

exit $find_exit
