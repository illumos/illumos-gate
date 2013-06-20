#! /usr/bin/sh
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

# Copyright 2016, Richard Lowe.

select_test=$(dirname $0)/select_test


# Below the stack and bulk alloc limits
i=0
while (( $i < 500 )); do
    i=$(($i + 1))

    $select_test 512 || exit 1
done;

# above the stack limit
i=0
while (( $i < 500 )); do
    i=$(($i + 1))

    $select_test 2048 || exit 1
done;

# above the bulk limit
i=0
while (( $i < 500 )); do
    i=$(($i + 1))

    $select_test 9001 || exit 1
done;
