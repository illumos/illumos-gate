#!/bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Runs the command passed as arguments, echoes the output to stderr.
#
# Exits with 0 (success) if the command exits with 0 and has no
# output.
#
# Exits with 1 (failure) if the command exits with 0 and has output.
#
# Exits with the exit code of the command if it exits with a non-zero
# exit code.

output=`"$@" 2>&1`
result=$?

if [ -n "$output" ]
then
    echo "$output" >&2
    test $result = 0 && result=1
fi

exit $result
