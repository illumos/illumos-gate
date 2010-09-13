#! /bin/ksh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#


# Script to wrap a non-windowing clean script to provide a prompt 
# before the dtterm window closes, and to catch abnormal terminations.

# For any abnormal termination of the clean script, kill our parent
# process so that our grandparent will know that the script did not
# terminate normally.  (We expect our parent to be dtterm, and our
# grandparent to be allocate.)

# Trap any signal that would cause abnormal termination of the script,
# This catches use of ^C, ^Z, etc., and it also catches the HUP signal
# when the dtterm window is closed before the script is finished.

PARENT_KILLED=no

killparent() {
  if [ $PARENT_KILLED = "no" ]; then
    PARENT_KILLED=yes
    kill -9 $PPID
  fi
}

trap "killparent" HUP INT TERM QUIT TSTP ABRT

SCRIPT=$1
shift

if [ ! -e $SCRIPT ]; then
	echo **** Clean script $SCRIPT not found **** 
	echo "**** Press RETURN to close window ****"
	read
	kill -9 $PPID
fi

echo "**** Device cleanup for $2 ****\n"

$SCRIPT "$@"
STAT=$?

echo "\n**** Press RETURN to close window ****"
read

# If the script returned a non-zero exit status, kill our dtterm
# parent process.

if [ $STAT != 0 ]; then
	killparent
fi
