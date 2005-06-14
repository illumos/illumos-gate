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
#
# Copyright 1990, 1991 Sun Microsystems, Inc.  All Rights Reserved.
#
#
#ident	"%Z%%M%	%I%	%E% SMI"

# This script restores password and group files changed by usrgrp.task back
# to what they used to be according to the archive file -

passwd_arch=${ASETDIR}/archives/passwd.arch.$ASETSECLEVEL
group_arch=${ASETDIR}/archives/group.arch.$ASETSECLEVEL
shadow_arch=${ASETDIR}/archives/shadow.arch.$ASETSECLEVEL
CP=/bin/cp

myname=`expr $0 : ".*/\(.*\)" \| $0`

fail()
{
   echo
   echo "$myname failed:"
   echo $*
   exit 1
}

doit()
# usage: doit command_string
# "command_string" is expected to succeed.
{
   $*
   status=$?
   if [ $status -ne 0 ]
   then
      echo;echo "Operation failed: $*"
   fi
   return $status
}

echo
echo "Beginning $myname..."

if [ "${ASETDIR}" = "" ]
then
   fail "ASETDIR variable undefined."
fi

if [ $UID -ne 0 ]
then
   fail "Permission Denied."
fi

doit $CP /etc/passwd /etc/passwd.asetbak
if [ $? = 0 ]
then
   echo;echo "Restoring /etc/passwd. Saved existing file in /etc/passwd.asetbak."
fi

doit $CP /etc/group /etc/group.asetbak
if [ $? = 0 ]
then
   echo;echo "Restoring /etc/group. Saved existing file in /etc/group.asetbak."
fi

doit $CP /etc/shadow /etc/shadow.asetback
if [ $? = 0 ]
then
   echo; echo "Restoring /etc/shadow. Saved existing file in /etc/shadow.asetback."
fi

doit $CP $passwd_arch /etc/passwd
doit $CP $group_arch /etc/group
doit $CP $shadow_arch /etc/shadow

echo
echo "$myname completed."
