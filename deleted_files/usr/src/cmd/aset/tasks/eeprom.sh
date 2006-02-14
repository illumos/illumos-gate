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
# Copyright 1990, 1991 Sun Microsystems, Inc.  All Rights Reserved.
#
#
#ident	"%Z%%M%	%I%	%E% SMI"

exittask()
{
   exit
}

bad_value()
{
   setting=$1
   case $setting in
      none | command | full)
	 # not a bad value
         return 1;;
      *)
	 # is a bad value
	 return 0;;
   esac
}

echo
echo "*** Begin EEPROM Check ***"

eeprom=/usr/sbin/eeprom

if [ ! -x $eeprom ]
then
   exit
fi

secureline=`$eeprom -i secure`
setting=`echo $secureline | $AWK -F= '{print $2}'`
if bad_value $setting
then
   secureline=`$eeprom -i security-mode`
   setting=`echo $secureline | $AWK -F= '{print $2}'`
   if bad_value $setting
   then
      echo
      echo "Security option not found on eeprom. Task skipped."
      exittask
   fi
fi

echo
echo EEPROM security option currently set to \"$setting\".

if [ "$ASETSECLEVEL" = "med" ]
then
   if [ "$setting" != "command" ]
   then
      echo
      echo Recommend setting to \"command\".
   fi
   exittask
fi

if [ "$ASETSECLEVEL" = "high" ]
then
   if [ "$setting" != "full" ]
   then
      echo
      echo Recommend setting to \"full\".
   fi
   exittask
fi

echo
echo "*** End EEPROM Check ***"
