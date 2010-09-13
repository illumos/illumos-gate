#! /bin/sh
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
# Copyright (c) 1992-1993, 1997-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
#  This a clean script for all tape drives
# 

PROG=`basename $0`
PATH="/usr/sbin:/usr/bin"
TEXTDOMAIN="SUNW_OST_OSCMD"
export TEXTDOMAIN

USAGE=`gettext "%s [-I|-s|-f|-i] device"`

#
# 		*** Shell Function Declarations ***
#


con_msg() {
    form=`gettext "%s: Media in %s is ready.  Please, label and store safely."`
    if [ "$silent" != "y" ] ; then
	printf "${form}\n" $PROG $DEVICE > /dev/console
    fi
}

e_con_msg() {
    form=`gettext "%s: Error cleaning up device %s."`
    if [ "$silent" != "y" ] ; then
	printf "${form}\n" $PROG $DEVICE > /dev/console
    fi
}

user_msg() {
    form=`gettext "%s: Media in %s is ready.  Please, label and store safely."`
    if [ "$silent" != "y" ] ; then
	printf "${form}\n" $PROG $DEVICE > /dev/tty
    fi
}

e_user_msg() {
    form=`gettext "%s: Error cleaning up device %s."`
    if [ "$silent" != "y" ] ; then
	printf "${form}" $PROG $DEVICE > /dev/tty
	gettext "Please inform system administrator.\n" > /dev/tty
    fi
}

mk_error() {
   chown bin /etc/security/dev/$1
   chmod 0100 /etc/security/dev/$1
}

silent=n

while getopts Iifs c
do
   case $c in
   I)	FLAG=i
	silent=y;;
   i)   FLAG=$c;;
   f)   FLAG=$c;;
   s)   FLAG=$c;;
   \?)   printf "${USAGE}\n" $PROG >/dev/tty
      exit 1 ;;
   esac
done
shift `expr $OPTIND - 1`

# get the map information

TAPE=$1
MAP=`dminfo -v -n $TAPE`
DEVICE=`echo $MAP | cut -f1 -d:`
TYPE=`echo $MAP | cut -f2 -d:`
FILES=`echo $MAP | cut -f3 -d:`
DEVFILE=`echo $FILES | cut -f1 -d" "`

#if init then do once and exit

if [ "$FLAG" = "i" ] ; then
   x="`mt -f $DEVFILE rewoffl 2>&1`"
   z="$?"   

   case $z in
   0)

   # if this is a open reel tape than we a sucessful
   # else must be a cartrige tape we failed

      if mt -f $DEVFILE status 2>&1 | grep "no tape loaded" >/dev/null ; then  
         con_msg
         exit 0
      else 
         e_con_msg
         mk_error $DEVICE
         exit 1
      fi;;
   1) 
   
   # only one error mesage is satisfactory

      if echo $x | grep "no tape loaded" >/dev/null ; then
         con_msg
         exit 0
      else
         e_con_msg
         mk_error $DEVICE
         exit 1
      fi;;

   2) 

   # clean up failed exit with error

      e_con_msg
      mk_error $DEVICE
      exit 1;;

   esac
else
# interactive clean up
   x="`mt -f $DEVFILE rewoffl 2>&1`"
   z="$?"

   case $z in
   0)

   # if this is a open reel tape than we a sucessful
   # else must be a cartrige tape we must retry until user removes tape

      if mt -f $DEVFILE status 2>&1 | grep "no tape loaded"  > /dev/null ; then
         user_msg
         exit 0
      else
         while true
         do
            if mt -f $DEVFILE status 2>&1 | grep "no tape loaded" > /dev/null ; then
                user_msg
                exit 0
            else
		form=`gettext "Please remove the tape from the %s."`
		if [ "$silent" != "y" ] ; then
                	printf "${form}\n" $DEVICE  >/dev/tty
                	/usr/5bin/echo \\007 >/dev/tty
		fi
                sleep 3
            fi
         done
      fi;;
   1)

   # only one error mesage is satisfactory

      if echo $x | grep "no tape loaded" > /dev/null ; then
         user_msg
         exit 0
      else
         e_user_msg
         mk_error $DEVICE
         exit 1
      fi;;

   2)

   # clean up failed exit with error

      e_user_msg
      mk_error $DEVICE
      exit 1;;

   esac
fi
exit 2
