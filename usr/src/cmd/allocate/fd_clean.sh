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
#  This a clean script for the floppy drive
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
	printf "${form}\n" $PROG $DEVICE > /dev/tty
	gettext "Please inform system administrator.\n" > /dev/tty
    fi
}

mk_error() {
   chown bin /etc/security/dev/$1
   chmod 0100 /etc/security/dev/$1
}

#
# 		*** Begin main program ***
#

silent=n

# Parse the argumnets

while getopts Iifs c
do
   case $c in
   I)	FLAG=i
	silent=y;;
   i)   FLAG=$c;;
   f)   FLAG=$c;;
   s)   FLAG=$c;;
   \?)   printf "${USAGE}\n" $PROG
      exit 1 ;;
   esac
done
shift `expr $OPTIND - 1`

# get the map information

FLOPPY=$1
MAP=`dminfo -v -n $FLOPPY`
DEVICE=`echo $MAP | cut -f1 -d:`
TYPE=`echo $MAP | cut -f2 -d:`
FILES=`echo $MAP | cut -f3 -d:`
DEVFILE=`echo $FILES | cut -f1 -d" "`

#if init then do once and exit

lform=`gettext "%s error: %s."`

if [ "$FLAG" = "i" ] ; then
   x="`eject -q $DEVFILE 2>&1`"		# Determine if there is media in drive
   z="$?"   

   case $z in
   0) 					# Media is in the drive.
	a="`eject -f $DEVFILE 2>&1`"
	b="$?"

	case $b in
	0)				# Media has been ejected 
		con_msg
		exit 0;;
	1)				# Media not ejected
		mk_error $DEVICE
		if [ "$silent" != "y" ] ; then
			printf "${lform}\n" $PROG $a >/dev/tty
		fi
		e_con_msg
		exit 1;;
	2)			# Error 
		mk_error $DEVICE
		if [ "$silent" != "y" ] ; then
			printf "${lform}\n" $PROG $a >/dev/tty
		fi
		e_con_msg
		exit 1;;
	3)			# Error - Perhaps drive doesn't support ejection
		mk_error $DEVICE
		if [ "$silent" != "y" ] ; then
			printf "${lform}\n" $PROG $a >/dev/tty
		fi
		e_con_msg
		exit 1;;
	esac;;
   1) 		# No media in drive
	con_msg
	exit 0;;	
   2)			# Error 
		mk_error $DEVICE
		if [ "$silent" != "y" ] ; then
			printf "${lform}\n" $PROG $x >/dev/tty
		fi
		e_con_msg
		exit 1;;
   3)			# Error 
		mk_error $DEVICE
		if [ "$silent" != "y" ] ; then
			printf "${lform}\n" $PROG $x >/dev/tty
		fi
		e_con_msg
		exit 1;;
   esac
else
# interactive clean up
   x="`eject -q $DEVFILE 2>&1`"		# Determine if there is media in drive
   z="$?"   

   case $z in
   0)					# Media is in the drive.
	a="`eject -f $DEVFILE 2>&1`"
	b="$?"
	case $b in
	0)				# Media has been ejected
		user_msg
		exit 0;;
	1)				# Media didn't eject
         	mk_error $DEVICE
		if [ "$silent" != "y" ] ; then
			printf "${lform}\n" $PROG $a >/dev/tty
		fi
         	e_user_msg
         	exit 1;;
	2)				# Other Error 
		mk_error $DEVICE
		if [ "$silent" != "y" ] ; then
			printf "${lform}\n" $PROG $a >/dev/tty
		fi
		e_user_msg
         	exit 1;;
	3)				
	
		if echo $a | grep "failed" >/dev/null ; then
         	while true 		# Drive doesn't support eject, so loop	
         	    do
			c="`eject -q $DEVFILE 2>&1`"	# Is floppy in drive?
			d="$?"
            		if [ $d -eq 0 ] ; then		# Yes, Floppy in drive
				form=`gettext "Please remove the floppy from %s."`
				if [ "$silent" != "y" ] ; then
               				printf "${form}\n" $DEVICE >/dev/tty
					/usr/5bin/echo \\007 > /dev/tty
				fi
               			sleep 3
            		elif echo $c | grep "NOT" > /dev/null ; then
							# No,Floppy NOT in drive
               			user_msg
               			exit 0
			else				# Error occurred
         			mk_error $DEVICE
				if [ "$silent" != "y" ] ; then
					printf "${lform}\n" $PROG $a >/dev/tty
				fi
				e_user_msg
         			exit 1
            		fi
         	    done
		else 					# Some other failure
			if [ "$silent" != "y" ] ; then
				printf "${lform}\n" $PROG $a >/dev/tty
			fi
         		e_user_msg
         		mk_error $DEVICE
         		exit 1
		fi;;
			
	esac;;
   1)							# No media in the drive
         user_msg
         exit 0;;
   2)
       	mk_error $DEVICE
	if [ "$silent" != "y" ] ; then
		printf "${lform}\n" $PROG $x >/dev/tty
	fi
	e_user_msg
       	exit 1;;
   3)
       	mk_error $DEVICE
	if [ "$silent" != "y" ] ; then
		printf "${lform}\n" $PROG $x >/dev/tty
	fi
	e_user_msg
       	exit 1;;
   esac
fi
exit 2
