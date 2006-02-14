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
#
# Makes the local machine a firewall
#
# Assumption: this is run at the high level of security. Other
# ASET tasks are making sure that there is no + in /etc/hosts.equiv
# and no /.rhosts files.
# 
# This script does 2 things:
#
# 1) Turn the kernel variable 'ip_forwarding' off, thereby ensuring
#    that the firewall will not pass on IP packets.
#
# 2) Ensure in.routed is started with -q flag. This prevents routing info
#    from being visible.  This could be done by editing /etc/rc.local.
#    But it could be error-prone. What we will do is:
#
#    - Move /usr/etc/in.routed to /usr/etc/in.routed.asetoriginal
#    - Create a script in the name of /usr/etc/in.routed that turns around
#      and calls /usr/etc/in.routed.asetoriginal with -q flag.

ADB="/bin/adb"
ROUTED="/usr/sbin/in.routed"
RC2INET="/etc/rc2.d/S69inet"

echo
echo "*** Begin Firewall Task ***"

if [ "$PREV_ASETSECLEVEL" = "high" -a "$DOWNGRADE" = "true" ]
then
   $ASETDIR/tasks/firewall.restore
   exit $?
fi

if [ "$ASETSECLEVEL" != "high" ]
then
   echo
   echo "Task skipped for security levels other than high."
   exit 0
fi

if [ $UID -ne 0 ]
then
   echo
   echo "You are not authorized to convert the machine to be a firewall."
   exit 1
fi

# old value of ip_forwarding
oldvalue=`ndd -get /dev/ip ip_forwarding`

oldvalue=`echo $oldvalue`

case $oldvalue in
   0 | 1 | 2 )
      # valid value
      ;;
   *)
      echo
      echo "Invalid old ip_forwarding value $oldvalue! Task skipped!"
      exit 1
      ;;
esac

done_already=false
if [ "$oldvalue" = "0" ]
then
   echo
   echo "IP forwarding already disabled."
   done_already=true
else
   ndd -set /dev/ip ip_forwarding 0
# ndd bug# 1185290 - ndd always indicates failure when setting a network entry
#   if [ $? -ne 0 ]
#   then
#     echo
#     echo "Could not change IP forwarding"
#     exit 1
#  fi
   echo
   echo "Disabled IP forwarding."
fi
if [ -f ${RC2INET}.asetoriginal ]
then
   echo
   echo "IP forwarding already disabled in rc files."
else
   $MV $RC2INET ${RC2INET}.asetoriginal
   $CP ${RC2INET}.asetoriginal $RC2INET
   /bin/chmod 0744 $RC2INET
   /bin/chown root $RC2INET
   /bin/chgrp sys  $RC2INET
   $ED - /etc/rc2.d/S69inet <<- !
       g/^[ 	]*ndd.*ip_forwarding[ 	][ 	]*1/s/^/#/
       w
       q
!
   echo
   echo "Saved ${RC2INET} to ${RC2INET}.asetorignal;"
   echo "Turned off IP forwarding in ${RC2INET} ."
fi

if [ -f ${ROUTED}.asetoriginal ]
then
   echo
   echo "ROUTED daemon already configured to be opaque."
else
   $MV $ROUTED ${ROUTED}.asetoriginal
   if [ $? -ne 0 ]
   then
      echo
      echo "Could not rename ${ROUTED}."
      exit 1
   fi
#  echo
   echo "#!/bin/sh" > ${ROUTED}
   if [ $? -ne 0 ]
   then
      echo
      echo "Could not create new ${ROUTED} script."
      exit 1
   fi
   echo "${ROUTED}.asetoriginal -q \$*" >> ${ROUTED}
   /bin/chmod 0755 ${ROUTED}
   if [ $? -ne 0 ]
   then
      echo
      echo "Could not chmod new ${ROUTED} script."
      exit 1
   fi
   echo
   echo "Renamed ${ROUTED} to ${ROUTED}.asetorignal;"
   echo "Installed new ${ROUTED} script."
fi

echo $oldvalue > ${ASETDIR}/archives/ipforwarding.arch

echo
echo "*** End Firewall Task ***"
