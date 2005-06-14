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
#   Tune attributes on system object 
#
#   This script is intended to set system object attributes
#   to values more appropriate for security-conscious environments.
#
#   -p : preview flag

archive=${ASETDIR}/archives/tune.arch.$PREV_ASETSECLEVEL

mychmod()
{
   tmode=$1
   file=$2
   sbits=`expr $tmode : ".*\(.\)..."`
   sgbit=0
   if [ "$sbits" != "" ]
   then
      sticky=`expr $sbits % 2`
      sbits=`expr $sbits / 2`
      sgbit=`expr $sbits % 2`
      subit=`expr $sbits / 2`
      if [ $sgbit -eq 1 -a $subit -eq 1 ]
      then
         return 1
      fi
   fi
   $CHMOD $tmode $file
   if [ -d $file -a $sgbit -eq 1 ]
   then
      $CHMOD g+s $file
   fi
   return 0
}

echo
echo "*** Begin Tune Task ***"

if [ $UID -ne 0 ]
then
   echo
   echo "You are not authorized to change system object attributes."
   echo "Task Skipped!"
   exit
fi

if [ $# -gt 0 -a "$1" = "-p" ]
then
   echo
   echo "... just previewing - objects attributes not changed"
   echo
   CHMOD="echo chmod"
   CHOWN="echo chown"
   CHGRP="echo chgrp"
fi

if [ "$DOWNGRADE" = "true" ]
then
   $ASETDIR/tasks/tune.restore
#   exit $?
fi

echo
echo "... setting attributes on the system objects defined in"
echo "    ${ASETDIR}/masters/tune.${ASETSECLEVEL}"    

if [ "$PREV_ASETSECLEVEL" != "$ASETSECLEVEL" ]
then
   # we know we are not downgrading, so we must be upgrading.
   need_archive="true"
   echo "# This file contains original settings of files or" > $archive
   echo "# directories that have been changed by ASET." >> $archive
   echo >> $archive
else
   need_archive="false"
fi

if [ ! -s ${ASETDIR}/masters/tune.${ASETSECLEVEL} ]
then
   echo
   echo "tune.task: master file not found: \c"
   echo "${ASETDIR}/masters/tune.${ASETSECLEVEL}"
   exit
fi

while read path mode user group type junk
do
   #   Skip comments and white lines
   if [ "$path" = "#" ]
   then
      continue;
   elif [ "$path" = "" ]
   then
      continue;
   fi

   # Warn and skip lines without all the required fields
   if [ "$type" = "" ]
   then
      echo
      echo "Warning: bad entry:"
      echo "$path $mode $user $group $type"
      continue;
   fi

   # Warn and skip lines with too many fields
   if [ "$junk" != "" ]
   then
      echo
      echo "Warning: bad entry:"
      echo "$path $mode $user $group $type $junk"
      continue;
   fi

   for file in $path
   do
      #
      #   If the object does not exist on this system then skip it.
      #
      if [ ! -d "$file" -a ! -f "$file" ]
      then
         continue;
      fi

      #   If a "?" is found in the mode, user, group field, that
      #   field is treated as a don't-care and ignored.
      #
      #   If the object is a symbolic link then do not chmod(1) it.
      #
      old_attr=`$FILE_ATTR $file`
      changed=false
      if [ "$type" != "symlink" -a "$mode" != "?" ]
      then
         newmode=`$MINMODE $file $mode`
         if [ $? -eq 0 ]
         then
            if mychmod "$newmode" "$file"
	    then
	       changed=true
	    fi
	 fi
      fi
      if [ "$user" != "?" -a \
           "$user" != `echo $old_attr | $AWK '{print $3}'` ]
      then
         $CHOWN "$user" "$file"
	 changed=true
      fi
      if [ "$group" != "?" -a \
	   "$group" != `echo $old_attr | $AWK '{print $4}'` ]
      then
         $CHGRP "$group" "$file"
	 changed=true
      fi
      if [ "$need_archive" = "true" -a "$changed" = "true" ]
      then
	 echo $file $old_attr >> $archive
      fi
   done # for loop
done < ${ASETDIR}/masters/tune.${ASETSECLEVEL} # while loop

echo
echo "*** End Tune Task ***"
