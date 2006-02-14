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
#

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

not_lower()
# usage: not_lower level1 level2
# return: 0 if level1 is not lower than level2 (higher or equal)
#         1 if lower
{
   level1=$1
   level2=$2
   case $level1 in
   null)
      if [ "$level2" = "null" ]
      then
         return 0
      fi;;
   low)
      if [ "$level2" = "null" -o "$level2" = "low" ]
      then
	 return 0
      fi;;
   med)
      if [ "$level2" != "high" ]
      then
	 return 0
      fi;;
   high)
      return 0;;
   esac
   return 1
}

between_levels()
# usage: between_levels level1 level2
# prints all the levels in between (inclusively) level1 and level2
# from the highest down.
# level1 is assumed to be not lower than level2.
{
   level1=$1
   level2=$2
   if not_lower $level1 $level2
   then
      l=$level1
      echo "$l \c"
      while [ "$l" != "$level2" ]
      do
         case $l in
         high)   l=med;;
         med)    l=low;;
         low)    l=null;;
         esac
         echo "$l \c"
      done
      echo
   fi
}

restore()
# usage: restore file_whose_content_is_to_be_restored
{
   pathname=$1
   filename=`expr $pathname : ".*/\(.*\)" \| $pathname`

   # Restore file contents from filename.arch.$ASETSECLEVEL files
   # Note that there may be more than one of these. We must be careful
   # to pick up all the changes from level to level.
   # We use the -t option of ls to weed out the ones that are bogus.
   arch_files=""
   for i in $LEVELS
   do
      arch_files="$ASETDIR/archives/$filename.arch.$i $arch_files"
   done
   arch_files=`/bin/ls -t $arch_files 2> /dev/null`
   lowest_arch=""
   for arch in $arch_files
   do
      level=`expr $arch  :  ".*\.\(.*\)$"`
      if not_lower $level $ASETSECLEVEL
      then
         lowest_arch=$arch
      else
         # we only care about arch files down to the downgrade target.
         # if other files exist and are older, they are bogus
         break
      fi
   done
   if [ "$lowest_arch" != "" ]
   then
      doit /bin/cp $pathname $pathname.asetbak
      if [ $? = 0 ]
      then
         echo;echo "Restoring $pathname. Saved existing file in $pathname.asetbak."
      fi
      doit /bin/cp $arch $pathname
   fi
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

LEVELS=`between_levels $PREV_ASETSECLEVEL $ASETSECLEVEL`
export LEVELS

# restore file contents
for file in /etc/hosts.equiv /etc/inetd.conf \
            /etc/aliases /.rhosts
do
   restore $file
done

# Restore file contents from sysconf.arch.$ASETSECLEVEL files
# Note that there may be more than one of these. We must be careful
# to pick up all the changes from level to level.
# We use the -t option of ls to weed out the ones that are bogus.
arch_files=""
for i in $LEVELS
do
   arch_files="$ASETDIR/archives/sysconf.arch.$i $arch_files"
done
arch_files=`/bin/ls -t $arch_files 2> /dev/null`
for arch in $arch_files
do
   level=`expr  $arch  :  ".*\.\(.*\)$"`
   if not_lower $level $ASETSECLEVEL
   then
      while read pathname orig_perm other_stuff
      do
         doit /bin/chmod $orig_perm $pathname
      done < $arch
   else
      # we only care about arch files down to the downgrade target.
      # if other files exist and are older, they are bogus
      break
   fi
done

echo
echo "$myname completed."
