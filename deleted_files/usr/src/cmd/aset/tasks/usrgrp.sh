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

# This script performs checking on password and group files and
# reports anything that can be a problem in terms of integrity
# and security.

etc_passwd=/etc/passwd
etc_shadow=/etc/shadow
yp_passwdbuf=${TMP}/yp_passwd.$$
passwdbuf=${TMP}/passwdbuf.$$

etc_group=/etc/group
yp_groupbuf=${TMP}/yp_group.$$
groupbuf=${TMP}/groupbuf.$$

########## FUNCTIONS ##########

archive()
{
   passwd_arch=${ASETDIR}/archives/passwd.arch.$PREV_ASETSECLEVEL
   group_arch=${ASETDIR}/archives/group.arch.$PREV_ASETSECLEVEL
   shadow_arch=${ASETDIR}/archives/shadow.arch.$PREV_ASETSECLEVEL

   $CP $etc_passwd $passwd_arch
   if [ $? -ne 0 ]
   then
      echo
      echo "Warning! Could not archive $etc_passwd to $passwd_arch."
      return 1
   fi

   $CP $etc_group $group_arch
   if [ $? -ne 0 ]
   then
      echo
      echo "Warning! Could not archive $etc_group to $group_arch."
      return 1
   fi

   $CP $etc_shadow $shadow_arch
   if [ $? -ne 0 ]
   then
      echo
      echo "Warning! Could not archive $etc_shadow to $shadow_arch."
      return 1
   fi

   return 0
}

check_dup_id()
# check duplicate user id's in password file;
# report them unless allowed by UID_ALIASES file.
# usage: check_dup_id passwd_file
{
   nouidalias=false
   if [ "$UID_ALIASES" = "" ]
   then
      nouidalias=true
   elif [ ! -s $UID_ALIASES ]
   then
      nouidalias=true
   fi

   $AWK -F: '{print $3, $1}' $1 | $SORT > ${TMP}/pwsort.$$
   $AWK '{print $1}' ${TMP}/pwsort.$$ | $UNIQ -d > ${TMP}/dupuids.$$

   while read uid uname
   do
      if fgrep -x -e $uid ${TMP}/dupuids.$$ > /dev/null
      then
	 if [ "$nouidalias" = "true" ]
	 then
	    echo
	    echo "Warning! Duplicate uid: $uid $uname"
	 else
            result=`$AWK -F= '($1==uid) { \
	       for (i=2; i<=NF; i++) { \
		    if ($i==uname) { \
		       print uname; \
                       break; \
		    } \
	       } \
	    }' uid=$uid uname=$uname $UID_ALIASES`
            if [ "$result" = "" ]
            then
	       echo
	       echo "Warning! Duplicate uid: $uid $uname"
            fi
	 fi
      fi
   done < ${TMP}/pwsort.$$
   $RM -f ${TMP}/pwsort.$$ ${TMP}/dupuids.$$
}

do_passwd()
# Check on the password file passed in.
# -f flag: fix where possible.
# Usage: do_passwd [-f] passwd_file
{
   if [ "$1" = "-f" ]
   then
      should_fix=true
      passwd_file=$2
   else
      should_fix=false
      passwd_file=$1
   fi

   echo
   echo "Checking $passwd_file ..."

   # check duplicate user names
   result=`$AWK -F: '{print $1}' $passwd_file | $SORT | $UNIQ -d`
   if [ "$result" ]
   then
      echo
      echo "Warning!  Duplicate user name(s) found in $passwd_file:"
      echo "\t$result"
   fi

   # check duplicate user ids
   check_dup_id $passwd_file

   # other format checks
   $AWK -f ${ASETDIR}/tasks/pwchk.awk $passwd_file

   # check nobody entry
   if $GREP -s '^nobody:.*:-2' $passwd_file
   then
      echo
      echo "Bad entry for user nobody in $passwd_file\c"
      echo " - has value -2 for uid/gid"
      if [ "$should_fix" = "true" ]
      then
         $AWK -F: '{ \
	    if ($1=="nobody" && ($3=="-2" || $4=="-2")) { \
               printf("%s:*:66534:66534:disable:", $1); \
               printf("/disable:/disable\n") \
            } else { \
               print $0; \
            } \
	 }' $passwd_file > $passwdbuf
         if $CP $passwdbuf $passwd_file
         then
            echo 
            echo "Entry repaired."
         else
            echo
            echo "Repair attempted but failed."
         fi
      fi
   fi

   # Check ypclient line (+...)
   if [ "$passwd_file" = "/etc/passwd" ]
   then
      # if this is an NIS server, check passwd file for ypclient line.
      if $PS -edf | $GREP ypserv | $GREP -s -v  grep
      then
	 if $GREP -s "^+:" $passwd_file
	 then
            echo
            echo "Warning! This machine is an NIS server; it should\c"
            echo " not have the client line (+...) in $passwd_file."
	    if [ "$should_fix" = "true" ]
	    then
               if [ "${ASETSECLEVEL}" = "med" -o \
                  "${ASETSECLEVEL}" = "high" ]
               then
                  $AWK -F":" '{if ($1!="+") print $0}' \
                     $passwd_file > $passwdbuf
                  $CP $passwdbuf $passwd_file
                  if [ "$?" = "0" ]
                  then
                     echo 
                     echo "Client line(s) deleted."
                  else
                     echo
                     echo "Deletion attempted but failed."
                  fi
               fi
            fi
	 fi
      fi
   fi
} # end do_passwd()

do_group()
# Check on the group file passed in.
# -f flag: fix where possible.
# Usage: do_group [-f] group_file
{
   if [ "$1" = "-f" ]
   then
      should_fix=true
      group_file=$2
   else
      should_fix=false
      group_file=$1
   fi

   echo
   echo "Checking $group_file ..."

   # check duplicate group names
   result=`$AWK -F: '{print $1}' $group_file | $SORT | $UNIQ -d`
   if test "$result"
   then
      echo
      echo "Warning!  Duplicate group names(s) found in $group_file:"
      echo "\t$result"
   fi

   # check duplicate group ids
   result=`$AWK -F: '{print $3}' $group_file | $SORT | $UNIQ -d`
   if test "$result"
   then
      echo
      echo "Warning!  Duplicate group id(s) found in $group_file:"
      echo "\t$result"
   fi

   # other format checks
   $AWK -f ${ASETDIR}/tasks/gpchk.awk $group_file

   # check nogroup entry
   if $GREP -s '^nogroup:.*:-2' $group_file
   then
      echo
      echo "Bad entry for group nogroup in $group_file\c"
      echo " - has value -2 for gid"
      if [ "$should_fix" = "true" ]
      then
         $AWK -F: '{ \
	    if ($1=="nogroup" && $3=="-2") { \
               printf("%s:*:66534:\n", $1); \
            } else { \
               print $0; \
            } \
	 }' $group_file > $groupbuf
         if $CP $groupbuf $group_file
         then
            echo 
            echo "Entry repaired."
         else
            echo
            echo "Repair attempted but failed."
         fi
      fi
   fi

   # Check ypclient line (+...)
   if [ "$group_file" = "/etc/group" ]
   then
      # if this is an NIS server, check group file for ypclient line.
      if $PS -edf | $GREP ypserv | $GREP -s -v  grep
      then
	 if $GREP -s "^+:" $group_file
	 then
            echo
            echo "Warning! This machine is an NIS server; it should\c"
            echo " not have the client line (+...) in $group_file."
	    if [ "$should_fix" = "true" ]
	    then
               if test "${ASETSECLEVEL}" = "med" -o \
                  "${ASETSECLEVEL}" = "high"
               then
                  $AWK -F":" '{if ($1!="+") print $0}' \
                     $group_file > $groupbuf
                  $CP $groupbuf $group_file
                  if test "$?" = "0"
                  then
                     echo 
                     echo "Client line(s) deleted."
                  else
                     echo
                     echo "Deletion attempted but failed."
                  fi
               fi
            fi
         fi
      fi
   fi
} # end do_group()

########## MAIN ##########

if [ $UID -ne 0 ]
then
   echo
   echo "Permission denied. Task skipped."
   exit
fi

if [ "$DOWNGRADE" = "true" ]
then
   $ASETDIR/tasks/usrgrp.restore
else   
   # Archive the password and group file so we can restore if necessary
   archive
   if [ $? -ne 0 ]
   then
      echo
      echo "Cannot archive password and group files. Task skipped."
      exit
   fi
fi

echo
echo "*** Begin User And Group Checking ***"

do_passwd -f $etc_passwd	# -f = fix whenever possible

if [ "${YPCHECK:-true}" = "true" ]
then
   $YPCAT passwd > $yp_passwdbuf
   if [ -s $yp_passwdbuf ]
   then
      do_passwd $yp_passwdbuf
   fi
fi

echo
echo "Checking $etc_shadow ..."
# check passwd shadow file
$AWK -f ${ASETDIR}/tasks/swchk.awk $etc_shadow

$RM -f $passwdbuf
$RM -f $yp_passwdbuf

echo
echo "... end user check."

do_group -f $etc_group	# -f = fix whenever possible

if [ "${YPCHECK:-true}" = "true" ]
then
   $YPCAT group > $yp_groupbuf
   if [ -s $yp_groupbuf ]
   then
      do_group $yp_groupbuf
   fi
fi

echo
echo "... end group check."

$RM -f $groupbuf
$RM -f $yp_groupbuf

echo
echo "*** End User And Group Checking ***"
