#!/bin/ksh
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
# Copyright 1990-2002 Sun Microsystems, Inc.  All Rights Reserved.
#
#
#ident	"%Z%%M%	%I%	%E% SMI"

# sysconf - performs checks (and fixes) on various system configuration
#           files (tables). See the ### MAIN ### section (at the end of
#           this file) for a list of the system files examined.

SU=false
if [ $UID -eq 0 ]
then
   SU=true
fi

########## FUNCTIONS ##########

archive()
# usage: archive [-perm] pathname_to_be_archived
# if -perm, saves the permission instead of the content of file
{
   if [ "$DOWNGRADE" = "true" ]
   then
      return # no op
   fi

   if [ "$1" = "-perm" ]
   then
      change_perm=true
      shift
   fi
   pathname=$1
   filename=`expr $pathname : ".*/\(.*\)" \| $pathname`

   if [ ! -s $pathname ]
   then
      # no file to archive
      return
   fi

   if [ "$change_perm" = "true" ]
   then
      arch=$ASETDIR/archives/sysconf.arch.$PREV_ASETSECLEVEL
      $FILE_ATTR $pathname >> $arch
   else
      arch=$ASETDIR/archives/$filename.arch.$PREV_ASETSECLEVEL
      $CP $pathname $arch
   fi

   if [ $? -ne 0 ]
   then
      echo;echo "Cannot archive $pathname. Task skipped!"
      exit 1
   fi
}
   
fix_default_login()
{
   etc_default_login=/etc/default/login

   if [ "$ASETSECLEVEL" = "low" ]
   then
      return
   fi

   archive $etc_default_login

   $GREP -s "^CONSOLE=" $etc_default_login > /dev/null 2>&1
   if [ $? -ne 0 ]
   then
      echo "Warning! Root login allowed at any terminal."
      if [ "$SU" != "true" ]
      then
	 echo "Ask an authorized administrator to fix this."
      else
	 echo "Changing $etc_default_login to allow root login \c"
         echo "only at the console terminal."
	 $ED - $etc_default_login <<- !
a
CONSOLE=/dev/console
.
w
q
!
      fi
   fi
}
  
fix_hosts_equiv()
{
   etc_hosts_equiv=/etc/hosts.equiv

   if [ ! -s $etc_hosts_equiv ]
   then
      return
   fi

   $GREP -s "^+$" $etc_hosts_equiv > /dev/null 2>&1
   if [ $? -ne 0 ]
   then
      return
   fi

   echo
   echo "Warning! $etc_hosts_equiv constains a line with a single +"
   echo "This makes every known host a trusted host, and is therefore"
   echo "not recommended for system security."

   if [ "$ASETSECLEVEL" = "low" ]
   then
      # good enough
      return
   fi

   if [ "$SU" != "true" ]
   then
      echo
      echo "Ask an authorized administrator to fix this problem."
      return
   fi

        archive $etc_hosts_equiv
      
	$ED - $etc_hosts_equiv <<- !
		g/^+$/d
		w
		q
!
	echo
	echo "Deleted that entry in $etc_hosts_equiv."
   return
}

fix_inetd_entry()
# fix entry in /etc/inetd.conf
{
   ENTRY=$1

   OUT=`$GREP -s "^${ENTRY}" /etc/inetd.conf`
   if [ $? -ne 0 ]
   then 
      return
   fi
   if [ "$2" = "SECURE" ]
   then
	OUT=`echo $OUT | $SED 's/^.*[ 	]\(-s\)[ 	].*/\1/'`
	if [ "$OUT" = "-s" ]
 	then
	      return
	fi
   fi

   if [ -d /tftpboot -a $ENTRY = "tftp" ]
   then
      echo
      echo "Warning! in.tftpd is not started securely in /etc/inetd.conf."
      echo
      if [ "$SU" != "true" ]
      then
	 echo "Ask an authorized administrator to fix this."
	 return
      fi
      $ED - /etc/inetd.conf <<- !
      g/^tftp/s/in\.tftpd/in.tftpd -s \/tftpboot/
      w
      q
!
      echo "Entry fixed: in.tftpd started with -s option in /tftpboot home directory"
      return
   fi

   echo
   echo "Warning! ${ENTRY} has poor authentication mechanism"
   echo "not recommended on a secure system. ($inetd_conf)"
   echo
   if [ "$SU" != "true" ]
   then
	echo "Ask an authorized administrator to fix this."
	return
   fi
   $ED - /etc/inetd.conf <<- !
   g/^${ENTRY}/s/^/#/
   w
   q
!
   # end ED
   echo "Entry fixed. ${ENTRY} entry is commented out."
}

fix_inetd_conf()
{
   inetd_conf=/etc/inetd.conf

   archive $inetd_conf

   fix_inetd_entry tftp SECURE

   if [ "${ASETSECLEVEL}" = "high" ]
   then
      fix_inetd_entry finger 
      fix_inetd_entry systat 
      fix_inetd_entry netstat 
      fix_inetd_entry rusersd 
      fix_inetd_entry rexd SECURE
   fi
}

fix_aliases()
{
   etc_aliases=/etc/aliases

   archive $etc_aliases

   OUT=`$GREP -s "^decode" $etc_aliases 2> /dev/null`
   if [ $? -ne 0 ]
   then
      return
   fi
   OUT=`echo $OUT|$GREP -s "uudecode" 2> /dev/null`
   if [ $? -ne 0 ]
   then
      return
   fi
   echo
   echo "Warning! The uucp decode alias in $etc_aliases is not\c"
   echo " recommended for system security."
   if [ "$ASETSECLEVEL" = "low" ]
   then
      return
   fi
   if [ "$SU" != "true" ]
   then
      echo
      echo "Ask an authorized administrator to fix this."
      return
   fi
   $ED - $etc_aliases <<- !
	g/^decode/s/^decode/#decode/
	w
	q
!
   # end ED
   echo
   echo "Decode alias has been commented out."
}

fix_utmp()
{
   $IS_WRITABLE /var/adm/utmpx
   if [ $? -eq 0 ]
   then
      echo
      echo "Warning! /var/adm/utmpx is writable by world. This is not"
      echo "recommended for system security."
   fi

   $IS_WRITABLE /var/adm/wtmpx
   if [ $? -eq 0 ]
   then
      echo
      echo "Warning! /var/adm/wtmpx is writable by world. This is not"
      echo "recommended for system security."
   fi

   if [ "$ASETSECLEVEL" != "high" ]
   then
      return
   fi

   if [ "$SU" != "true" ]
   then
      echo
      echo "Ask an authorized administrator to fix this."
      return
   fi
   archive -perm /var/adm/utmpx
   archive -perm /var/adm/wtmpx
   $CHMOD o-w /var/adm/utmpx
   $CHMOD o-w /var/adm/wtmpx
   echo
   echo "World writability for /var/adm/utmpx has been removed."
   echo "World writability for /var/adm/wtmpx has been removed."
}

fix_root_rhosts()
{
   if [ -s /.rhosts ]
   then
      echo
      echo "Warning! The use of /.rhosts file is not recommended for\c"
      echo " system security."
      if [ "$ASETSECLEVEL" != "low" ]
      then
         if [ "$SU" != "true" ]
         then
            echo
            echo "Ask an authorized administrator to fix this."
            return
         fi
         archive /.rhosts
	 $MV /.rhosts /.rhosts.asetbak
	 echo
	 echo "Moved aside to /.rhosts.asetbak."
      fi
   fi
}
	    
fix_vfstab()
# Check world-readable/writable devices in vfstab.
{
   vfstab=/etc/vfstab

   devfiles=`$AWK 'index($1, "/")==1 && $1 !="/proc" && $4!="lofs" \
       {print $1}' $vfstab`

   for dev in $devfiles
   do
      if $IS_READABLE $dev
      then
	 echo
	 echo "Warning! $dev is readable by world."
	 if [ "$ASETSECLEVEL" != "low" ]
	 then
	    if [ "$SU" = "true" ]
	    then
	       archive -perm $dev
	       $CHMOD o-r $dev
	       if [ $? -ne 0 ]
	       then
		  echo
		  echo "Had problem fixing $dev"
	       else
		  echo
		  echo "World readability has been removed from $dev."
	       fi
	    else
	       echo
	       echo "Ask an authorized administrator to fix this."
	    fi
	 fi
      fi
      if $IS_WRITABLE $dev
      then
	 echo
	 echo "Warning! $dev is writable by world."
	 if [ "$ASETSECLEVEL" != "low" ]
	 then
	    if [ "$SU" = "true" ]
	    then
	       archive -perm $dev
	       $CHMOD o-w $dev
	       if [ $? -ne 0 ]
	       then
		  echo
		  echo "Had problem fixing $dev"
	       else
		  echo
		  echo "World writability has been removed from $dev."
	       fi
	    else
	       echo
	       echo "Ask an authorized administrator to fix this."
	    fi
	 fi
      fi
   done
}

fix_exports()
# check unrestricted exportation of file systems.
{
   exports=/etc/dfs/dfstab

   if [ -s $exports ]
   then
      $AWK '{ \
	 while(getline >0) \
	    if ($0 !~ /^#/ && $0 !~ /-o/ && $0 != "") { \
	       printf("\nWarning! Shared resources file (/etc/dfs/dfstab) , line %d, file system exported with no restrictions:\n\t%s\n", NR, $0) \
	    } \
      }' ${exports}
   fi
}

fix_ftpusers()
{
   if [ "$ASETSECLEVEL" != "high" ]
   then
      return
   fi

   ftpusers=/etc/ftpd/ftpusers
   $FGREP -s -x root $ftpusers > /dev/null 2>&1
   if [ $? -eq 0 ]
   then
      return
   fi
   echo
   echo "Warning! $ftpusers should contain root at high security level."
   if [ "$SU" = "true" ]
   then
      archive $ftpusers
      echo root >> $ftpusers
      echo
      echo "Root entry has been appended in $ftpusers."
   else
      echo
      echo "Ask an authorized administrator to fix this."
   fi
}

########## MAIN ##########

if [ "$DOWNGRADE" = "true" ]
then
   $ASETDIR/tasks/sysconf.restore
fi

echo
echo "*** Begin System Scripts Check ***"

#echo
#echo "checking /etc/default/login for console root login"
fix_default_login

#echo
#echo "checking hosts.equiv for NIS entry"
fix_hosts_equiv

#echo
#echo "checking inetd_conf for non-secure mode daemons"
fix_inetd_conf

#echo
#echo "checking /etc/aliases for uucp uudecode alias"
fix_aliases

#echo
#echo "checking utmpx/wtmpx permissions"
fix_utmp
	 
#echo
#echo "checking /.rhosts file"
fix_root_rhosts

#echo
#echo "checking mounted partitions permissions"
fix_vfstab

#echo
#echo "checking exported partitions access permissions"
fix_exports

#echo
#echo "checking /etc/ftpusers for root"
fix_ftpusers

echo
echo "*** End System Scripts Check ***"
