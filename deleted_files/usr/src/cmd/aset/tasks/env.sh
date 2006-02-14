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
# Copyright 1990-2002 Sun Microsystems, Inc.  All Rights Reserved.
#
#
#ident	"%Z%%M%	%I%	%E% SMI"

CHOWN="/usr/bin/chown"
CHMOD="/usr/bin/chmod"
MKDIR="/usr/bin/mkdir"
dot_cshrc=".cshrc"
dot_profile=".profile"
dot_login=".login"
root_env="/$dot_cshrc /$dot_profile /$dot_login /etc/profile"
tmp=/tmp/aset.$$
tmpenv=$tmp/tmpenv
tmppath=$tmp/tmppath
tmpstatus=$tmp/tmpstatus

########## FUNCTIONS ##########

check_umask()
{
	for i in $root_env
	do
		if [ -s $i ]; then
			umask=`$GREP umask $i 2>/dev/null`
			if [ $? -eq 0 ]; then
 				mask=`echo $umask | $AWK '{ \
					if ($2 != "") { \
						if (length($2) == 1) \
							print "00"$2; \
						else if (length($2) == 2) \
							print "0"$2; \
						else \
							print $2; \
					} else
						print "000";
				}'`
				perm=`echo $mask | $SED 's/..\(.\).*/\1/'`
				if [ "$perm" -lt 6 ]; then
					if [ "$umask" ]; then
						echo
						echo "Warning! umask set to $umask in $i - not recommended."
					fi
				fi
			fi
		fi
	done
} # end check_umask


check_file()
{
	infile=$1

	> $tmpstatus
	$CHMOD 600 $tmpstatus

	$SED -n -e 's/^.*\(::\).*/\1/p' $tmppath >> $tmpstatus
	$SED -n -e 's/^.*\(:\.:\).*/\1/p' $tmppath >> $tmpstatus
	$SED -n -e 's/^.*\(=:\).*/\1/p' $tmppath >> $tmpstatus
	$SED -n -e 's/^.*\(:\.\)$/\1/p' $tmppath >> $tmpstatus
	$SED -n -e 's/^\(\.:\).*/\1/p' $tmppath >> $tmpstatus

	case $infile in */$dot_profile)
		$SED -n -e 's/^\(:\).*/\1/p' $tmppath >> $tmpstatus
		$SED -n -e 's/^.*\(:\)$/\1/p' $tmppath >> $tmpstatus
	;; esac

	if [ -s $tmpstatus ]; then
		echo
		echo "Warning! \".\" is in path variable!"
		echo "         Check $infile file."
	fi

	for i in `$SED 's/:/ /g' $tmppath`
	do
		echo $i
	done | $SORT -u |
	while read i
	do
		if [ -d $i -a "$i" != "." ]; then
			if $IS_WRITABLE $i
			then
				echo
				echo "Warning! Directory $i is world writable!"
				echo "         Should not be in path variable."
				echo "         Check $infile file."
			fi
		fi
	done

	$RM -f $tmpstatus
} # end check_file


check_path()
#
# Usage: check_path users
# Root is always checked.
#
{
	$RM -rf $tmp
	$MKDIR -m 755 $tmp
	if [ $? -ne 0 ]; then
		exit 1
	fi
	trap "$RM -rf $tmp" 0

	for user in root $*
	do
		home=`echo $user | $HOMEDIR`
		if [ "$home" = "NONE" ]; then
			continue
		fi

		# note: execute . files as 'user', not as root

		cshrc=`echo "${home}/.cshrc" | $SED 's/\/\//\//g'`
		profile=`echo "${home}/.profile" | $SED 's/\/\//\//g'`
		login=`echo "${home}/.login" | $SED 's/\/\//\//g'`

		# check .cshrc
		if [ -r $cshrc ]; then
			echo "#!/bin/csh" > $tmpenv
			$CHMOD 644 $tmpenv
			echo "set home = $home" >> $tmpenv
			echo "set path = /usr/bin" >> $tmpenv
			echo "source $cshrc" >> $tmpenv
			> $tmppath
			$CHMOD 644 $tmppath
			$CHOWN $user $tmppath
			echo "echo \$PATH >> $tmppath" >> $tmpenv
			/bin/su $user -c "/bin/csh $tmpenv" > /dev/null 2>&1
			check_file $cshrc
			$RM -f $tmpenv $tmppath
		fi

		# check .login
		if [ -r $login ]; then
			echo "#!/bin/csh" > $tmpenv
			$CHMOD 644 $tmpenv
			echo "set home = $home" >> $tmpenv
			echo "set path = /usr/bin" >> $tmpenv
			echo "source $login" >> $tmpenv
			> $tmppath
			$CHMOD 644 $tmppath
			$CHOWN $user $tmppath
			echo "echo \$PATH >> $tmppath" >> $tmpenv
			/bin/su $user -c "/bin/csh $tmpenv" > /dev/null 2>&1
			check_file $login
			$RM -f $tmpenv $tmppath
		fi

		# check .profile
		if [ -r $profile ]; then
			echo "#!/bin/sh" > $tmpenv
			$CHMOD 644 $tmpenv
			echo "HOME=$home; export HOME" >> $tmpenv
			echo "PATH=/usr/bin; export PATH" >> $tmpenv
			echo ". $profile" >> $tmpenv
			> $tmppath
			$CHMOD 644 $tmppath
			$CHOWN $user $tmppath
			echo "echo \$PATH >> $tmppath" >> $tmpenv
			/bin/su $user -c "/bin/sh $tmpenv" > /dev/null 2>&1
			check_file $profile
			$RM -f $tmpenv $tmppath
		fi
  	done # for user
} # end check_path


########## MAIN ##########

echo
echo "*** Begin Enviroment Check ***"

# relocate to / so that csh can stat .
cd /

check_umask

if [ "$CHECK_USERS" != "" ]
then
   check_path `$CAT $CHECK_USERS`
else
   check_path
fi

echo
echo "*** End Enviroment Check ***"
