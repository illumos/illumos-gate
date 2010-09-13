#!/bin/sh --
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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

# Check :include: aliases (in files configured in sendmail.cf) and .forward
# files to make sure the files and their parent directory paths all have
# proper permissions.  And check the master alias file(s) too.
#
# See http://www.sendmail.org/vendor/sun/migration.html#Security for details.
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# %W% (Sun) %G%
# ident	"%Z%%M%	%I%	%E% SMI"

PATH=/bin

# Check the group- and world-writable bits on the given file.

analyze() {
	case "`ls -Lldn $1`" in
		?????w??w?*) 
			echo $2: $1 is group and world writable
			bogus_dirs=true ;;
		????????w?*) 
			echo $2: $1 is world writable
			bogus_dirs=true ;;
		?????w????*) 
			echo $2: $1 is group writable
			bogus_dirs=true ;;
	esac
}

# Break down the given file name into its components, and call analyze with
# each of them.  E.g., an argument of /usr/local/aliases/foo.list would call
# analyze in turn with arguments:
# * /usr/local/aliases/foo.list
# * /usr/local/aliases
# * /usr/local
# * /usr

break_down() {
	for j in `echo $1 | \
		awk '{
			n = split($0, parts, "/");
			for (i = n; i >= 2; i--){
				string = "";
				for (j = 2; j <= i; j++){
					string = sprintf("%s/%s", string, parts[j]);
				}
				print string
			}
		}'` "/"
	do
		analyze $j $1
	done
}

config=/etc/mail/sendmail.cf
bogus_dirs=false

afl1=`grep "^OA" $config | sed 's/^OA//' | sed 's/,/ /g' | sed 's/.*://'`
afl2=`grep "^O AliasFile=" $config | sed 's/^O AliasFile=//' | \
    sed 's/,/ /g' | sed 's/.*://'`

# These should be OK themselves, but other packages may have screwed up the
# permissions on /etc or /etc/mail .  And best to check in case non-standard
# alias paths are used.

break_down $afl1 $afl2

# Find all valid :include: files used in alias files configured in sendmail.cf

for i in `sed 's/^[#].*$//' $afl1 $afl2 | \
	grep :include: | \
	sed 's/.*:include://' | \
	sed 's/,.*$//'`
do
	break_down $i
done

# Check .forward files as well.  If the argument "ALL" is given, do it for
# everyone.  If no argument to the script is given, just do it for the current
# user.  O/w, do it for all arguments.

if [ $# -eq 0 ] ; then
	arg=`id | nawk -F'(' '{n = split($2,id,")"); print id[1]}'`
elif [ $1 = "ALL" ] ; then
	arg=""
else
	arg="$*"
fi

for i in `getent passwd $arg | nawk -F: '{print $6}'`
do
	if [ -f $i/.forward ] ; then
		break_down $i/.forward
	fi
done

$bogus_dirs || echo "No unsafe directories found."
