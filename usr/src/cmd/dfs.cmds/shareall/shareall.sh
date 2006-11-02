#!/sbin/sh
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
#	Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
#	Use is subject to license terms.


#ident	"%Z%%M%	%I%	%E% SMI"
# shareall  -- share resources

USAGE="shareall [-F fsys[,fsys...]] [- | file]"
fsys=
set -- `getopt F: $*`
if [ $? != 0 ]		# invalid options
	then
	echo $USAGE >&2
	exit 1
fi
for i in $*		# pick up the options
do
	case $i in
	-F)  fsys=$2; shift 2;;
	--)  shift; break;;
	esac
done

if [ $# -gt 1 ]		# accept only one argument
then
	echo $USAGE >&2
	exit 1
elif [ $# = 1 ]
then
	case $1 in
	-)	infile=;;	# use stdin
	*)	infile=$1;;	# use a given source file
	esac
else
	infile=/etc/dfs/dfstab	# default
fi


if [ "$fsys" ]		# for each file system ...
then
	if [ "$infile" = "/etc/dfs/dfstab" ]
	then
	    /usr/sbin/sharemgr start -P $fsys -a
	else
	    while read line				# get complete lines
	    do
		echo $line
	    done < $infile |

	    `egrep "^[^#]*[ 	][ 	]*-F[ 	]*(\`echo $fsys|tr ',' '|'\`)" |
	    /sbin/sh`

	    fsys_file=/etc/dfs/fstypes
	    if [ -f $fsys_file ]    		# get default file system type
	    then
		def_fs=`egrep '^[^#]' $fsys_file | awk '{print $1; exit}'`
		if [ "$def_fs" = "$fsys" ]      # if default is what we want ...
		then            		# for every file system ...
			while read line
			do
				echo $line
			done < $infile |

			# not a comment and no -F option
			`egrep -v "(^[#]|-F)" | /sbin/sh`
		fi
	    else
		echo "shareall: can't open $fsys_file"
	    fi
	fi
else			# for every file system ...
	if [ "$infile" = "/etc/dfs/dfstab" ]
	then
	    /usr/sbin/sharemgr start -a
	else
	    cat $infile|/sbin/sh
	fi
fi
