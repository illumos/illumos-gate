#!/sbin/sh
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
#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved


#ident	"%Z%%M%	%I%	%E% SMI"
#!/bin/sh
#
#  exportfs: compatibility script for SunOs command.  
#

USAGE="Usage: exportfs [-aviu] [-o options] directory"
DFSTAB=/etc/dfs/dfstab
OPTS="rw"

#
# Translate from exportfs opts to share opts
#

fixopts() {
	IFS=, ; set - $OPTS ; IFS=" "
	for i
		do case $i in *access=* ) eval $i ;; esac ; done
	if [ ! "$access" ] ; then return ; fi

	OPTS=""
	for i
	do
		case $i in
		rw=*     ) OPTS="$OPTS$i," ;;
		ro | rw  ) OPTS="${OPTS}$i=$access," ; ropt="true" ;;
		access=* ) ;;
		*        ) OPTS="$OPTS$i," ;;
		esac
	done
	if [ ! "$ropt" ] ; then OPTS="ro=$access,$OPTS" ; fi
	OPTS=`echo $OPTS | sed 's/,$//'`
}

bad() {
	echo $USAGE >&2
	exit 1
}

PATH=/usr/sbin:/usr/bin:$PATH
export PATH

if set -- `getopt aviuo: $*` ; then : ; else bad ; fi

for i in $*
do
	case $i in
	-a ) aflg="true" ; shift ;;	# share all nfs
	-v ) vflg="true" ; shift ;;	# verbose
	-i ) iflg="true" ; shift ;;	# ignore dfstab opts
	-u ) uflg="true" ; shift ;;	# unshare
	-o ) oflg="true" ; OPTS=$2 ; shift 2 ;;	# option string
	-- ) shift ; break ;;
	esac
done

if [ $aflg ] ; then
	if [ "$DIR" -o "$iflg" -o "$oflg"  ] ; then bad ; fi
	if [ $uflg ] ; then
		if [ $vflg ] ; then echo unshareall -F nfs ; fi
		/usr/sbin/unshareall -F nfs
	else
		if [ $vflg ] ; then echo shareall -F nfs ; fi
		/usr/sbin/shareall -F nfs
	fi
	exit $?
fi

case $# in
	0 ) if [ "$iflg" -o "$uflg" -o "$oflg" ] ; then bad ; fi
	    if [ "$vflg" ] ; then echo share -F nfs ; fi
	    /usr/sbin/share -F nfs
	    exit $? ;;

	1 ) DIR=$1 ;;
	* ) bad ;;
esac

if [ $uflg ] ; then
	if [ "$iflg" -o "$oflg" ] ; then bad ; fi
	if [ $vflg ] ; then echo unshare -F nfs $DIR ; fi
	/usr/sbin/unshare -F nfs $DIR
	exit $?
fi

if [ $iflg ] ; then
	fixopts
	if [ $vflg ] ; then echo share -F nfs -o $OPTS $DIR ; fi
	/usr/sbin/share -F nfs -o $OPTS $DIR
else
	CMD=`grep $DIR'[ 	]*$' $DFSTAB`
	if [ "$CMD" = "" ] ; then
		echo "exportfs: no entry for $DIR in $DFSTAB" >&2
		exit 1
	fi
	if [ $oflg ] ; then
		echo "exportfs: supplied options ignored" >&2
		vflg="true"
	fi
	if [ $vflg ] ; then echo $CMD ; fi
	eval $CMD
fi
exit $?

