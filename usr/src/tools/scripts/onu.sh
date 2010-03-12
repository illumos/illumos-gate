#!/bin/ksh93 -p
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

#
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PATH=/usr/bin:/usr/sbin
export PATH

DEFAULTONURI="http://ipkg.sfbay/on-nightly"
DEFAULTONPUB="on-nightly"
DEFAULTONEXTRAURI="http://ipkg.sfbay/on-extra"
DEFAULTONEXTRAPUB="on-extra"

usage()
{
	echo "usage: $0 [-e URI [-E pub]] [-O] [-s beName] -t beName [-u URI [-U pub]] [-vZ]"
	echo "usage: $0 [ -d dir ][ -O ][ -s beName ] -t beName [-vZ]"
	echo "Use -s to specify the source BE to clone (default is the active BE)."
	echo "Use -t to specify the target BE name."
	echo "Use -u to specify the origin URI for the publisher packaging repository"
	echo "\t(default is \$ONURI if set in the environment, otherwise"
	echo "\t$DEFAULTONURI )."
	echo "Use -U to specify the publisher prefix for the packaging repository"
	echo "\t(default is \$ONPUB if set in the environment, otherwise"
	echo "\t$DEFAULTONPUB )."
	echo "Use -e to specify the origin URI for the extra repository (default is"
	echo "\t\$ONEXTRAURI if set in the environment, otherwise"
	echo "\t$DEFAULTONEXTRAURI )."
	echo "Use -E to specify the publisher prefix for the extra repository (default"
	echo "\tis \$ONEXTRAPUB if set in the environment, otherwise"
	echo "\t$DEFAULTONEXTRAPUB )."
	echo "Use -d to specify a directory containing redist and extra directories."
	echo "\tNote that -d overrides -u, -U, -e and -E."
	echo "Use -O for open mode, meaning that no extra repository will be used."
	echo "Use -v for verbose mode."
	echo "Use -Z to skip updating zones."
	exit 1
}

exit_error()
{
	echo $*
	cleanup
	exit 2
}

cleanup()
{
	[ $redistpid -gt 0 ] && kill $redistpid
	[ $extrapid -gt 0 ] && kill $extrapid
	[ -d /tmp/redist.$$ ] && /bin/rm -rf /tmp/redist.$$
	[ -d /tmp/extra.$$ ] && /bin/rm -rf /tmp/extra.$$
}

do_cmd()
{
	[ $verbose -gt 0 ] && echo $*
	$*
	exit_code=$?
	[ $exit_code -eq 0 ] && return
	# pkg(1) returns 4 if "nothing to do", which is safe to ignore
	[ $1 = "pkg" -a $exit_code -eq 4 ] && return
	exit_error "$*" failed: exit code $exit_code
}

update()
{
	tmpdir=$1

	do_cmd pkg -R $tmpdir set-publisher --non-sticky opensolaris.org
	pkg -R $tmpdir list entire > /dev/null 2>&1
	[ $? -eq 0 ] && do_cmd pkg -R $tmpdir uninstall entire
	do_cmd pkg -R $tmpdir set-publisher -P -O $uri $redistpub
	[ $open -eq 0 ] && do_cmd pkg -R $tmpdir set-publisher -O $extrauri $extrapub
	do_cmd pkg -R $tmpdir refresh --full
	do_cmd pkg -R $tmpdir image-update
}

update_zone()
{
	zone=$1

	name=`echo $zone | cut -d: -f 2`
	if [ $name = "global" ]; then
		return
	fi

	brand=`echo $zone | cut -d: -f 6`
	if [ $brand != "ipkg" ]; then
		return
	fi

	if [ "$zone_warned" = 0 ]; then
		echo "WARNING: Use of onu(1) will prevent use of zone attach in the new BE" >&2
		if [ -n "$repodir" ]; then
			echo "WARNING: use of -d option will prevent new zone installs in the new BE" >&2
		fi

		echo "See onu(1)" >&2
		zone_warned=1
	fi

	state=`echo $zone | cut -d: -f 3`

	case "$state" in 
	configured|incomplete)
		return
		;;
	esac

	zoneroot=`echo $zone | cut -d: -f 4`

	echo "Updating zone $name"
	update $zoneroot/root
}

sourcebe=""
targetbe=""
uri=""
extrauri=""
repodir=""
verbose=0
open=0
redistpid=0
extrapid=0
redistport=13000
extraport=13001
no_zones=0
zone_warned=0

trap cleanup 1 2 3 15

while getopts :d:E:e:Os:t:U:u:vZ i ; do
	case $i in
	d)
		repodir=$OPTARG
		;;
	E)
		extrapub=$OPTARG
		;;
	e)
		extrauri=$OPTARG
		;;
	O)
		open=1
		;;
	s)
		sourcebe=$OPTARG
		;;
	t)
		targetbe=$OPTARG
		;;
	U)
		redistpub=$OPTARG
		;;
	u)
		uri=$OPTARG
		;;
	v)
		verbose=1
		;;
	Z)
		no_zones=1
		;;
	*)
		usage
	esac
done
shift `expr $OPTIND - 1`

[ -z "$targetbe" ] && usage
[ -z "$uri" ] && uri=$ONURI
[ -z "$uri" ] && uri=$DEFAULTONURI
[ -z "$redistpub" ] && redistpub=$ONPUB
[ -z "$redistpub" ] && redistpub=$DEFAULTONPUB
[ -z "$extrauri" ] && extrauri=$ONEXTRAURI
[ -z "$extrauri" ] && extrauri=$DEFAULTONEXTRAURI
[ -z "$extrapub" ] && extrapub=$ONEXTRAPUB
[ -z "$extrapub" ] && extrapub=$DEFAULTONEXTRAPUB

if [ -n "$repodir" ]; then
	redistdir=$repodir/repo.redist
	[ -d $redistdir ] || exit_error "$redistdir not found"
	redistpub=$(python2.6 <<# EOF
		import ConfigParser
		p = ConfigParser.SafeConfigParser()
		p.read("$redistdir/cfg_cache")
		pp = p.get("publisher", "prefix")
		print "%s" % pp
		EOF)
	[ $verbose -gt 0 ] && echo "starting pkg.depotd -d $redistdir -p $redistport"
	ARGS="--readonly --writable-root"
	mkdir /tmp/redist.$$
	/usr/lib/pkg.depotd -d $redistdir -p $redistport $ARGS /tmp/redist.$$ >/dev/null &
	redistpid=$!
	uri="http://localhost:$redistport/"
	if [ $open -eq 0 ]; then
		extradir=$repodir/repo.extra
		[ -d $extradir ] || exit_error "$extradir not found"
		extrapub=$(python2.6 <<# EOF
			import ConfigParser
			p = ConfigParser.SafeConfigParser()
			p.read("$extradir/cfg_cache")
			pp = p.get("publisher", "prefix")
			print "%s" % pp
			EOF)
		[ $verbose -gt 0 ] && echo "starting pkg.depotd -d $extradir -p $extraport"
		mkdir /tmp/extra.$$
		/usr/lib/pkg.depotd -d $extradir -p $extraport $ARGS /tmp/extra.$$ >/dev/null &
		extrapid=$!
		extrauri="http://localhost:$extraport/"
	fi
fi

createargs=""
[ -n "$sourcebe" ] && createargs="-e $sourcebe"

# ksh seems to have its own mktemp with slightly different semantics
tmpdir=`/usr/bin/mktemp -d /tmp/onu.XXXXXX`
[ -z "$tmpdir" ] && exit_error "mktemp failed"

do_cmd beadm create $createargs $targetbe
do_cmd beadm mount $targetbe $tmpdir
update $tmpdir
do_cmd beadm activate $targetbe

if [ "$no_zones" != 1 ]; then
	for zone in `do_cmd zoneadm -R $tmpdir list -cip`; do
		update_zone $zone
	done
fi

cleanup
exit 0
