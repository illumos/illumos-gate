#!/bin/bash

#
# CDDL HEADER START
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# CDDL HEADER END
#

#
# Copyright (c) 2015, 2016 by Delphix. All rights reserved.
#

set -x
export BITS=64
export UMEM_DEBUG=default,verbose
export UMEM_LOGGING=transaction,contents
set +x

sparc_32=sparc
sparc_64=sparcv9
i386_32=i86
i386_64=amd64
ARCH=`uname -p`
eval 'ARCHBITS=${'"${ARCH}_${BITS}"'}'
BIN=$ROOT/usr/bin/${ARCHBITS}
SBIN=$ROOT/usr/sbin/${ARCHBITS}
DEFAULTWORKDIR=/var/tmp
DEFAULTCOREDIR=/var/tmp/zloop

function usage
{
	echo -e "\n$0 [-t <timeout>] [-c <dump directory>]" \
	    "[ -- [extra ztest parameters]]\n" \
	    "\n" \
	    "  This script runs ztest repeatedly with randomized arguments.\n" \
	    "  If a crash is encountered, the ztest logs, any associated\n" \
	    "  vdev files, and core file (if one exists) are moved to the\n" \
	    "  output directory ($DEFAULTCOREDIR by default). Any options\n" \
	    "  after the -- end-of-options marker will be passed to ztest.\n" \
	    "\n" \
	    "  Options:\n" \
	    "    -t  Total time to loop for, in seconds. If not provided,\n" \
	    "        zloop runs forever.\n" \
	    "    -f  Specify working directory for ztest vdev files.\n" \
	    "    -c  Specify a core dump directory to use.\n" \
	    "    -h  Print this help message.\n" \
	    "" >&2
}

function or_die
{
	$@
	if [[ $? -ne 0 ]]; then
		echo "Command failed: $@"
		exit 1
	fi
}

function store_core
{
	if [[ $ztrc -ne 0 ]] || [[ -f core ]]; then
		coreid=$(/bin/date "+zloop-%y%m%d-%H%M%S")
		foundcrashes=$(($foundcrashes + 1))

		dest=$coredir/$coreid
		or_die /bin/mkdir $dest
		or_die /bin/mkdir $dest/vdev

		echo "*** ztest crash found - moving logs to $coredir/$coreid"

		or_die /bin/mv ztest.history $dest/
		or_die /bin/mv ztest.out $dest/
		or_die /bin/mv $workdir/ztest* $dest/vdev/
		or_die /bin/mv $workdir/zpool.cache $dest/vdev/

		# check for core
		if [[ -f core ]]; then
			corestatus=$(mdb -e "::status" core)
			corestack=$(mdb -e "::stack" core)

			# Dump core + logs to stored directory
			echo "$corestatus" >>$dest/status
			echo "$corestack" >>$dest/status
			or_die /bin/mv core $dest/

			# Record info in cores logfile
			echo "*** core @ $coredir/$coreid/core:" | /bin/tee -a ztest.cores
			echo "$corestatus" | /bin/tee -a ztest.cores
			echo "$corestack" | /bin/tee -a ztest.cores
			echo "" | /bin/tee -a ztest.cores
		fi
		echo "continuing..."
	fi
}

set -x
export PATH=${BIN}:${SBIN}
export LD_LIBRARY_PATH=$ROOT/lib/$BITS:$ROOT/usr/lib/$BITS
set +x

# parse arguments
# expected format: zloop [-t timeout] [-c coredir] [-- extra ztest args]
coredir=$DEFAULTCOREDIR
workdir=$DEFAULTWORKDIR
timeout=0
while getopts ":ht:c:f:" opt; do
	case $opt in
		t ) [[ $OPTARG -gt 0 ]] && timeout=$OPTARG ;;
		c ) [[ $OPTARG ]] && coredir=$OPTARG ;;
		f ) [[ $OPTARG ]] && workdir=$(/usr/bin/readlink -f $OPTARG) ;;
		h ) usage
		    exit 2
		    ;;
		* ) echo "Invalid argument: -$OPTARG";
		    usage
		    exit 1
	esac
done
# pass remaining arguments on to ztest
shift $((OPTIND - 1))

if [[ -f core ]]; then
	echo "There's a core dump here you might want to look at first."
	exit 1
fi

if [[ ! -d $coredir ]]; then
	echo "core dump directory ($coredir) does not exist, creating it."
	or_die /bin/mkdir -p $coredir
fi

if [[ ! -w $coredir ]]; then
	echo "core dump directory ($coredir) is not writable."
	exit 1
fi

or_die /bin/rm -f ztest.history
or_die /bin/rm -f ztest.cores

ztrc=0		# ztest return value
foundcrashes=0	# number of crashes found so far
starttime=$(/bin/date +%s)
curtime=$starttime

# if no timeout was specified, loop forever.
while [[ $timeout -eq 0 ]] || [[ $curtime -le $(($starttime + $timeout)) ]]; do
	zopt="-VVVVV"

	# switch between common arrangements & fully randomized
	if [[ $((RANDOM % 2)) -eq 0 ]]; then
		mirrors=2
		raidz=0
		parity=1
		vdevs=2
	else
		mirrors=$(((RANDOM % 3) * 1))
		parity=$(((RANDOM % 3) + 1))
		raidz=$((((RANDOM % 9) + parity + 1) * (RANDOM % 2)))
		vdevs=$(((RANDOM % 3) + 3))
	fi
	align=$(((RANDOM % 2) * 3 + 9))
	runtime=$((RANDOM % 100))
	passtime=$((RANDOM % (runtime / 3 + 1) + 10))
	size=128m

	zopt="$zopt -m $mirrors"
	zopt="$zopt -r $raidz"
	zopt="$zopt -R $parity"
	zopt="$zopt -v $vdevs"
	zopt="$zopt -a $align"
	zopt="$zopt -T $runtime"
	zopt="$zopt -P $passtime"
	zopt="$zopt -s $size"
	zopt="$zopt -f $workdir"

	cmd="ztest $zopt $@"
	desc="$(/bin/date '+%m/%d %T') $cmd"
	echo "$desc" | /bin/tee -a ztest.history
	echo "$desc" >>ztest.out
	$BIN/$cmd >>ztest.out 2>&1
	ztrc=$?
	/bin/egrep '===|WARNING' ztest.out >>ztest.history
	$SBIN/zdb -U $workdir/zpool.cache -DD ztest >>ztest.ddt 2>&1

	store_core

	curtime=$(/bin/date +%s)
done

echo "zloop finished, $foundcrashes crashes found"

/bin/uptime >>ztest.out

if [[ $foundcrashes -gt 0 ]]; then
	exit 1
fi
