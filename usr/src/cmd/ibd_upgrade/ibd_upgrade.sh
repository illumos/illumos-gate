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
#
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#
#

PATH=/sbin:/bin
ORIGIFS="${IFS}"
USAGE="Usage: ibd_upgrade [-v]"
DRVCONF=/kernel/drv/ibp.conf.old

#
# split device path into path components
#
split_path_components()
{
	hca_path=
	node_name=
	port=
	pkey=
	service=
	partition_name=

	hca_path="/dev/`dirname $device_path`"
	bname=`basename $device_path`
	IFS=":"
	set -- $bname
	node_at_addr=$1
	partition_name=$2
	IFS="@"
	set -- $node_at_addr
	node_name=$1
	IFS=","
	set -- $2
	port=$1
	pkey=0x$2
	service=$3

	IFS="${ORIGIFS}"
}

do_cmd()
{
	if [ $verbose -eq 1 ]; then
		echo "$1"
	fi
	$1
}

process_rc_mode()
{
	device=$1

	#
	# Get the instance number of ibd
	# Device name format would be ibd#, 
	#
	IFS="d"
	set -- ${device}
	IFS="${ORIGIFS}"

	if [ "$1" != "ib" ]; then
		return
	fi

	inst=$2

	IFS=","
	set -- ${enable_rc}
	IFS="${ORIGIFS}"

	if [ ${inst} -lt $# ]; then
		(( inst = $inst + 1 ))
		eval "linkmode=\$${inst}"
	else
		linkmode=0
	fi

	if [ "$linkmode" = "0" ]; then
		do_cmd "dladm set-linkprop -p linkmode=ud ${device}"
	fi
}

verbose=0
while getopts v c
do
	case $c in
	v)	verbose=1;;
	\?)	echo "$USAGE" 1>&2
		exit 2;;
	esac
done

enable_rc=
if [ -f ${DRVCONF} ]; then
	enable_rc=`egrep "^[ 	]*enable_rc[ 	]*=" ${DRVCONF} | sed -e "s/[ 	]*//g" -e "s/enable_rc=//" -e "s/;$//" 2>/dev/null`
fi

#
# Loop through all ibd devices based on the old model (i.e., one ibd instance
# per partition; consequently device names have non zero pkey)
# and create data links with the same names as in the old model under the
# new model.
#
ls -l /dev/ibd* 2> /dev/null \
    | while read x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 device_path
do
	split_path_components

	if [ "$node_name" != "ibport" -o "$service" != "ipib" \
	    -o "$pkey" = "0x0" -o "$pkey" = "0x" ]; then
		continue
	fi

	# verify that the hca path exists
	cd $hca_path 2> /dev/null
	if [ $? -ne 0 ]; then
		continue
	fi

	fn=`echo ibport@${port},0,ipib:ibp*[0-9]`
	if [ -c "$fn" ]; then
		IFS=":"
		set -- $fn
		IFS="${ORIGIFS}"

		do_cmd "dladm delete-phys $partition_name" 2>/dev/null
		if [ $? -ne 0 ]; then
			do_cmd "ibd_delete_link $partition_name"
		fi
		do_cmd "dladm create-part -f -l $2 -P $pkey $partition_name"

		if [ "$enable_rc" != "" ]; then
			process_rc_mode $partition_name
		fi
	fi
done 

exit 0
