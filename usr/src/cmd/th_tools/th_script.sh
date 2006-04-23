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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#
# usage: force_state_change <path> <target state>
#
force_state_change()
{
	[[ $2 != "online" && $2 != "offline" ]] && exit 1
	th_manage $1 getstate | read path state busy
	[[ $? != 0 ]] && exit 1
	[[ "$state" = "$2" ]] && return 0
	th_manage $1 $2
	[[ $? != 0 ]] && exit 1
	th_manage $1 getstate | read path state busy
	[[ $? != 0 ]] && exit 1
	[[ "$state" != "$2" ]] && exit 1
	return 0
}


script_pid=0
trap ' terminate $script_pid ' 1 2 3 15
terminate()
{
	[[ $1 -gt 0 ]] && kill $1 > /dev/null 2>&1
	exit 1
}

#
# usage: control_workload <path> <pid>
# The following function is called (as a background task) prior to taking a
# driver instance offline and immediately after it is brought online. If the
# th_define process which created this script did not specify a script with the
# -e option then the default action is to run in the background this script
# which will continuously offline and online the instance until the injected
# error is detected by the driver or until the errdef is aborted.
#
control_workload()
{
	fixup_script 1
	if [ $? == 0 ]; then
		return
	fi

	#
	# Default workload - continuously offline and online the driver instance
	# while injecting errors
	#

	if [[ $2 -gt 0 ]]; then
		kill $2 > /dev/null 2>&1
	fi
	if [ $# -lt 2 ]; then
		echo syntax: $0 path pid
	elif [ $DRIVER_UNCONFIGURE = 1 ]; then
		: no unconfigure action required ;
	elif [ $DRIVER_CONFIGURE = 1 ]; then
		while [ 1 ]; do
			sleep 2
			force_state_change $1 offline
			force_state_change $1 online
		done &
		script_pid=$!
	fi
}

#
# usage: prepare_for_errdef <path> <driver> <instance> <do_unconfigure>
#
prepare_for_errdef()
{
	export DRIVER_PATH=$1
	export DRIVER_NAME=$2
	export DRIVER_INSTANCE=$3
	export DRIVER_UNCONFIGURE=1
	export DRIVER_CONFIGURE=0
	control_workload $1 $script_pid
	script_pid=0

	th_manage $2 $3 get_handles >/dev/null 2>&1
	[[ $? != 0 ]] && exit 1
	force_state_change $1 offline
	force_state_change $1 online

	export DRIVER_UNCONFIGURE=0
	export DRIVER_CONFIGURE=1
	[[ $4 == 1 ]] &&
		control_workload $1 $script_pid
}

# usage: monitor_edef <driver> <instance> <nsteps>
monitor_edef()
{
	let aborted=0
	trap ' (( aborted += 1 )) ' 16
	sleep 2	# Wait for the errdef to be added
	th_manage $1 $2 start
	[[ $? != 0 ]] && exit 1

	let s=0
	let x=$3
	set -A stats 0 0 1 0 0 0 0 ""

	#
	# Loop for x reports unless the error is reported or the access fail
	# count goes to zero.
	#
	while (( (x -= 1) >= 0 ))
	do
		(( aborted > 0 )) && break
		read line
		[ -z "$line" ] && break
		set -A stats $(echo "$line" |
		    /usr/bin/awk -F: '{for (i = 1; i <= NF; i++) print $i}')
		[ "${stats[6]}" -ne "0" ] && break	# Fault was reported
		#
		# If fail count is zero - increment a loop counter 3 times
		# before aborting this errdef.
		#
		[ "${stats[3]}" = "0" ] && (( (s += 1) > 3 )) && break
	done
	th_manage $1 $2 clear_errdefs			# Clear errors.
	[[ $? != 0 ]] && exit 1
	echo "${stats[@]}"
}

#
# Install, activate and monitor some error definitions
# usage: run_subtest <driver> <instance> < errdefs
#
run_subtest()
{
	let edefid=0
	drv=$1
	inst=$2
	if [ $devpath = "NULL" ]
	then
		path=$(th_manage $1 $2 getpath)
	else
		path=$devpath
	fi
	while read line
	do
		set -- $(echo "$line" | \
		    /usr/bin/awk '{for (i = 1; i <= NF; i++) print $i}')
		w=${line##*"-w "}
		let a=${w%%" "*}
		let b=${w##*" "}
		let x='a / b'
		(( a % b > 0 )) && (( x += 1 ))
		prepare_for_errdef $path $drv $inst 1
		set -A status $(th_define $* 2>./elog | \
		    monitor_edef $drv $inst $x)
		if [ "${status[2]}" -gt 0 ]; then
			res="test not triggered"
		elif [ "${status[1]}" -eq 0 ]; then
			res="success (error undetected)"
		elif [ "${status[1]}" -gt 0 ]; then
			if [ "${status[6]}" -eq 16 ]; then
				res="failure (no service impact reported)"
			else
				res="success (error reported)"
			fi
		else
			res=
		fi
		echo "Subtest $edefid: Result: \"$res\""
		echo $line
		if [ -n "${status[7]}" ]; then
			let i=6
			let l=${#status[@]}
			echo "	Fail Msg  :\t\c"
			while (( (i += 1) <= l ))
			do
				echo "${status[$i]} \c"
			done
			echo ""
		fi
		echo "\tFail Time :\t${status[0]}\tMsg Time  :\t${status[1]}"
		echo "\tAcc count :\t${status[2]}\tFail count:\t${status[3]}"
		echo "\tAccess Chk:\t${status[4]}\tEmsg count:\t${status[5]}"
		if [ "${status[6]}" -eq 0 ]; then
			echo "\tSeverity:\tSERVICE UNAFFECTED"
		elif [ "${status[6]}" -eq -16 ]; then
			echo "\tSeverity:\tSERVICE DEGRADED"
		elif [ "${status[6]}" -eq -32 ]; then
			echo "\tSeverity:\tSERVICE LOST"
		fi
		((edefid += 1))
	done

	fixup_script 0
	prepare_for_errdef $path $drv $inst 0
}
