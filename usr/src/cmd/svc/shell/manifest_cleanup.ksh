#!/bin/ksh
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

[ -f /lib/svc/share/smf_include.sh ] || exit 1

. /lib/svc/share/smf_include.sh

SVCADM=/usr/sbin/svcadm
SVCCFG=/usr/sbin/svccfg
SVCPROP=/bin/svcprop
SVCS=/usr/bin/svcs
MFSTPG=manifestfiles
MFSTSCAN=/lib/svc/bin/mfstscan
MCLEANUPFILE=/etc/svc/volatile/mcleanup.$$
IGNORELIST="system/install-discovery smf/manifest"
UPLIST=0

#
# Create a list of service to manifest pairs for the upgrade
# process to determine what files are associated with a service
#
function create_list {
	for cl_mfile in `find /var/svc/manifest -name "*.xml"`
	do
		for cl_invent in `svccfg inventory $cl_mfile`
		do
			cl_invent=${cl_invent#svc:/*}

			cl_instance=${cl_invent#*:}
			cl_instance=${cl_instance##*/*}
			[ $cl_instance ] && continue

			cl_invent=${cl_invent%:*}
			cl_invent=`echo $cl_invent | sed -e 's/[-\/\,]/_/g'`


			eval $cl_invent=\"\$$cl_invent $cl_mfile\"
			# XXX - remove this line at some point "
			# I clears up the above escaped quote throwing
			# off my color scheme in vim.
		done
	done
	UPLIST=1
}

#
# Inventory the instances listed with a manifest file
#
function get_instances {
	gi_mfile=$1

	lst=""
	for gi_invent in `svccfg inventory $gi_mfile`
	do
		gi_tmp=${gi_invent#svc:/*}
		gi_tmp=${gi_tmp#*:}
		gi_tmp=${gi_tmp##*/*}

		[ $gi_tmp ] && lst="$lst $gi_invent"
	done

	echo $lst
}

function pid_timeout {
	pt_pid=$1

	pt_cnt=0
	while [ `ps -p $pt_pid -o pid | grep -v PID` -a $pt_cnt -lt 30 ]
	do
		sleep 1
		cnt=`expr $pt_cnt + 1`
	done
	if [ $pt_cnt -eq 30 -a "`ps -p $pt_pid -o pid | grep -v PID`" ]; then
		return 1
	else
		return 0
	fi
}

#
# Process a service to ensure that it's manifests exist
# and are in sync with the service.
#
function process_service {
	ps_service=$1

	#
	# Throw away unsupported services, if there is a false listing
	# for manifestfiles support
	#
	$SVCPROP -p $MFSTPG/support $ps_service 2>/dev/null | grep false > /dev/null
	[ $? -eq 0 ] && return

	#
	# Create the list of instances for this service.
	#
	$SVCPROP -p $MFSTPG $ps_service > $MCLEANUPFILE
	set -A ps_mfiles `grep astring $MCLEANUPFILE | awk '{print $3}'`

	#
	# Check to see if the manifest files associated with the service are
	# missing, or if the manifest file has changed, either caught here
	# or by the caller.
	#
	ps_x=`$MFSTSCAN ${ps_mfiles[@]} 2>&1`
	if [ $? -eq 0 ]; then
		if [ "$force" != "true" -a ! "$ps_x" ]; then
			ps_ret=0
			for ps_f in ${ps_mfiles[@]}
			do
				echo "$force" | grep -v $ps_f > /dev/null 2>&1
				ps_ret=`expr $ps_ret + $?`
			done
			[ $ps_ret -eq 0 ] && return
		fi
	fi

	ps_refresh=0
	ps_mfiles_tmp=""
	ps_mfiles_cnt=${#ps_mfiles[@]}
	ps_instances=`$SVCS -H -oFMRI $ps_service 2>/dev/null`

	#
	# For each manifest file that is listed by the service
	# check for its existance.  If it exists, then check that
	# the instances of the service are supported by at least
	# one of the manifest files listed.
	#
	for mf in ${ps_mfiles[@]}
	do
		if [ ! -f $mf ]; then
			ps_mfiles_tmp="$ps_mfiles_tmp $mf"
			continue
		fi

		[ ${mf%/var/svc/manifest*} ] && continue

		inst=`get_instances $mf`

		set -A ps_inst_list
		for i in $inst
		do
			ps_inst_tmp=""
			for j in $ps_instances
			do
				if [ "$i" == "$j" ]; then
					set -A ps_inst_list ${ps_inst_list[*]} $j
					continue
				else
					ps_inst_tmp="$ps_inst_tmp $j"
				fi
			done
			#
			# If there are any instances not accounted for add
			# them to the list to be cleaned up.
			#
			ps_instances=$ps_inst_tmp
		done
	done
	#
	# If there are any manifest files set them to the list
	# to be cleaned up.
	#
	set -A ps_mfiles $ps_mfiles_tmp

	#
	# For each manifest file that was not found remove it from
	# the service's list of manifest files.
	#
	for mf in ${ps_mfiles[@]}
	do
		#
		# Need to remove the file from the smf/manifest
		# list.
		#
		ps_refresh=1
		mf_nw=`echo "$needwork" | grep -v $mf`
		needwork="$mf_nw"
		mf_srch=`echo $mf | sed -e 's/\./\\\./g'`
		mf_pg=`grep "$mf_srch" $MCLEANUPFILE | awk '{print $1}'`
		[ $ps_mfiles_cnt -ne ${#ps_mfiles[@]} ] && \
		    $SVCCFG -s $ps_service delprop $mf_pg > /dev/null 2>&1
		mf_pg=`echo $mf_pg | awk -F'/' '{print $2}'`
		$SVCCFG -s smf/manifest delpg $mf_pg > /dev/null 2>&1
	done

	#
	# If all the manifest files that were listed in the service have now
	# been removed, delete the service.
	#
	if [ $ps_mfiles_cnt -eq ${#ps_mfiles[@]} ]; then
		#
		# Disable each of the instances for the service
		# then delete the service.
		#
		# If the restarter is not startd then the service
		# will not be online at this point and we need
		# to not wait on the disable.
		#
		# Set the delete opt to -f if the disable is not
		# synchronous.
		#
		$SVCPROP -q -p general/restarter $ps_service
		if [ $? -ne 0 ]; then
			DISOPT="-s"
			DELOP=""
		else
			DISOPT=""
			DELOP="-f"
		fi

		for i in `$SVCS -H -oFMRI $ps_service`
		do
			$SVCADM disable $DISOPT $i &
			CPID=$!

			pid_timeout $CPID
			if [ $? -ne 0 ]; then
				DELOPT="-f"
				kill $CPID
			fi
		done

		echo "$SVCCFG delete $ps_service"
		$SVCCFG delete $DELOPT $ps_service
		return
	fi

	#
	# Need to only cleanup instances that are no longer supported
	# by the manifest files associated with the service.
	#
	for i in $ps_instances
	do
		#
		# Ignore any instances that are hand created
		#
		ps_refresh=1
		$SVCCFG -s $i selectsnap last-import > /dev/null 2>&1
		[ $? -ne 0 ] && continue

		#
		# If the restarter is not startd then the service
		# will not be online at this point and we need
		# to not wait on the disable.
		#
		$SVCPROP -q -p general/restarter $ps_service
		if [ $? -ne 0 ]; then
			DELOP=""
			$SVCADM disable -s $i &
			CPID=$!

			pid_timeout $CPID
			if [ $? -ne 0 ]; then
				DELOPT="-f"
				kill $CPID
			fi
		else
			DELOP="-f"
			$SVCADM disable $i
		fi

		echo "$SVCCFG delete $i"
		$SVCCFG delete $DELOP $i
	done

	#
	# If instances of the services were removed, refresh the
	# additional instances, or cleanup any leftover services.
	#
	if [ $ps_refresh -ne 0 ]; then
		if [ ${#ps_inst_list[@]} -gt 0 ]; then
			for i in ${ps_inst_list[@]}
			do
				$SVCCFG -s $i refresh
			done
		else
			ps_support=0
			for ps_mfile in `awk '{print $3}' $MCLEANUPFILE`
			do
				$SVCCFG inventory $ps_mfile | grep $ps_service > /dev/null 2>&1
				[ $? -eq 0 ] && ps_supprt=1
			done
			[ $ps_support -eq 0 ] && $SVCCFG delete $ps_service
		fi
	fi
}

#
# Upgrade a service to have the manifest files associated with
# listed in the manifestfiles property group.
#
# If the first argument is FALSE, then check to see if the service
# has any previous import indications.  If so then delete the
# service, otherwise set the service as a non-supported service
# for the automated manifest deletion process.
#
function add_manifest {
	am_service=$1
	shift

	$SVCCFG -s $am_service addpg $MFSTPG framework

	if [ "$1" == "FALSE" ]; then
		am_lisnap=1
		am_inst=`svcs -H -oFMRI $am_service 2>/dev/null`
		if [ $? -eq 0 ]; then
			for i in $am_inst
			do
				$SVCCFG -s $i selectsnap last-import > /dev/null 2>&1
				[ $? -eq 0 ] && am_lisnap=0
			done
		fi

		if [ $am_lisnap -eq 0 ]; then
			$SVCCFG delete -f $am_service
		else
			$SVCCFG -s $am_service setprop $MFSTPG/support = boolean: 0
		fi
	else
		for am_mfile in $@
		do
			CF=${am_mfile#/*}
			CF=`echo $CF | sed -e 's/[-\/\,\.]/_/g'`
			$SVCCFG -s $am_service setprop $MFSTPG/$CF = astring: $am_mfile
		done
	fi
}

#
# upgrade the entries in the smf/manifest table to have
# a pointer to the actual manifest file.
#
function upgrade_smfmanifest {
	us_unfnd=""

	for us_E in `$SVCPROP smf/manifest | grep md5sum | grep var_svc_manifest | awk '{print $1}' | awk -F'/' '{print $1}'`
	do
		$SVCPROP -q -p $us_E/manifestfile smf/manifest
		[ $? -eq 0 ] && continue

		us_S=`echo $us_E | sed -e 's/_xml/.xml/'`
		us_S=`echo $us_S | sed -e 's/var_svc_manifest_/var\/svc\/manifest\//'`

		us_R=""
		while [ ! -f $us_S -a ! "$us_R" ]
		do
			us_S=`echo $us_S | sed -e 's/_/\//'`
			us_R=${us_S##*_*}
		done

		us_S="/$us_S"
		if [ -f $us_S ]; then
			us_R=`$MFSTSCAN $us_S`
			[ ! "$R" ] && \
				$SVCCFG -s smf/manifest setprop ${us_E}/manifestfile = astring: $us_S
		else
			us_unfnd="$us_unfnd $us_E"
		fi
	done

	echo "$us_unfnd"
}

function manifest_cleanup {
	#
	# If manifest-import had activity then need to make checks to override
	# a mfstscan that returns no modifications.  This is because the hash
	# table will already have been updated by the manifest-import run, 
	# therefor manifest-cleanup will not see those changes in the mfstscan
	# call.
	#
	# activity indicates changes and overrides the needwork check.
	# force can be a list of files that will only be processed
	# 	or force can be set to true, so that all files are checked
	# 	regardless.
	#
	arg1=$1
	activity=${arg1:-true}
	[ "$1" ] && shift
	argrest=$@
	force=${argrest:-false}

	#
	# Check the smf/manifest table to see if it needs upgrading
	#
	md5c=`$SVCPROP smf/manifest | grep var_svc_manifest | grep -c md5sum`
	mfc=`$SVCPROP smf/manifest | grep var_svc_manifest | grep -cw manifestfile`
	if [ $md5c -ne $mfc ]; then
		unfnd_upgrade=`upgrade_smfmanifest`
		if [ "$force" == false ]; then
			activity="true"
			force="true"
		fi
	fi

	smfmfiles=`svcprop smf/manifest | grep manifestfile | grep astring | awk '{print $3}'`
	needwork=`/lib/svc/bin/mfstscan $smfmfiles 2>&1 1>/dev/null`
	if [ ! "$needwork" ]; then
		[ "$activity" == false ] && return
	
		[ "$activity" == true -a "$force" == false ] && return
	fi

	#
	# Walk the list of services...
	#
	export SVCCFG_CHECKHASH=1
	for service in `$SVCCFG list`
	do
		svcprop -q -p $MFSTPG $service
		if [ $? -ne 0 ]; then
			if [[ $IGNORELIST == $ps_service ]]; then
				echo "add_manifest $service FALSE"
				add_manifest $service FALSE
			fi
			
			[ $UPLIST -eq 0 ] && create_list

			CS=`echo $service | sed -e 's/[-\/\,]/_/g'`

			eval manifestlist=\$$CS
			if [ -n "$manifestlist" ]; then
				echo "add_manifest $service $manifestlist"
				add_manifest $service $manifestlist
			else
				echo "add_manifest $service FALSE"
				add_manifest $service FALSE
			fi
		else
			process_service $service
		fi
	done

	rm -f $MCLEANUPFILE
	unset SVCCFG_CHECKHASH

	#
	# Check to make sure all work was processed and 
	# that all the files were removed correctly from
	# the smf/manifest table.
	#
	leftover=`echo "$needwork" | grep "cannot stat" | awk '{print $4}'`
	for f in $leftover $unfnd_upgrade
	do
		f_srch=`echo $f | sed -e 's/\./\\\./g; s/:$//'`
		f_entry=`$SVCPROP smf/manifest | grep "$f_srch" | awk -F'/' '{print $1}'`
		[ "$f_entry" ] && $SVCCFG -s smf/manifest delpg $f_entry
	done
}
