#!/bin/ksh -p
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# NOTE: this script runs in the global zone and touches the non-global
# zone, so care should be taken to validate any modifications so that they
# are safe.

. /usr/lib/brand/shared/common.ksh

LOGFILE=
MSG_PREFIX="p2v: "
EXIT_CODE=1

usage()
{
	echo "$0 [-s] [-m msgprefix] [-u] [-v] [-b patchid]* zonename" >&2
	exit $EXIT_CODE
}

# Clean up on interrupt
trap_cleanup()
{
	msg=$(gettext "Postprocessing cancelled due to interrupt.")
	error "$msg"

	if (( $zone_is_running != 0 )); then
		error "$e_shutdown" "$ZONENAME"
		/usr/sbin/zoneadm -z $ZONENAME halt
	fi

	exit $EXIT_CODE
}

#
# For an exclusive stack zone, fix up the network configuration files.
# We need to do this even if unconfiguring the zone so sys-unconfig works
# correctly.
#
fix_net()
{
	[[ "$STACK_TYPE" == "shared" ]] && return

	NETIF_CNT=$(/usr/bin/ls $ZONEROOT/etc/hostname.* 2>/dev/null | \
	    /usr/bin/wc -l)
	if (( $NETIF_CNT != 1 )); then
		vlog "$v_nonetfix"
		return
	fi

	NET=$(LC_ALL=C /usr/sbin/zonecfg -z $ZONENAME info net)
	if (( $? != 0 )); then
		error "$e_badinfo" "net"
		return
	fi

	NETIF=$(echo $NET | /usr/bin/nawk '{
		for (i = 1; i < NF; i++) {
			if ($i == "physical:") {
				if (length(net) == 0) {
					i++
					net = $i
				} else {
					multiple=1
				}
			}
		}
	}
	END {	if (!multiple)
			print net
	}')

	if [[ -z "$NETIF" ]]; then
		vlog "$v_nonetfix"
		return
	fi

	OLD_HOSTNET=$(/usr/bin/ls $ZONEROOT/etc/hostname.*)
	if [[ "$OLD_HOSTNET" != "$ZONEROOT/etc/hostname.$NETIF" ]]; then
		safe_move $OLD_HOSTNET $ZONEROOT/etc/hostname.$NETIF
	fi
}

#
# Disable all of the shares since the zone cannot be an NFS server.
# Note that we disable the various instances of the svc:/network/shares/group
# SMF service in the fix_smf function. 
#
fix_nfs()
{
	zonedfs=$ZONEROOT/etc/dfs

	if [[ -h $zonedfs/dfstab || ! -f $zonedfs/dfstab ]]; then
		error "$e_badfile" "/etc/dfs/dfstab"
		return
	fi

	tmpfile=$(/usr/bin/mktemp -t -p /var/tmp)
	if [[ -z "$tmpfile" ]]; then
		error "$e_tmpfile"
		return
	fi

	/usr/bin/nawk '{
		if (substr($1, 0, 1) == "#") {
			print $0
		} else {
			print "#", $0
			modified=1
		}
	}
	END {
		if (modified == 1) {
			printf("# Modified by p2v ")
			system("/usr/bin/date")
			exit 0
		}
		exit 1
	}' $zonedfs/dfstab >>$tmpfile

	if (( $? == 0 )); then
		if [[ ! -f $zonedfs/dfstab.pre_p2v ]]; then
			safe_copy $zonedfs/dfstab $zonedfs/dfstab.pre_p2v
		fi
		safe_copy $tmpfile $zonedfs/dfstab
	fi
	/usr/bin/rm -f $tmpfile
}

#
# Comment out most of the old mounts since they are either unneeded or
# likely incorrect within a zone.  Specific mounts can be manually 
# reenabled if the corresponding device is added to the zone.
#
fix_vfstab()
{
	if [[ -h $ZONEROOT/etc/vfstab || ! -f $ZONEROOT/etc/vfstab ]]; then
		error "$e_badfile" "/etc/vfstab"
		return
	fi

	tmpfile=$(/usr/bin/mktemp -t -p /var/tmp)
	if [[ -z "$tmpfile" ]]; then
		error "$e_tmpfile"
		return
	fi

	/usr/bin/nawk '{
		if (substr($1, 0, 1) == "#") {
			print $0
		} else if ($1 == "fd" || $1 == "/proc" || $1 == "swap" ||
		    $1 == "ctfs" || $1 == "objfs" || $1 == "sharefs" ||
		    $4 == "nfs" || $4 == "lofs") {
			print $0
		} else {
			print "#", $0
			modified=1
		}
	}
	END {
		if (modified == 1) {
			printf("# Modified by p2v ")
			system("/usr/bin/date")
			exit 0
		}
		exit 1
	}' $ZONEROOT/etc/vfstab >>$tmpfile

	if (( $? == 0 )); then
		if [[ ! -f $ZONEROOT/etc/vfstab.pre_p2v ]]; then
			safe_copy $ZONEROOT/etc/vfstab \
			    $ZONEROOT/etc/vfstab.pre_p2v
		fi
		safe_copy $tmpfile $ZONEROOT/etc/vfstab
	fi
	/usr/bin/rm -f $tmpfile
}

#
# Delete or disable SMF services.
# Zone is booted to milestone=none when this function is called.
#
fix_smf()
{
	#
	# Delete services that are delivered in hollow pkgs.
	#
	# Start by getting the svc manifests that are delivered by hollow
	# pkgs then use 'svccfg inventory' to get the names of the svcs
	# delivered by those manifests.  The svc names are saved into a
	# temporary file.  We then login to the zone and delete them from SMF
	# so that the various dependencies also get cleaned up properly.
	#

	smftmpfile=$(/usr/bin/mktemp -t -p /var/tmp smf.XXXXXX)
	if [[ -z "$smftmpfile" ]]; then
		error "$e_tmpfile"
		return
	fi

	for i in /var/sadm/pkg/*
	do
		pkg=$(/usr/bin/basename $i)
		[[ ! -f /var/sadm/pkg/$pkg/save/pspool/$pkg/pkgmap ]] && \
		    continue

		manifests=$(/usr/bin/nawk '{if ($2 == "f" &&
		    substr($4, 1, 17) == "var/svc/manifest/") print $4}' \
		    /var/sadm/pkg/$pkg/save/pspool/$pkg/pkgmap)

		if [[ -n "$manifests" ]]; then
			/usr/bin/egrep -s "SUNW_PKG_HOLLOW=true" \
			    /var/sadm/pkg/$pkg/pkginfo || continue

			for j in $manifests
			do
				svcs=$(SVCCFG_NOVALIDATE=1 /usr/sbin/svccfg \
				    inventory /$j)
				for k in $svcs
				do
					case $k in
					*:default)
						# ignore default instance
						;;
					*)
						echo $k >> $smftmpfile
						;;
					esac
				done
			done
		fi
	done

	# 
	# Zone was already booted to milestone=none, wait until SMF door exists.
	#
	for i in 0 1 2 3 4 5 6 7 8 9
	do
		[[ -r $ZONEROOT/etc/svc/volatile/repository_door ]] && break
		sleep 5
	done

	if [[ $i -eq 9 && ! -r $ZONEROOT/etc/svc/volatile/repository_door ]];
	then
		error "$e_nosmf"
		/usr/bin/rm -f $smftmpfile
		return
	fi

	insttmpfile=$(/usr/bin/mktemp -t -p /var/tmp instsmf.XXXXXX)
	if [[ -z "$insttmpfile" ]]; then
		error "$e_tmpfile"
		/usr/bin/rm -f $smftmpfile
		return
	fi

	# Get a list of the svcs that exist in the zone.
	/usr/sbin/zlogin -S $ZONENAME /usr/bin/svcs -aH | \
	    /usr/bin/nawk '{print $3}' >>$insttmpfile

	[[ -n $LOGFILE ]] && \
	    printf "[$(date)] ${MSG_PREFIX}${v_svcsinzone}\n" >&2
	[[ -n $LOGFILE ]] && cat $insttmpfile >&2

	vlog "$v_rmhollowsvcs"
	for i in $(cat $smftmpfile)
	do
		# Skip svcs not installed in the zone.
		/usr/bin/egrep -s "$i:" $insttmpfile || continue

		# Delete the svc.
		vlog "$v_delsvc" "$i"
		/usr/sbin/zlogin -S $ZONENAME /usr/sbin/svccfg delete $i >&2 \
		    || error "$e_delsvc" $i
	done

	/usr/bin/rm -f $smftmpfile

	#
	# Fix network services if shared stack.
	#
	if [[ "$STACK_TYPE" == "shared" ]]; then
		vlog "$v_fixnetsvcs"

		NETPHYSDEF="svc:/network/physical:default"
		NETPHYSNWAM="svc:/network/physical:nwam"

		/usr/bin/egrep -s "$NETPHYSDEF" $insttmpfile
		if (( $? == 0 )); then
			vlog "$v_enblsvc" "$NETPHYSDEF"
			/usr/sbin/zlogin -S $ZONENAME \
			    /usr/sbin/svcadm enable $NETPHYSDEF || \
			    error "$e_dissvc" "$NETPHYSDEF"
		fi

		/usr/bin/egrep -s "$NETPHYSNWAM" $insttmpfile
		if (( $? == 0 )); then
			vlog "$v_dissvc" "$NETPHYSNWAM"
			/usr/sbin/zlogin -S $ZONENAME \
			    /usr/sbin/svcadm disable $NETPHYSNWAM || \
			    error "$e_enblsvc" "$NETPHYSNWAM"
		fi

		for i in $(/usr/bin/egrep network/routing $insttmpfile)
		do
			# Disable the svc.
			vlog "$v_dissvc" "$i"
			/usr/sbin/zlogin -S $ZONENAME \
			    /usr/sbin/svcadm disable $i || \
			    error "$e_dissvc" $i
		done
	fi

	#
	# Disable well-known services that don't run in a zone.
	#
	vlog "$v_rminvalidsvcs"
	for i in $(/usr/bin/egrep -hv "^#" \
	    /usr/lib/brand/native/smf_disable.lst \
	    /etc/brand/native/smf_disable.conf)
	do
		# Skip svcs not installed in the zone.
		/usr/bin/egrep -s "$i:" $insttmpfile || continue

		# Disable the svc.
		vlog "$v_dissvc" "$i"
		/usr/sbin/zlogin -S $ZONENAME /usr/sbin/svcadm disable $i || \
		    error "$e_dissvc" $i
	done

	#
	# Since zones can't be NFS servers, disable all of the instances of
	# the shares svc.
	#
	for i in $(/usr/bin/egrep network/shares/group $insttmpfile)
	do
		vlog "$v_dissvc" "$i"
		/usr/sbin/zlogin -S $ZONENAME /usr/sbin/svcadm disable $i || \
		    error "$e_dissvc" $i
	done

	/usr/bin/rm -f $insttmpfile
}

#
# Remove well-known pkgs that do not work inside a zone.
#
rm_pkgs()
{
	/usr/bin/cat <<-EOF > $ZONEROOT/tmp/admin || fatal "$e_adminf"
	mail=
	instance=overwrite
	partial=nocheck
	runlevel=nocheck
	idepend=nocheck
	rdepend=nocheck
	space=nocheck
	setuid=nocheck
	conflict=nocheck
	action=nocheck
	basedir=default
	EOF

	for i in $(/usr/bin/egrep -hv "^#" /usr/lib/brand/native/pkgrm.lst \
	    /etc/brand/native/pkgrm.conf)
	do
		[[ ! -d $ZONEROOT/var/sadm/pkg/$i ]] && continue

		vlog "$v_rmpkg" "$i"
		/usr/sbin/zlogin -S $ZONENAME \
		    /usr/sbin/pkgrm -na /tmp/admin $i >&2 || error "$e_rmpkg" $i
	done
}

#
# Zoneadmd writes a one-line index file into the zone when the zone boots,
# so any information about installed zones from the original system will
# be lost at that time.  Here we'll warn the sysadmin about any pre-existing
# zones that they might want to clean up by hand, but we'll leave the zonepaths
# in place in case they're on shared storage and will be migrated to
# a new host.
#
warn_zones()
{
	zoneconfig=$ZONEROOT/etc/zones

	if [[ -h $zoneconfig/index || ! -f $zoneconfig/index ]]; then
		error "$e_badfile" "/etc/zones/index"
		return
	fi

	NGZ=$(/usr/bin/nawk -F: '{
		if (substr($1, 0, 1) == "#" || $1 == "global")
			continue

		if ($2 == "installed")
			printf("%s ", $1)
	}' $zoneconfig/index)

	# Return if there are no installed zones to warn about.
	[[ -z "$NGZ" ]] && return

	log "$v_rmzones" "$NGZ"

	NGZP=$(/usr/bin/nawk -F: '{
		if (substr($1, 0, 1) == "#" || $1 == "global")
			continue

		if ($2 == "installed")
			printf("%s ", $3)
	}' $zoneconfig/index)

	log "$v_rmzonepaths"

	for i in $NGZP
	do
		log "    %s" "$i"
	done
}

unset LD_LIBRARY_PATH
PATH=/usr/sbin:/usr/bin
export PATH

#
# ^C Should cleanup; if the zone is running, it should try to halt it.
#
zone_is_running=0
trap trap_cleanup INT

#
# Parse the command line options.
#
unset backout
OPT_U=
OPT_V=
OPT_M=
OPT_L=
while getopts "b:uvm:l:" opt
do
	case "$opt" in
		b)	if [[ -n "$backout" ]]; then
				backout="$backout -b $OPTARG"
			else
				backout="-b $OPTARG"
			fi
			;;
		u)	OPT_U="-u";;
		v)	OPT_V="-v";;
		m)	MSG_PREFIX="$OPTARG"; OPT_M="-m \"$OPTARG\"";;
		l)	LOGFILE="$OPTARG"; OPT_L="-l \"$OPTARG\"";;
		*)	usage;;
	esac
done
shift OPTIND-1

(( $# < 1 )) && usage

(( $# > 2 )) && usage

[[ -n $LOGFILE ]] && exec 2>>$LOGFILE

ZONENAME=$1
ZONEPATH=$2
ZONEROOT=$ZONEPATH/root

e_badinfo=$(gettext "Failed to get '%s' zone resource")
e_badfile=$(gettext "Invalid '%s' file within the zone")
e_tmpfile=$(gettext "Unable to create temporary file")
v_mkdirs=$(gettext "Creating mount points")
v_nonetfix=$(gettext "Cannot update /etc/hostname.{net} file")
v_update=$(gettext "Updating the zone software to match the global zone...")
v_updatedone=$(gettext "Zone software update complete")
e_badupdate=$(gettext "Updating the Zone software failed")
v_adjust=$(gettext "Updating the image to run within a zone")
v_stacktype=$(gettext "Stack type '%s'")
v_booting=$(gettext "Booting zone to single user mode")
e_badboot=$(gettext "Zone boot failed")
e_nosmf=$(gettext "ERROR: SMF repository unavailable.")
e_nosingleuser=$(gettext "ERROR: zone did not finish booting to single-user.")
v_svcsinzone=$(gettext "The following SMF services are installed:")
v_rmhollowsvcs=$(gettext "Deleting SMF services from hollow packages")
v_fixnetsvcs=$(gettext "Adjusting network SMF services")
v_rminvalidsvcs=$(gettext "Disabling invalid SMF services")
v_delsvc=$(gettext "Delete SMF svc '%s'")
e_delsvc=$(gettext "deleting SMF svc '%s'")
v_enblsvc=$(gettext "Enable SMF svc '%s'")
e_enblsvc=$(gettext "enabling SMF svc '%s'")
v_dissvc=$(gettext "Disable SMF svc '%s'")
e_dissvc=$(gettext "disabling SMF svc '%s'")
e_adminf=$(gettext "Unable to create admin file")
v_rmpkg=$(gettext "Remove package '%s'")
e_rmpkg=$(gettext "removing package '%s'")
v_rmzones=$(gettext "The following zones in this image will be unusable: %s")
v_rmzonepaths=$(gettext "These zonepaths could be removed from this image:")
v_unconfig=$(gettext "Performing zone sys-unconfig")
e_unconfig=$(gettext "sys-unconfig failed")
v_halting=$(gettext "Halting zone")
e_shutdown=$(gettext "Shutting down zone %s...")
e_badhalt=$(gettext "Zone halt failed")
v_exitgood=$(gettext "Postprocessing successful.")
e_exitfail=$(gettext "Postprocessing failed.")

#
# Do some validation on the paths we'll be accessing
#
safe_dir etc
safe_dir etc/dfs
safe_dir etc/zones
safe_dir var

# Now do the work to update the zone.

# Before booting the zone we may need to create a few mnt points, just in
# case they don't exist for some reason.
#
# Whenever we reach into the zone while running in the global zone we
# need to validate that none of the interim directories are symlinks
# that could cause us to inadvertently modify the global zone.
vlog "$v_mkdirs"
if [[ ! -f $ZONEROOT/tmp && ! -d $ZONEROOT/tmp ]]; then
	mkdir -m 1777 -p $ZONEROOT/tmp || exit $EXIT_CODE
fi
if [[ ! -f $ZONEROOT/var/run && ! -d $ZONEROOT/var/run ]]; then
	mkdir -m 1755 -p $ZONEROOT/var/run || exit $EXIT_CODE
fi
if [[ ! -h $ZONEROOT/etc && ! -f $ZONEROOT/etc/mnttab ]]; then
	/usr/bin/touch $ZONEROOT/etc/mnttab || exit $EXIT_CODE
	/usr/bin/chmod 444 $ZONEROOT/etc/mnttab || exit $EXIT_CODE
fi
if [[ ! -f $ZONEROOT/proc && ! -d $ZONEROOT/proc ]]; then
	mkdir -m 755 -p $ZONEROOT/proc || exit $EXIT_CODE
fi
if [[ ! -f $ZONEROOT/dev && ! -d $ZONEROOT/dev ]]; then
	mkdir -m 755 -p $ZONEROOT/dev || exit $EXIT_CODE
fi
if [[ ! -h $ZONEROOT/etc && ! -h $ZONEROOT/etc/svc && ! -d $ZONEROOT/etc/svc ]]
then
	mkdir -m 755 -p $ZONEROOT/etc/svc/volatile || exit $EXIT_CODE
fi

# Check for zones inside of image.
warn_zones

#
# Run update on attach.  State is currently 'incomplete' so use the private
# force-update option.
#
log "$v_update"
/usr/sbin/zoneadm -z $ZONENAME attach -U $backout >&2
res=$?
if (( $? != 0 )); then
	fatal "$e_badupdate"
else
	log "$v_updatedone"
fi

log "$v_adjust"

#
# Any errors in these functions are not considered fatal.  The zone can be
# be fixed up manually afterwards and it may need some additional manual
# cleanup in any case.
#

STACK_TYPE=$(/usr/sbin/zoneadm -z $ZONENAME list -p | \
    /usr/bin/nawk -F: '{print $7}')
if (( $? != 0 )); then
	error "$e_badinfo" "stacktype"
fi
vlog "$v_stacktype" "$STACK_TYPE"

fix_net
fix_nfs
fix_vfstab

vlog "$v_booting"

#
# Boot the zone so that we can do all of the SMF updates needed on the zone's
# repository.
#

zone_is_running=1

# The 'update on attach' left the zone installed.
/usr/sbin/zoneadm -z $ZONENAME boot -f -- -m milestone=none
if (( $? != 0 )); then
	error "$e_badboot"
	fatal "$e_exitfail"
fi

# cleanup SMF services
fix_smf

# remove invalid pkgs
rm_pkgs

vlog "$v_halting"
/usr/sbin/zoneadm -z $ZONENAME halt
if (( $? != 0 )); then
	error "$e_badhalt"
	failed=1
fi
zone_is_running=0

if [[ -z $failed && -n $OPT_U ]]; then
	#
	# We're sys-unconfiging the zone.  This will halt the zone, however
	# there are problems with sys-unconfig and it usually hangs when the
	# zone is booted to milestone=none.  This is why we previously halted
	# the zone.  We now boot to milestone=single-user.  Again, the
	# sys-unconfig can hang if the zone is still in the process of
	# booting when we try to run sys-unconfig.  Wait until the boot is
	# done, which we do by checking for sulogin, or waiting 30 seconds,
	# whichever comes first.
	#

	vlog "$v_unconfig"

	zone_is_running=1
	/usr/sbin/zoneadm -z $ZONENAME boot -- -m milestone=single-user
	if (( $? != 0 )); then
		error "$e_badboot"
		fatal "$e_exitfail"
	fi

        for i in 0 1 2 3 4 5 6 7 8 9
        do
                sleep 10
		/usr/sbin/zlogin $ZONENAME \
		    /usr/bin/svcs -H svc:/milestone/single-user:default 2>&1 |
		    /usr/bin/nawk '{
			if ($1 == "online")
				exit 0
			else
				exit 1
		    }' && break
        done

	if (( $i == 9 )); then
		vlog "$e_nosingleuser"
        fi

	echo "yes" | /usr/sbin/zlogin -S $ZONENAME \
	    /usr/sbin/sys-unconfig >/dev/null 2>&1
	if (( $? != 0 )); then
		error "$e_unconfig"
		failed=1
	fi
fi


if [[ -n $failed ]]; then
	fatal "$e_exitfail"
fi

vlog "$v_exitgood"
exit 0
