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

unset LD_LIBRARY_PATH
PATH=/usr/bin:/usr/sbin
export PATH

. /usr/lib/brand/shared/common.ksh

# Use the ipkg-brand ZFS property for denoting the zone root's active dataset.
PROP_ACTIVE="org.opensolaris.libbe:active"

# Values for service tags.
STCLIENT=/usr/bin/stclient
ST_PRODUCT_NAME="Solaris 10 Containers"
ST_PRODUCT_REV="1.0"
ST_PRODUCT_UUID="urn:uuid:2f459121-dec7-11de-9af7-080020a9ed93"

w_sanity_detail=$(gettext "       WARNING: Skipping image sanity checks.")
f_sanity_detail=$(gettext  "Missing %s at %s")
f_sanity_sparse=$(gettext  "Is this a sparse zone image?  The image must be whole-root.")
f_sanity_vers=$(gettext  "The image release version must be 10 (got %s), the zone is not usable on this system.")
f_not_s10_image=$(gettext  "%s doesn't look like a Solaris 10 image.")
f_sanity_nopatch=$(gettext "Unable to determine the image's patch level.")
f_sanity_downrev=$(gettext "The image patch level is downrev for running in a solaris10 branded zone.\n(patchlist %s)")
f_need_newer_emul=$(gettext "The image requires a newer version of the solaris10 brand emulation.")
f_zfs_create=$(gettext "Unable to create the zone's ZFS dataset.")
f_no_ds=$(gettext "No zonepath dataset; the zonepath must be a ZFS dataset.")
f_multiple_ds=$(gettext "Multiple active datasets.")
f_no_active_ds=$(gettext "No active dataset; the zone's ZFS root dataset must be configured as\n\ta zone boot environment.")
f_zfs_unmount=$(gettext "Unable to unmount the zone's root ZFS dataset (%s).\nIs there a global zone process inside the zone root?\nThe current zone boot environment will remain mounted.\n")
f_zfs_mount=$(gettext "Unable to mount the zone's ZFS dataset.")
incompat_options=$(gettext "mutually exclusive options.\n%s")

sanity_ok=$(gettext     "  Sanity Check: Passed.  Looks like a Solaris 10 image.")
sanity_fail=$(gettext   "  Sanity Check: FAILED (see log for details).")

e_badboot=$(gettext "Zone boot failed")
e_nosingleuser=$(gettext "ERROR: zone did not finish booting to single-user.")
e_unconfig=$(gettext "sys-unconfig failed")
v_unconfig=$(gettext "Performing zone sys-unconfig")

v_no_tags=$(gettext "Service tags facility not present.")
e_bad_uuid=$(gettext "Failed to get zone UUID")
v_addtag=$(gettext "Adding service tag: %s")
v_deltag=$(gettext "Removing service tag: %s")
e_addtag_fail=$(gettext "Adding service tag failed (error: %s)")

sanity_check()
{
	typeset dir="$1"
	res=0

	#
	# Check for some required directories and make sure this isn't a
	# sparse zone image.
	#
	checks="etc etc/svc var var/svc"
	for x in $checks; do
		if [[ ! -e $dir/$x ]]; then
			log "$f_sanity_detail" "$x" "$dir"
			res=1
		fi
	done
	# Files from SUNWcsr and SUNWcsu that are in sparse inherit-pkg-dirs.
	checks="lib/svc sbin/zonename usr/bin/chmod"
	for x in $checks; do
		if [[ ! -e $dir/$x ]]; then
			log "$f_sanity_detail" "$x" "$dir"
			log "$f_sanity_sparse"
			res=1
		fi
	done

	if (( $res != 0 )); then
		log "$sanity_fail"
		fatal "$install_fail" "$ZONENAME"
	fi

	if [[ "$SANITY_SKIP" == 1 ]]; then
		log "$w_sanity_detail"
		return
	fi

	#
	# Check image release to be sure its S10.
	#
	image_vers="unknown"
	if [[ -f $dir/var/sadm/system/admin/INST_RELEASE ]]; then
		image_vers=$(nawk -F= '{if ($1 == "VERSION") print $2}' \
		    $dir/var/sadm/system/admin/INST_RELEASE)
	fi

	if [[ "$image_vers" != "10" ]]; then
		log "$f_sanity_vers" "$image_vers"
		res=1
	fi

	#
	# Make sure we have the minimal KU patch we support.  These are the
	# KUs for S10u8.
	#
	if [[ $(uname -p) == "i386" ]]; then
		req_patch="141445-09"
	else
		req_patch="141444-09"
	fi

	for i in $dir/var/sadm/pkg/SUNWcakr*
	do
		if [[ ! -d $i || ! -f $i/pkginfo ]]; then
			log "$f_sanity_nopatch"
			res=1
		fi
	done

	#
	# Check the core kernel pkg for the required KU patch.
	#
	found=0
	for i in $dir/var/sadm/pkg/SUNWcakr*/pkginfo
	do
		patches=$(nawk -F= '{if ($1 == "PATCHLIST") print $2}' $i)
		for patch in $patches
		do
			if [[ $patch == $req_patch ]]; then
				found=1
				break
			fi
		done

		if (( $found == 1 )); then
			break
		fi
	done

	if (( $found != 1 )); then
		log "$f_sanity_downrev" "$patches"
		res=1
	fi

	#
	# Check the S10 image for a required version of the emulation.
	#
	VERS_FILE=/usr/lib/brand/solaris10/version
	s10vers_needs=0
	if [[ -f $dir/$VERS_FILE ]]; then
		s10vers_needs=$(/usr/bin/egrep -v "^#" $dir/$VERS_FILE)
	fi

	# Now get the current emulation version.
	emul_vers=$(/usr/bin/egrep -v "^#" $VERS_FILE)

	# Verify that the emulation can run this version of S10.
	if (( $s10vers_needs > $emul_vers )); then
		log "$f_need_newer_emul"
		res=1
	fi

	if (( $res != 0 )); then
		log "$sanity_fail"
		fatal "$install_fail" "$ZONENAME"
	fi

	vlog "$sanity_ok"
}

# Find the active dataset under the zonepath dataset to mount on zonepath/root.
# $1 ZONEPATH_DS
get_active_ds() {
	ACTIVE_DS=`/usr/sbin/zfs list -H -r -t filesystem \
	    -o name,$PROP_ACTIVE $1/ROOT | \
	    /usr/bin/nawk ' {
		if ($1 ~ /ROOT\/[^\/]+$/ && $2 == "on") {
			print $1
			if (found == 1)
				exit 1
			found = 1
		}
	    }'`

	if [ $? -ne 0 ]; then
		fail_fatal "$f_multiple_ds"
	fi

	if [ -z "$ACTIVE_DS" ]; then
		fail_fatal "$f_no_active_ds"
	fi
}

#
# Make sure the active dataset is mounted for the zone.  There are several
# cases to consider:
# 1) First boot of the zone, nothing is mounted
# 2) Zone is halting, active dataset remains the same.
# 3) Zone is halting, there is a new active dataset to mount.
#
mount_active_ds() {
	mount -p | cut -d' ' -f3 | egrep -s "^$zonepath/root$"
	if (( $? == 0 )); then
		# Umount current dataset on the root (it might be an old BE).
		/usr/sbin/umount $zonepath/root
		if (( $? != 0 )); then
			# The umount failed, leave the old BE mounted.  If
			# there are zone processes (i.e. zsched) in the fs,
			# then we're umounting because we failed validation
			# during boot, otherwise, warn about gz process
			# preventing umount.
			nproc=`pgrep -z $zonename | wc -l`
			if (( $nproc == 0 )); then
                       		printf "$f_zfs_unmount" "$zonepath/root"
			fi
			return
		fi
	fi

	# Mount active dataset on the root.
	get_zonepath_ds $zonepath
	get_active_ds $ZONEPATH_DS

	/usr/sbin/mount -F zfs $ACTIVE_DS $zonepath/root || \
	    fail_fatal "$f_zfs_mount"
}

#
# Set up ZFS dataset hierarchy for the zone root dataset.
#
create_active_ds() {
	# Find the zone's current dataset.  This should have been created by
	# zoneadm (or the attach hook).
	get_zonepath_ds $zonepath

	#
	# We need to tolerate errors while creating the datasets and making the
	# mountpoint, since these could already exist from an attach scenario.
	#

	/usr/sbin/zfs list -H -o name $ZONEPATH_DS/ROOT >/dev/null 2>&1
	if (( $? != 0 )); then
		/usr/sbin/zfs create -o mountpoint=legacy -o zoned=on \
		    $ZONEPATH_DS/ROOT
		if (( $? != 0 )); then
			fail_fatal "$f_zfs_create"
		fi
	else
	       	/usr/sbin/zfs set mountpoint=legacy $ZONEPATH_DS/ROOT \
		    >/dev/null 2>&1
	       	/usr/sbin/zfs set zoned=on $ZONEPATH_DS/ROOT \
		    >/dev/null 2>&1
	fi

	BENAME=zbe-0
	/usr/sbin/zfs list -H -o name $ZONEPATH_DS/ROOT/$BENAME >/dev/null 2>&1
	if (( $? != 0 )); then
	       	/usr/sbin/zfs create -o $PROP_ACTIVE=on -o canmount=noauto \
		    $ZONEPATH_DS/ROOT/$BENAME >/dev/null 2>&1
		if (( $? != 0 )); then
			fail_fatal "$f_zfs_create"
		fi
	else
	       	/usr/sbin/zfs set $PROP_ACTIVE=on $ZONEPATH_DS/ROOT/$BENAME \
		    >/dev/null 2>&1
	       	/usr/sbin/zfs set canmount=noauto $ZONEPATH_DS/ROOT/$BENAME \
		    >/dev/null 2>&1
	       	/usr/sbin/zfs inherit mountpoint $ZONEPATH_DS/ROOT/$BENAME \
		    >/dev/null 2>&1
	       	/usr/sbin/zfs inherit zoned $ZONEPATH_DS/ROOT/$BENAME \
		    >/dev/null 2>&1
	fi

	if [ ! -d $ZONEROOT ]; then
		/usr/bin/mkdir -m 0755 -p $ZONEROOT || \
		    fail_fatal "$f_mkdir" "$ZONEROOT"
	fi
	/usr/bin/chmod 700 $ZONEPATH || fail_fatal "$f_chmod" "$ZONEPATH"

	/usr/sbin/mount -F zfs $ZONEPATH_DS/ROOT/$BENAME $ZONEROOT || \
		fail_fatal "$f_zfs_mount"
}

#
# Before booting the zone we may need to create a few mnt points, just in
# case they don't exist for some reason.
#
# Whenever we reach into the zone while running in the global zone we
# need to validate that none of the interim directories are symlinks
# that could cause us to inadvertently modify the global zone.
#
mk_zone_dirs() {
	vlog "$v_mkdirs"
	if [[ ! -f $ZONEROOT/tmp && ! -d $ZONEROOT/tmp ]]; then
		mkdir -m 1777 -p $ZONEROOT/tmp || exit $EXIT_CODE
	fi
	if [[ ! -f $ZONEROOT/var/run && ! -d $ZONEROOT/var/run ]]; then
		mkdir -m 1755 -p $ZONEROOT/var/run || exit $EXIT_CODE
	fi
	if [[ ! -f $ZONEROOT/var/tmp && ! -d $ZONEROOT/var/tmp ]]; then
		mkdir -m 1777 -p $ZONEROOT/var/tmp || exit $EXIT_CODE
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
	if [[ ! -h $ZONEROOT/etc && ! -h $ZONEROOT/etc/svc && \
	    ! -d $ZONEROOT/etc/svc ]]; then
		mkdir -m 755 -p $ZONEROOT/etc/svc/volatile || exit $EXIT_CODE
	fi
}

#
# We're sys-unconfig-ing the zone.  This will normally halt the zone, however
# there are problems with sys-unconfig and it can hang when the zone is booted
# to milestone=none.  Sys-unconfig also sometimes hangs halting the zone.
# Thus, we take some care to workaround these sys-unconfig limitations.
#
# On entry we expect the zone to be booted.  We use sys-unconfig -R to make it
# think its working on an alternate root and let the caller halt the zone.
#
sysunconfig_zone() {
	/usr/sbin/zlogin -S $ZONENAME /usr/sbin/sys-unconfig -R /./ \
	    >/dev/null 2>&1
	if (( $? != 0 )); then
		error "$e_unconfig"
		return 1
	fi

	return 0
}

#
# Get zone's uuid for service tag.
#
get_inst_uuid()
{
        typeset ZONENAME="$1"

	ZONEUUID=`zoneadm -z $ZONENAME list -p | nawk -F: '{print $5}'`
	[[ $? -ne 0 || -z $ZONEUUID ]] && return 1

	INSTANCE_UUID="urn:st:${ZONEUUID}"
	return 0
}

#
# Add a service tag for a given zone.  We use two UUIDs-- the first,
# the Product UUID, comes from the Sun swoRDFish ontology.  The second
# is the UUID of the zone itself, which forms the instance UUID.
#
add_svc_tag()
{
        typeset ZONENAME="$1"
        typeset SOURCE="$2"

	if [ ! -x $STCLIENT ]; then
		vlog "$v_no_tags"
		return 0
	fi

	get_inst_uuid "$ZONENAME" || (error "$e_bad_uuid"; return 1)

	vlog "$v_addtag" "$INSTANCE_UUID"
	$STCLIENT -a \
	    -p "$ST_PRODUCT_NAME" \
	    -e "$ST_PRODUCT_REV" \
	    -t "$ST_PRODUCT_UUID" \
	    -i "$INSTANCE_UUID" \
	    -P "none" \
	    -m "Sun" \
	    -A `uname -p` \
	    -z "$ZONENAME" \
	    -S "$SOURCE" >/dev/null 2>&1

	err=$?

	# 226 means "duplicate record," which we can ignore.
	if [[ $err -ne 0 && $err -ne 226 ]]; then
		error "$e_addtag_fail" "$err" 
		return 1
	fi
	return 0
}

#
# Remove a service tag for a given zone.
#
del_svc_tag()
{
        typeset ZONENAME="$1"

	if [ ! -x $STCLIENT ]; then
		vlog "$v_no_tags"
		return 0
	fi

	get_inst_uuid "$ZONENAME" || (error "$e_bad_uuid"; return 1)

	vlog "$v_deltag" "$INSTANCE_UUID"
        $STCLIENT -d -i "$INSTANCE_UUID" >/dev/null 2>&1
	return 0
}
