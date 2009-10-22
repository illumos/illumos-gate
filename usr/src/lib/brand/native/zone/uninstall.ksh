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

#
# get script name (bname)
#
bname=`basename $0`

#
# common shell script functions
#
. /usr/lib/brand/shared/common.ksh

#
# error messages
#
m_usage=$(gettext "Usage: %s: [-hFn]")

m_1_zfs_promote=$(gettext "promoting '%s'.")
m_1_zfs_destroy=$(gettext "destroying '%s'.")
m_2_zfs_rename=$(gettext "renaming '%s' to '%s'.")
m_3_zfs_set=$(gettext "setting property %s='%s' for '%s'.")
m_rm_r=$(gettext "recursively deleting '%s'.")
m_rm=$(gettext "deleting '%s'.")

w_no_ds=$(gettext "Warning: no zonepath dataset found.")

f_usage_err=$(gettext "Error: invalid usage")
f_abort=$(gettext "Error: internal error detected, aborting.")
f_1_zfs_promote=$(gettext "Error: promoting ZFS dataset '%s'.")
f_2_zfs_rename=$(gettext "Error: renaming ZFS dataset '%s' to '%s'.")
f_3_zfs_set=$(gettext "Error: setting ZFS propery %s='%s' for '%s'.")
f_1_zfs_destroy=$(gettext "Error: destroying ZFS dataset.")
f_2_zfs_get=$(gettext "Error: reading ZFS dataset property '%s' from '%s'.")
f_user_snap=$(gettext "Error: user snapshot(s) detected.")
f_stray_snap=$(gettext "Error: uncloned snapshot(s) detected.")
f_stray_clone=$(gettext "Error: cloned zone datasets found outsize of zone.")
f_rm_snap=$(gettext "Error: please delete snapshot(s) and retry uninstall.")
f_rm_clone=$(gettext "Error: please delete clone(s) and retry uninstall.")
f_iu_clone=$(gettext "Error: cloned zone dataset(s) in use.")
f_dis_clone=$(gettext "Error: please stop using clone(s) and retry uninstall.")

#
# functions
#
print_array()
{
	typeset -n pa_array=$1

	(( pa_i = 0 ))
	while (( $pa_i < ${#pa_array[@]} )); do
		printf "\t${pa_array[$pa_i]}\n"
		(( pa_i = $pa_i + 1 ))
	done
}

usage()
{
	printf "$m_usage\n" "$bname"
	exit $ZONE_SUBPROC_USAGE
}

usage_err()
{
	printf "$f_usage_err\n" >&2
	usage >&2
}

rm_zonepath()
{
	# cleanup stuff we know about and leave any user data alone

	[[ -z "$opt_n" ]] && [[ -n "$opt_v" ]] &&
		printf "$m_rm\n" "$zonepath/SUNWattached.xml"
	$nop /bin/rm -f "$zonepath/SUNWattached.xml"

	[[ -z "$opt_n" ]] && [[ -n "$opt_v" ]] &&
		printf "$m_rm_r\n" "$zonepath/lu"
	$nop /bin/rm -rf "$zonepath/lu"

	[[ -z "$opt_n" ]] && [[ -n "$opt_v" ]] &&
		printf "$m_rm_r\n" "$zonepath/dev"
	$nop /bin/rm -rf "$zonepath/dev"

	[[ -z "$opt_n" ]] && [[ -n "$opt_v" ]] &&
		printf "$m_rm_r\n" "$zonepath/root"
	$nop /bin/rm -rf "$zonepath/root"

	[[ -z "$opt_n" ]] && [[ -n "$opt_v" ]] &&
		printf "$m_rm\n" "$zonepath"
	$nop /bin/rmdir "$zonepath" 2>/dev/null
}

zfs_destroy()
{
	zd_fs1="$1"

	# first figure out if the target fs has an origin snapshot
	zd_origin=`/sbin/zfs get -H -o value origin "$zd_fs1"`
	if [[ $? != 0 ]]; then
		printf "$f_2_zfs_get\n" origin "$zd_fs1" >&2
		exit $ZONE_SUBPROC_FATAL
	fi

	[[ -z "$opt_n" ]] && [[ -n "$opt_v" ]] &&
		printf "$m_1_zfs_destroy\n" "$zd_fs1"

	#
	# note that we specify the '-r' flag so that we destroy any
	# descendants (filesystems and snapshot) of the specified
	# filesystem.
	#
	$nop /sbin/zfs destroy -r "$zd_fs1"
	if [[ $? != 0 ]]; then
		printf "$f_1_zfs_destroy\n" "$zd_fs1" >&2
		exit $ZONE_SUBPROC_FATAL
	fi

	[[ "$zd_origin" == "-" ]] && return

	[[ -z "$opt_n" ]] && [[ -n "$opt_v" ]] &&
		printf "$m_1_zfs_destroy\n" "$zd_origin"

	$nop /sbin/zfs destroy "$zd_origin" 2>/dev/null
	#
	# we ignore errors while trying to destroy the origin since
	# the origin could have been used as the source for other
	# clones
	#
}

zfs_promote()
{
	zp_fs1="$1"

	[[ -z "$opt_n" ]] &&
		printf "$m_1_zfs_promote\n" "$zp_fs1"

	$nop /sbin/zfs promote "$zp_fs1"
	if [[ $? != 0 ]]; then
		printf "$f_1_zfs_promote\n" "$zp_fs1" >&2
		exit $ZONE_SUBPROC_FATAL
	fi
}

zfs_rename()
{
	zr_fs1="$1"
	zr_fs2="$2"

	[[ -z "$opt_n" ]] &&
		printf "$m_2_zfs_rename\n" "$zr_fs1" "$zr_fs2"

	$nop /sbin/zfs rename "$zr_fs1" "$zr_fs2"
	if [[ $? != 0 ]]; then
		printf "$f_2_zfs_rename\n" "$zr_fs1" "$zr_fs2" >&2
		return 1
	fi
	return 0
}

zfs_set()
{
	zs_prop=$1
	zs_value=$2
	zs_fs1=$3

	[[ -z "$opt_n" ]] && [[ -n "$opt_v" ]] &&
		printf "$m_3_zfs_set\n" "$zs_prop" "$zs_value" "$zs_fs1"

	$nop /sbin/zfs set "$zs_prop"="$zs_value" "$zs_fs1"
	if [[ $? != 0 ]]; then
		printf "$f_3_zfs_set\n" "$zs_prop" "$zs_value" "$zs_fs1"
		return 1
	fi
	return 0
}

zfs_set_array()
{
	zsa_prop=$1
	zsa_value=$2
	typeset -n zsa_array=$3
	zsa_ignore_errors=$4

	(( zsa_i = 0 ))
	while (( $zsa_i < ${#zsa_array[@]} )); do
		zfs_set "$zsa_prop" "$zsa_value" "${zsa_array[$zsa_i]}"
		[[ $? != 0 ]] && [[ -z "$zsa_ignore_errors" ]] &&
			return 1
		(( zsa_i = $zsa_i + 1 ))
	done
	return 0
}


(( snap_rename_zbe_i = 1 ))
(( snap_rename_snap_i = 1 ))
snap_rename_init()
{
	(( snap_rename_zbe_i = 1 ))
	(( snap_rename_snap_i = 1 ))
}

snap_rename()
{
	eval sr_fs=\${$1}
	eval sr_snap=\${$2}

	if [[ "$sr_snap" == ~(Elr)(zbe-[0-9][0-9]*) ]]; then
		sr_snap="zbe-$snap_rename_zbe_i"
		(( snap_rename_zbe_i = $snap_rename_zbe_i + 1 ))
	elif [[ "$sr_snap" == ~(Er)(_snap[0-9]*) ]]; then
		sr_snap=${sr_snap##~(Er)([0-9]*)}
		sr_snap="${sr_snap}${snap_rename_snap_i}"
		(( snap_rename_snap_i = $snap_rename_snap_i + 1 ))
	else
		printf "$f_user_snap\n" >&2
		printf "\t$sr_fs@$sr_snap\n" >&2
		printf "$f_rm_snap\n" >&2
		exit $ZONE_SUBPROC_FATAL
	fi

	eval $2="$sr_snap"
}

# find the dataset associated with $zonepath
uninstall_get_zonepath_ds()
{
	ZONEPATH_DS=`/sbin/zfs list -t filesystem -o name,mountpoint | \
	    /bin/nawk -v zonepath=$zonepath '{
		if ($2 == zonepath)
			print $1
	}'`

	if [ -z "$ZONEPATH_DS" ]; then
		# there is no $zonepath dataset
		rm_zonepath
		exit $ZONE_SUBPROC_OK
	fi
}

# find the dataset associated with $ZONEPATH_DS/ROOT
uninstall_get_zonepath_root_ds()
{
	ZONEPATH_RDS=`/sbin/zfs list -H -t filesystem -o name \
		$ZONEPATH_DS/ROOT 2>/dev/null`

	if [ -z "$ZONEPATH_RDS" ]; then
		# there is no $ZONEPATH_DS/ROOT dataset
		c=`/sbin/zfs list -H -t filesystem -r $ZONEPATH_DS | wc -l`
		if [ $c = 1 ]; then
			# $zonepath dataset has no descendents
			zfs_destroy "$ZONEPATH_DS"
		fi
		rm_zonepath
		exit $ZONE_SUBPROC_OK
	fi
}

destroy_zone_dataset()
{
	fs=$1

	pool=${fs%%/*}

	# Fastpath.  if there are no snapshots of $fs then just delete it.
	c=`/sbin/zfs list -H -t snapshot -o name -r $fs | grep "^$fs@" |
	    LC_ALL=C LANG=C wc -l`
	if (( $c == 0 )) ; then
		zfs_destroy "$fs"
		return
	fi

	#
	# This zone BE has snapshots.  This can happen if a zone has
	# multiple BEs (in which case we have snapshots named "zbe-XXX"),
	# if this zone has been used as the source for a clone of
	# another zone (in which case we have snapshots named
	# "XXX_snap"), or if an administrator has been doing manual
	# snapshotting.
	#
	# To be able to destroy this dataset (which we'll call the
	# origin) we need to get rid of all it's snapshots.  The "easiest"
	# way to do this is to:
	#
	# - delete any uncloned origin snapshots
	# - find the oldest clone of the youngest origin snapshot (which
	#   we'll call the oldest clone)
	# - check if there are any snapshots naming conflicts between
	#   the origin and the oldest clone.
	# - if so, find any clones of those conflicting origin snapshots
	# - make sure that those clones are not zoned an in-use.
	# - if any of those clones are zoned, unzone them.
	# - rename origin snapshots to eliminate naming conflicts
	# - for any clones that we unzoned, rezone them.
	# - promote the oldest clone
	# - destroy the origin and all it's descendants
	#

	#
	# Get a list of all the cloned datasets within the zpool
	# containing the origin filesystem.  Filter out any filesystems
	# that are descendants of origin because we are planning to
	# destroy them anyway.
	#
	unset clones clones_origin
	(( clones_c = 0 ))
	pool=${fs%%/*}
	LANG=C LC_ALL=C /sbin/zfs list -H -t filesystem -s creation \
	    -o name,origin -r "$pool" |
	    while IFS="	" read name origin; do

		# skip non-clone filesystems
		[[ "$origin" == "-" ]] &&
			continue

		# skip desendents of the origin we plan to destroy
		[[ "$name" == ~()(${fs}/*) ]] &&
			continue

		# record this clone and it's origin
		clones[$clones_c]="$name"
		clones_origin[$clones_c]="$origin"
		(( clones_c = $clones_c + 1 ))
	done

	#
	# Now do a sanity check.  Search for clones of a child datasets
	# of the dataset we want to destroy, that are not themselves
	# children of the dataset we're going to destroy).  This should
	# really never happen unless the global zone admin has cloned a
	# snapshot of a zone filesystem to a location outside of that
	# zone.  bad admin...
	#
	unset stray_clones
	(( stray_clones_c = 0 ))
	(( j = 0 ))
	while (( $j < $clones_c )); do
		# is the clone origin a descendant of $fs?
		if [[ "${clones_origin[$j]}" != ~()(${fs}/*) ]]; then
			# we don't care.
			(( j = $j + 1 ))
			continue
		fi
		stray_clones[$stray_clones_c]=${clones[$j]}
		(( stray_clones_c = $stray_clones_c + 1 ))
		(( j = $j + 1 ))
	done
	if (( stray_clones_c > 0 )); then
		#
		# sigh.  the admin has done something strange.
		# tell them to clean it up and retry.
		#
		printf "$f_stray_clone\n" >&2
		print_array stray_clones >&2
		printf "$f_rm_clone\n" >&2
		exit $ZONE_SUBPROC_FATAL
	fi

	# Find all the snapshots of the origin filesystem.
	unset s_origin
	(( s_origin_c = 0 ))
	/sbin/zfs list -H -t snapshot -s creation -o name -r $fs |
	    grep "^$fs@" | while read name; do
		s_origin[$s_origin_c]=$name
		(( s_origin_c = $s_origin_c + 1 ))
	done

	#
	# Now go through the origin snapshots and find those which don't
	# have clones.  We're going to explicity delete these snapshots
	# before we do the promotion.
	#
	unset s_delete
	(( s_delete_c = 0 ))
	(( j = 0 ))
	while (( $j < $s_origin_c )); do
		(( k = 0 ))
		while (( $k < $clones_c )); do
			# if we have a match then break out of this loop
			[[ "${s_origin[$j]}" == "${clones_origin[$k]}" ]] &&
				break
			(( k = $k + 1 ))
		done
		if (( $k != $clones_c )); then
			# this snapshot has a clone, move on to the next one
			(( j = $j + 1 ))
			continue
		fi

		# snapshot has no clones so add it to our delete list
		s_delete[$s_delete_c]=${s_origin[$j]}
		(( s_delete_c = $s_delete_c + 1 ))
		# remove it from the origin snapshot list
		(( k = $j + 1 ))
		while (( $k < $s_origin_c )); do
			s_origin[(( $k - 1 ))]=${s_origin[$k]}
			(( k = $k + 1 ))
		done
		(( s_origin_c = $s_origin_c - 1 ))
	done

	#
	# Fastpath.  If there are no remaining snapshots then just
	# delete the origin filesystem (and all it's descendents) and
	# move onto the next zone BE.
	#
	if (( $s_origin_c == 0 )); then
		zfs_destroy "$fs"
		return
	fi

	# find the youngest snapshot of $fs
	s_youngest=${s_origin[(( $s_origin_c - 1 ))]}

	# Find the oldest clone of the youngest snapshot of $fs
	unset s_clone
	(( j = $clones_c - 1 ))
	while (( $j >= 0 )); do
		if [[ "$s_youngest" == "${clones_origin[$j]}" ]]; then
			s_clone=${clones[$j]}
			break
		fi
		(( j = $j - 1 ))
	done
	if [[ -z "$s_clone" ]]; then
		# uh oh.  something has gone wrong.  bail.
		printf "$f_stray_snap\n" >&2
		printf "\t$s_youngest\n" >&2
		printf "$f_rm_snap\n" >&2
		exit $ZONE_SUBPROC_FATAL
	fi

	# create an array of clone snapshot names
	unset s_clone_s
	(( s_clone_s_c = 0 ))
	/sbin/zfs list -H -t snapshot -s creation -o name -r $s_clone |
	    grep "^$s_clone@" | while read name; do
		s_clone_s[$s_clone_s_c]=${name##*@}
		(( s_clone_s_c = $s_clone_s_c + 1 ))
	done

	# create an arrays of possible origin snapshot renames
	unset s_origin_snap
	unset s_rename
	(( j = 0 ))
	while (( $j < $s_origin_c )); do
		s_origin_snap[$j]=${s_origin[$j]##*@}
		s_rename[$j]=${s_origin[$j]##*@}
		(( j = $j + 1 ))
	done

	#
	# Search for snapshot name collisions between the origin and
	# oldest clone.  If we find one, generate a new name for the
	# origin snapshot and re-do the collision check.
	#
	snap_rename_init
	(( j = 0 ))
	while (( $j < $s_origin_c )); do
		(( k = 0 ))
		while (( $k < $s_clone_s_c )); do

			# if there's no naming conflict continue
			if [[ "${s_rename[$j]}" != "${s_clone_s[$k]}" ]]; then
				(( k = $k + 1 ))
				continue
			fi

			#
			# The origin snapshot conflicts with a clone
			# snapshot.  Choose a new name and then restart
			# then check that against clone snapshot names.
			#
			snap_rename fs "s_rename[$j]"
			(( k = 0 ))
			continue;
		done

		# if we didn't rename this snapshot then continue
		if [[ "${s_rename[$j]}" == "${s_origin_snap[$j]}" ]]; then
			(( j = $j + 1 ))
			continue
		fi

		#
		# We need to rename this origin snapshot because it
		# conflicts with a clone snapshot name.  So above we
		# chose a name that didn't conflict with any other clone
		# snapshot names.  But we also have to avoid naming
		# conflicts with any other origin snapshot names.  So
		# check for that now.
		#
		(( k = 0 ))
		while (( $k < $s_origin_c )); do

			# don't compare against ourself
			if (( $j == $k )); then
				(( k = $k + 1 ))
				continue
			fi

			# if there's no naming conflict continue
			if [[ "${s_rename[$j]}" != "${s_rename[$k]}" ]]; then
				(( k = $k + 1 ))
				continue
			fi

			#
			# The new origin snapshot name conflicts with
			# another origin snapshot name.  Choose a new
			# name and then go back to check the new name
			# for uniqueness against all the clone snapshot
			# names.
			#
			snap_rename fs "s_rename[$j]"
			continue 2;
		done

		#
		# A new unique name has been chosen.  Move on to the
		# next origin snapshot.
		#
		(( j = $j + 1 ))
		snap_rename_init
	done

	#
	# So now we know what snapshots need to be renamed before the
	# promotion.  But there's an additional problem.  If any of the
	# filesystems cloned from these snapshots have the "zoned"
	# attribute set (which is highly likely) or if they are in use
	# (and can't be unmounted and re-mounted) then the snapshot
	# rename will fail.  So now we'll search for all the clones of
	# snapshots we plan to rename and look for ones that are zoned.
	#
	# We'll ignore any snapshot clones that may be in use but are
	# not zoned.  If these clones are in-use, the rename will fail
	# and we'll abort, there's not much else we can do about it.
	# But if they are not in use the snapshot rename will unmount
	# and remount the clone.  This is ok because when the zoned
	# attribute is off, we know that the clone was originally
	# mounted from the global zone.  (So unmounting and remounting
	# it from the global zone is ok.)
	#
	# But we'll abort this whole operation if we find any clones
	# that that are zoned and in use.  (This can happen if another
	# zone has been cloned from this one and is now booted.)  The
	# reason we do this is because those zoned filesystems could
	# have originally mounted from within the zone.  So if we
	# cleared the zone attribute and did the rename, we'd be
	# remounting the filesystem from the global zone.  This would
	# result in the zone losing the ability to unmount the
	# filesystem, which would be bad.
	#
	unset zoned_clones zoned_iu_clones
	(( zoned_clones_c = 0 ))
	(( zoned_iu_clones_c = 0 ))
	(( j = 0 ))
	# walk through all the clones
	while (( $j < $clones_c )); do
		# walk through all the origin snapshots
		(( k = 0 ))
		while (( $k < $s_origin_c )); do
			#
			# check if this clone originated from a snapshot that
			# we need to rename.
			#
			[[ "${clones_origin[$j]}" == "${s_origin[$k]}" ]] &&
			    [[ "${s_origin_snap[$k]}" != "${s_rename[$k]}" ]] &&
				break
			(( k = $k + 1 ))
			continue
		done
		if (( $k == $s_origin_c )); then
			# This isn't a clone of a snapshot we want to rename.
			(( j = $j + 1 ))
			continue;
		fi

		# get the zoned attr for this clone.
		zoned=`LC_ALL=C LANG=C \
		    /sbin/zfs get -H -o value zoned ${clones[$j]}`
		if [[ "$zoned" != on ]]; then
			# This clone isn't zoned so ignore it.
			(( j = $j + 1 ))
			continue
		fi

		# remember this clone so we can muck with it's zoned attr.
		zoned_clones[$zoned_clones_c]=${clones[$j]}
		(( zoned_clones_c = $zoned_clones_c + 1 ))

		# check if it's in use
		mounted=`LC_ALL=C LANG=C \
		    /sbin/zfs get -H -o value mounted ${clones[$j]}`
		if [[ "$mounted" != yes ]]; then
			# Good news.  This clone isn't in use.
			(( j = $j + 1 ))
			continue
		fi

		# Sigh.  This clone is in use so we're destined to fail.
		zoned_iu_clones[$zoned_iu_clones_c]=${clones[$j]}
		(( zoned_iu_clones_c = $zoned_iu_clones_c + 1 ))

		# keep looking for errors so we can report them all at once.
		(( j = $j + 1 ))
	done
	if (( zoned_iu_clones_c > 0 )); then
		#
		# Tell the admin
		#
		printf "$f_iu_clone\n" >&2
		print_array zoned_iu_clones >&2
		printf "$f_dis_clone\n" >&2
		exit $ZONE_SUBPROC_FATAL
	fi

	#
	# Ok.  So we're finally done with planning and we can do some
	# damage.  We're going to:
	# - destroy unused snapshots
	# - unzone clones which originate from snapshots we need to rename
	# - rename conflicting snapshots
	# - rezone any clones which we unzoned
	# - promote the oldest clone of the youngest snapshot
	# - finally destroy the origin filesystem.
	#

	# delete any unsed snapshot
	(( j = 0 ))
	while (( $j < $s_delete_c )); do
		zfs_destroy "${s_delete[$j]}"
		(( j = $j + 1 ))
	done

	# unzone clones
	zfs_set_array zoned off zoned_clones ||
		zfs_set_array zoned on zoned_clones 1

	# rename conflicting snapshots
	(( j = 0 ))
	while (( $j < $s_origin_c )); do
		if [[ "${s_origin_snap[$j]}" != "${s_rename[$j]}" ]]; then
			zfs_rename "${s_origin[$j]}" "$fs@${s_rename[$j]}"
			if [[ $? != 0 ]]; then
				# re-zone the clones before aborting
				zfs_set_array zoned on zoned_clones 1
				exit $ZONE_SUBPROC_FATAL
			fi
		fi
		(( j = $j + 1 ))
	done

	# re-zone the clones
	zfs_set_array zoned on zoned_clones 1

	# promote the youngest clone of the oldest snapshot
	zfs_promote "$s_clone"

	# destroy the origin filesystem and it's descendants
	zfs_destroy "$fs"
}

#
# This function expects an array named fs_all to exist which is initialized
# with the zone's ZFS datasets that should be destroyed.  fs_all_c is the
# count of the number of elements in the array.  ZONEPATH_RDS is the
# zonepath/root dataset and ZONEPATH_DS is the zonepath dataset.
#
destroy_zone_datasets()
{
	# Destroy the zone BEs datasets one by one.
	(( i = 0 ))
	while (( $i < $fs_all_c )); do
		fs=${fs_all[$i]}

		destroy_zone_dataset "$fs"
		(( i = $i + 1 ))
	done

	#
	# Check if there are any other datasets left.  There may be datasets
	# associated with other GZ BEs, so we need to leave things alone in
	# that case.
	#
	c=`/sbin/zfs list -H -t filesystem -r $ZONEPATH_RDS | wc -l`
	if [ $c = 1 ]; then
		zfs_destroy "$ZONEPATH_RDS"
	fi
	c=`/sbin/zfs list -H -t filesystem -r $ZONEPATH_DS | wc -l`
	if [ $c = 1 ]; then
		zfs_destroy "$ZONEPATH_DS"
	fi

	rm_zonepath
}
