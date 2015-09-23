#!/sbin/sh -p
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
# Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2015 Nexenta Systems, Inc. All rights reserved.
#
#
PATH=/usr/bin:/usr/sbin:$PATH; export PATH
STMSBOOTUTIL=/lib/mpxio/stmsboot_util
STMSMETHODSCRIPT=/lib/svc/method/mpxio-upgrade
KDRVCONF=
DRVCONF=
TMPDRVCONF=
TMPDRVCONF_MPXIO_ENTRY=
TMPDRVCONF_SATA_ENTRY=
DRVLIST=
GUID=
VFSTAB=/etc/vfstab
SAVEDIR=/etc/mpxio
BOOTDEVICES=$SAVEDIR/boot-devices
RECOVERFILE=$SAVEDIR/recover_instructions
SVCCFG_RECOVERY=$SAVEDIR/svccfg_recover
SUPPORTED_DRIVERS="fp|mpt|mpt_sas|pmcs"
USAGE=`gettext "Usage: stmsboot [-D $SUPPORTED_DRIVERS] -e | -d | -u | -L | -l controller_number"`
TEXTDOMAIN=SUNW_OST_OSCMD
export TEXTDOMAIN
STMSINSTANCE=svc:system/device/mpxio-upgrade:default
FASTBOOTINSTANCE=svc:system/boot-config:default
STMSBOOT=/usr/sbin/stmsboot
BOOTADM=/sbin/bootadm
MOUNT=/usr/sbin/mount
EEPROM=/usr/sbin/eeprom
EGREP=/usr/bin/egrep
GREP=/usr/bin/grep
AWK=/usr/bin/awk
CP=/usr/bin/cp
DF=/usr/bin/df
LS=/usr/bin/ls
MV=/usr/bin/mv
RM=/usr/bin/rm
SORT=/usr/bin/sort
UNIQ=/usr/bin/uniq
EXPR=/usr/bin/expr
MKDIR=/usr/bin/mkdir
REBOOT=/usr/sbin/reboot
SED=/usr/bin/sed
SVCPROP=/usr/bin/svcprop
SVCCFG=/usr/sbin/svccfg
SVCS=/usr/bin/svcs
SVCADM=/usr/sbin/svcadm

NOW=`/usr/bin/date +%G%m%d_%H%M`
MACH=`/usr/bin/uname -p`
BOOTENV_FILE=bootenv.rc
reboot_needed=0
new_bootpath=""
CLIENT_TYPE_PHCI=""
CLIENT_TYPE_VHCI="/scsi_vhci"

#
# Copy all entries (including comments) from source driver.conf
# to destination driver.conf except those entries which contain
# the mpxio-disable property.
# Take into consideration entries that spawn more than one line.
#
# $1	source driver.conf file
# $2	destination driver.conf file
#
# Returns 0 on success, non zero on failure.
#
delete_mpxio_disable_entries()
{
	# be careful here, we've got embedded \t characters
	# in sed's pattern space.
	$SED '
		/^[ 	]*#/{ p
			      d
			    }
		s/[ 	]*$//
		/^$/{ p
		      d
		    }
		/mpxio-disable[ 	]*=.*;$/{ w '$3'
						  d
						}
		/disable-sata-mpxio[ 	]*=.*;$/{ w '$4'
						  d
						}
		/;$/{ p
		      d
		    }
		:rdnext
		N
		s/[ 	]*$//
		/[^;]$/b rdnext
		/mpxio-disable[ 	]*=/{ s/\n/ /g
					      w '$3'
					      d
					    }
		' $1 > $2

	return $?
}

#
# backup the last saved copy of the specified files.
# $*	files to backup
#
backup_lastsaved()
{
	for file in $*
	do
		newfile=`basename $file`
		$CP $file $SAVEDIR/$newfile.$cmd.$NOW
	done
}

#
# build recover instructions
#
# $1	1 to include boot script in the instructions
#	0 otherwise
#
build_recover()
{
	gettext "Instructions to recover your previous STMS configuration (if in case the system does not boot):\n\n" > $RECOVERFILE
	echo "\tboot net \c"  >> $RECOVERFILE
	gettext "(or from a cd/dvd/another disk)\n" >> $RECOVERFILE
	echo "\tfsck <your-root-device>" >> $RECOVERFILE
	echo "\tmount <your-root-device> /mnt" >> $RECOVERFILE

	if [ "$cmd" = "update" ]; then
		gettext "\tUndo the modifications you made to STMS configuration.\n\tFor example undo any changes you made to " >> $RECOVERFILE
		echo "/mnt$KDRVCONF." >> $RECOVERFILE
	else
		echo "\tcp /mnt${SAVEDIR}/$DRVCONF.$cmd.$NOW /mnt$KDRVCONF" >> $RECOVERFILE
	fi

	if [ $1 -eq 1 ]; then
		echo "\tcp /mnt${SAVEDIR}/vfstab.$cmd.$NOW /mnt$VFSTAB" >> $RECOVERFILE

		echo "repository /mnt/etc/svc/repository.db" > $SVCCFG_RECOVERY
		echo "select $STMSINSTANCE" >> $SVCCFG_RECOVERY
		echo "setprop general/enabled=false" >> $SVCCFG_RECOVERY
		echo "exit" >> $SVCCFG_RECOVERY

		echo "\t$SVCCFG -f /mnt$SVCCFG_RECOVERY" >> $RECOVERFILE

		if [ -n "$new_bootpath" -a "$MACH" = "i386" ]; then
			echo "\tcp /mnt${SAVEDIR}/bootenv.rc.$cmd.$NOW /mnt/boot/solaris/$BOOTENV_FILE" >> $RECOVERFILE
		fi
	fi

	rootdisk=`$MOUNT | $GREP "/ on " | cut -f 3 -d " "`
	echo "\tumount /mnt\n\treboot\n\n${rootdisk} \c" >> $RECOVERFILE
	gettext "was your root device,\nbut it could be named differently after you boot net.\n" >> $RECOVERFILE
}


#
# Arrange for /etc/vfstab and dump configuration to be updated
# during the next reboot. If the cmd is "enable" or "disable", copy
# $TMPDRVCONF to $KDRVCONF.
#
# Returns 0 on success, 1 on failure.
#
update_sysfiles()
{

	gettext "WARNING: This operation will require a reboot.\n"
	gettext "Do you want to continue ? [y/n] (default: y) "
	read response

	if [ -n "$response" -a "$response" != "y" -a \
	    "$response" != "Y" ]; then
		for d in $DRVLIST; do
			TMPDRVCONF=/var/run/tmp.$d.conf.$$
			$RM -f $TMPDRVCONF > /dev/null 2>&1
		done;
		return 0;
	fi

	# set need_bootscript to the number of drivers that
	# we support.
	need_bootscript=`echo $SUPPORTED_DRIVERS|$AWK -F"|" '{print NF}'`

	if [ "$cmd" = "enable" -o "$cmd" = "disable" ]; then

		for d in $DRVLIST; do
			DRVCONF=$d.conf
			KDRVCONF=/kernel/drv/$d.conf
			TMPDRVCONF=/var/run/tmp.$d.conf.$$

			$CP $KDRVCONF $SAVEDIR/`basename $KDRVCONF`.$cmd.$NOW
			if [ -f $TMPDRVCONF ]; then
				$CP $TMPDRVCONF $KDRVCONF
				$RM -f $TMPDRVCONF
			else
				# if $TMPDRVCONF doesn't exist, then we
				# haven't made any changes to it
				continue;
			fi

			#
			# there is no need to update the system files in the following
			# cases:
			# - we are enabling mpxio and the system has no configured
			#   disks accessible by phci paths.
			# - we are disabling mpxio and the system has no configured
			#   disks accessible by vhci paths.
			#

			# Function to setup the CLIENT_TYPE_PHCI string based on
			# the list of drivers that we're operating on. The variable
			# depends upon the pathname of the parent node in the 
			# device tree, which can be different on x86/x64 and sparc.

			CLIENT_TYPE_PHCI=`$STMSBOOTUTIL -D $d -N`;

			if [ -z "$CLIENT_TYPE_PHCI" ]; then
				continue;
			fi

			if [ "$cmd" = "enable" ]; then
				$LS -l /dev/dsk/*s2 2> /dev/null | \
				    $EGREP -s "$CLIENT_TYPE_PHCI"
			else
				$LS -l /dev/dsk/*s2 2> /dev/null | \
				    $EGREP -s "$CLIENT_TYPE_VHCI"
			fi

			if [ $? -ne 0 ]; then
				need_bootscript=`$EXPR $need_bootscript - 1`
			fi
		done
	fi

	if [ $need_bootscript -gt 0 ]; then
		need_bootscript=1
		if [  -n "$new_bootpath" -a "$MACH" = "i386" ]; then
			#only update bootpath for x86.
			$CP /boot/solaris/$BOOTENV_FILE $SAVEDIR/$BOOTENV_FILE.$cmd.$NOW
			$EEPROM bootpath="$new_bootpath"
		fi

		if [ "$MACH" = "i386" ]; then
			# Disable Fast Reboot temporarily for the next reboot only.
			HASZFSROOT=`$DF -g / |$GREP zfs`
			if [ -n "$HASZFSROOT" ]; then
				$SVCCFG -s $FASTBOOTINSTANCE addpg config_ovr application P > /dev/null 2>&1
				$SVCCFG -s $FASTBOOTINSTANCE \
				    setprop config_ovr/fastreboot_default=boolean:\"false\"
				$SVCCFG -s $FASTBOOTINSTANCE \
				    setprop config_ovr/fastreboot_onpanic=boolean:\"false\"
				$SVCADM refresh $FASTBOOTINSTANCE 
			fi
		fi

		# Enable the mpxio-upgrade service for the reboot
		$SVCADM disable -t $STMSINSTANCE
		$SVCCFG -s $STMSINSTANCE "setprop general/enabled=true"
	else
		need_bootscript=0
	fi

	build_recover $need_bootscript

	if [ "$MACH" = "i386" ]; then
		$BOOTADM update-archive
	fi

	gettext "The changes will come into effect after rebooting the system.\nReboot the system now ? [y/n] (default: y) "
	read response

	if [ -z "$response" -o "$response" = "y" -o \
	    "$response" = "Y" ]; then
		$REBOOT
	fi

	return 0
}


#
# Enable or disable mpxio as specified by the cmd.
# Returns 0 on success, 1 on failure.
#
# Args: $cmd = {enable | disable}
#	$d = {fp | mpt | mpt_sas | pmcs}
#
# the global variable $DRVLIST is used
#
configure_mpxio()
{
	# be careful here, we've got embedded \t characters
	# in sed's pattern space.
	mpxiodisableno='mpxio-disable[ 	]*=[ 	]*"no"[ 	]*;'
	mpxiodisableyes='mpxio-disable[ 	]*=[ 	]*"yes"[ 	]*;'
	satadisableno='disable-sata-mpxio[ 	]*=[ 	]*"no"[ 	]*;'
	satadisableyes='disable-sata-mpxio[ 	]*=[ 	]*"yes"[ 	]*;'

	if [ "$cmd" = "enable" ]; then
		mpxiodisable_cur_entry=$mpxiodisableyes
		satadisable_cur_entry=$satadisableyes
		propval=no
		msg=`gettext "STMS already enabled"`
	else
		mpxiodisable_cur_entry=$mpxiodisableno
		satadisable_cur_entry=$satadisableno
		propval=yes
		msg=`gettext "STMS already disabled"`
	fi

	DRVCONF=$d.conf
	KDRVCONF=/kernel/drv/$d.conf
	TMPDRVCONF=/var/run/tmp.$d.conf.$$
	TMPDRVCONF_MPXIO_ENTRY=/var/run/tmp.$d.conf.mpxioentry.$$;
	TMPDRVCONF_SATA_ENTRY=/var/run/tmp.$d.conf.sataentry.$$;

	if delete_mpxio_disable_entries $KDRVCONF $TMPDRVCONF $TMPDRVCONF_MPXIO_ENTRY $TMPDRVCONF_SATA_ENTRY; then

		if [ -s $TMPDRVCONF_MPXIO_ENTRY ]; then
			# $DRVCONF does have mpxiodisable entries
			$EGREP -s "$mpxiodisable_cur_entry" $TMPDRVCONF_MPXIO_ENTRY
			if [ $? -eq 0 ]; then
				reboot_needed=`$EXPR $reboot_needed + 1`
			else
				# if all mpxiodisable entries are no/yes for
				# enable/disable mpxio, notify the user
				$EGREP -s "$satadisable_cur_entry" $TMPDRVCONF_SATA_ENTRY
				if [ $? -eq 0 -a "$d" = "mpt" ]; then
					reboot_needed=`$EXPR $reboot_needed + 1`
				else
					$RM -f $TMPDRVCONF $TMPDRVCONF_MPXIO_ENTRY $TMPDRVCONF_SATA_ENTRY > /dev/null 2>&1
					return 0;
				fi
			fi

			# If mpxiodisable entries do not exist, always continue update
		fi
	else
		$RM -f $TMPDRVCONF $TMPDRVCONF_MPXIO_ENTRY $TMPDRVCONF_SATA_ENTRY > /dev/null 2>&1
		gettext "failed to update " 1>&2
		echo "$KDRVCONF." 1>&2 
		gettext "No changes were made to your STMS configuration.\n" 1>&2
		return 1
	fi

	rm $TMPDRVCONF_MPXIO_ENTRY $TMPDRVCONF_SATA_ENTRY > /dev/null 2>&1
	echo "mpxio-disable=\"${propval}\";" >> $TMPDRVCONF
	if [ "$d" = "mpt" ]; then
		echo "disable-sata-mpxio=\"${propval}\";" >> $TMPDRVCONF
	fi

}

setcmd()
{
	if [ "$cmd" = "none" ]; then
		cmd=$1
	else
		echo "$USAGE" 1>&2
		exit 2
	fi
}

#
# Need to update bootpath on x86 if boot system from FC disk
# Only update bootpath here when mpxio is enabled
# If mpxio is currently disabled, then we'll update bootpath in the
# mpxio-upgrade service method on reboot.
#

get_newbootpath_for_stmsdev() {
	if [ "$cmd" = "enable" ]; then
		return 0
	fi

	cur_bootpath=`$STMSBOOTUTIL -b`
	if [ $? != 0 ]; then
		return 1
	fi

	# Since on x64 platforms the eeprom command doesn't update the
	# kernel, the file /boot/solaris/bootenv.rc and the kernel's
	# bootpath variable have a good chance of differing. We do some
	# extra handwaving to get the correct bootpath variable setting. 

	ONDISKVER=`$AWK '/bootpath/ {print $3}' /boot/solaris/bootenv.rc|\
		$SED -e"s,',,g"`
	if [ "$ONDISKVER" != "$cur_bootpath" ]; then
		cur_bootpath="$ONDISKVER"
	fi

	NEWBOOTPATH=""
	for path in $cur_bootpath; do
		mapped=`$STMSBOOTUTIL -p $path`
		if [ "$mapped" != "NOT_MAPPED" ]; then
			if [ "$mapped" != "$path" ]; then
				NEWBOOTPATH=`echo "$path " | \
				   $SED -e"s|$path|$mapped|"`" $NEWBOOTPATH"
			else
				NEWBOOTPATH="$NEWBOOTPATH $path"
			fi
		fi
	done
	# now strip off leading and trailing space chars
	new_bootpath=`echo $NEWBOOTPATH`
	return 0
}

#
# Emit a warning message to the user that by default we
# operate on all multipath-capable controllers that are
# attached to the system, and that if they want to operate
# on only a specific controller type (fp|mpt|mpt_sas|pmcs|....) then 
# they need to re-invoke stmsboot with "-D $driver" in
# their argument list
#

emit_driver_warning_msg() {

	# for each driver that we support, grab the list
	# of controllers attached to the system.

	echo ""
	gettext "WARNING: stmsboot operates on each supported multipath-capable controller\n"
	gettext "         detected in a host. In your system, these controllers are\n\n"

	for WARNDRV in `echo $SUPPORTED_DRIVERS| $SED -e"s,|, ,g"`; do
		$STMSBOOTUTIL -D $WARNDRV -n
	done;
	
	echo ""
	gettext "If you do NOT wish to operate on these controllers, please quit stmsboot\n"
	gettext "and re-invoke with -D { fp | mpt | mpt_sas | pmcs} to specify which controllers you wish\n"
	gettext "to modify your multipathing configuration for.\n"

	echo ""
	gettext "Do you wish to continue? [y/n] (default: y) " 
	read response

	if [ -n "$response" -a "$response" != "Y" -a \
	    "$response" != "y" ]; then
		exit
	fi
}


#
#
# main starts here
#

cmd=none
# process options
while getopts D:geduLl: c
do
	case $c in
	e)	setcmd enable;;
	d)	setcmd disable;;
	u)	setcmd update;;
	L)	setcmd listall;;
	l)	setcmd list
		controller=$OPTARG;;
	D)	DRV=$OPTARG;;
	g)	GUID="-g";;
	\?)	echo "$USAGE" 1>&2
		exit 2;;
	esac
done

if [ "$cmd" = "none" ]; then
	echo "$USAGE" 1>&2
	exit 2
fi

if [ -z "$DRV" ]; then
	DRVLIST="fp mpt mpt_sas pmcs"
else
	DRVLIST=$DRV
fi

USERID=`id | $EGREP "uid=0"`
if [ -z "$USERID" ]; then
	gettext "You must be super-user to run this script.\n" 1>&2
	exit 1
fi

# just a sanity check
if [ ! -f $STMSBOOTUTIL -o ! -f $STMSMETHODSCRIPT ]; then
	fmt=`gettext "Can't find %s and/or %s"`
	printf "$fmt\n" "$STMSBOOTUTIL" "$STMSMETHODSCRIPT" 1>&2
	exit 1
fi

# If the old sun4u-specific SMF method is found, remove it
$SVCCFG -s "platform/sun4u/mpxio-upgrade:default" < /dev/null > /dev/null 2>&1
if [ $? -eq 0 ]; then
	$SVCCFG delete "platform/sun4u/mpxio-upgrade:default" > /dev/null 2>&1
fi

# now import the new service, if necessary
$SVCPROP -q $STMSINSTANCE < /dev/null > /dev/null 2>&1
if [ $? -ne 0 ]; then
	if [ -f /lib/svc/manifest/system/device/mpxio-upgrade.xml ]; then
		$SVCCFG import /lib/svc/manifest/system/device/mpxio-upgrade.xml
		if [ $? -ne 0 ]; then

			fmt=`gettext "Unable to import the %s service"`
			printf "$fmt\n" "$STMSINSTANCE" 1>&2
			exit 1
		else
			fmt=`gettext "Service %s imported successfully, continuing"`
			printf "$fmt\n" "$STMSINSTANCE" 1>&2
		fi
	else
		fmt=`gettext "Service %s does not exist on this host"`
 		printf "$fmt\n" "$STMSINSTANCE" 1>&2
		exit 1
	fi
fi


# make sure we can stash our data somewhere private
if [ ! -d $SAVEDIR ]; then
	$MKDIR -p $SAVEDIR
fi
# prime the cache
$STMSBOOTUTIL -i


if [ "$cmd" = "enable" -o "$cmd" = "disable" -o "$cmd" = "update" ]; then
	if $MOUNT -v | $EGREP -s " on / type nfs "; then
		gettext "This command option is not supported on systems with an nfs mounted root filesystem.\n" 1>&2
		exit 1
	fi

	# if the user has left the system with the mpxio-upgrade service
	# in a temporarily disabled state (ie, service is armed for the next
	# reboot), then let them know. We need to ensure that the system is
	# is in a sane state before allowing any further invocations, so 
	# try to get the system admin to do so

	ISARMED=`$SVCS -l $STMSINSTANCE|$GREP "enabled.*false.*temporary"`
	if [ ! $? ]; then
		echo ""
		gettext "You need to reboot the system in order to complete\n"
		gettext "the previous invocation of stmsboot.\n"
		echo ""
		gettext "Do you wish to reboot the system now? (y/n, default y) "
		read response

		if [ -z "$response" -o "x$response" = "Y" -o \
		    "$response" = "y" ]; then
			$REBOOT
		else
			echo ""
			gettext "Please reboot this system before continuing\n"
			echo ""
			exit 1
		fi
	fi

	#
	# keep a copy of the last saved files, useful for manual
	# recovery in case of a problem.
	#
	for d in $DRVLIST; do
		DRVCONF=$d.conf
		KDRVCONF=/kernel/drv/$d.conf
		TMPDRVCONF=/var/run/tmp.$d.conf.$$
		TMPDRVCONF_MPXIO_ENTRY=/var/run/tmp.$d.conf.mpxioentry.$$;
		if [ "$MACH" = "sparc" ]; then
			backup_lastsaved $KDRVCONF $VFSTAB
		else
			backup_lastsaved $KDRVCONF $VFSTAB /boot/solaris/$BOOTENV_FILE
		fi
	done
fi

if [ "$cmd" = "enable" -o "$cmd" = "disable" ]; then

	msgneeded=`echo "$DRVLIST" |$GREP " "`
	if [ -n "$msgneeded" ]; then
		emit_driver_warning_msg
	fi
	for d in $DRVLIST; do
		configure_mpxio $cmd $d
	done

	if [ $reboot_needed -ne 0 ]; then
		# Need to update bootpath on x86 if our boot device is
		# now accessed through mpxio.
		# Only update bootpath before reboot when mpxio is enabled
		# If mpxio is currently disabled, we will update bootpath
		# on reboot in the mpxio-upgrade service
		
		if [ "$cmd" = "disable" ]; then
			if [ "$MACH" = "i386" ]; then
				get_newbootpath_for_stmsdev
				if [ $? -ne 0 ]; then
					$RM -f $TMPDRVCONF > /dev/null 2>&1
					gettext "failed to update bootpath.\n" 1>&2
					gettext "No changes were made to your STMS configuration.\n" 1>&2
					return 1
				fi
			fi
			# If we're not using ZFS root then we need
			# to keep track of what / maps to in case
			# it's an active-active device and we boot from
			# the other path
			HASZFSROOT=`$DF -g / |$GREP zfs`
			if [ -z "$HASZFSROOT" ]; then
				ROOTSCSIVHCI=`$DF /|$AWK -F":" '{print $1}' | \
					$AWK -F"(" '{print $2}'| $SED -e"s,),,"`
				TMPROOTDEV=`$LS -l $ROOTSCSIVHCI |$AWK -F">" '{print $2}' | \
					$SED -e"s, ../../devices,,"`
				$STMSBOOTUTIL -q $TMPROOTDEV > $BOOTDEVICES
			fi
		fi
		update_sysfiles
	else
		echo "STMS is already ${cmd}d. No changes or reboots needed"
	fi


elif [ "$cmd" = "update" ]; then
	if [ "$MACH" = "i386" ]; then
	# In this case we always change the bootpath to phci-based
	# path first. bootpath will later be modified in mpxio-upgrade
	# to the vhci-based path if mpxio is enabled on root.
		get_newbootpath_for_stmsdev
		if [ $? -ne 0 ]; then
			gettext "failed to update bootpath.\n" 1>&2
			return 1
		fi
	fi
	update_sysfiles

elif [ "$cmd" = "list" ]; then
		$STMSBOOTUTIL $GUID -l $controller
else
		$STMSBOOTUTIL $GUID -L
fi

exit $?
