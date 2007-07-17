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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

PATH=/usr/bin:/usr/sbin:$PATH; export PATH
STMSBOOTUTIL=/lib/mpxio/stmsboot_util
STMSMETHODSCRIPT=/lib/svc/method/mpxio-upgrade
KDRVCONF=
DRVCONF=
TMPDRVCONF=
TMPDRVCONF_MPXIO_ENTRY=
DRVLIST=
GUID=
VFSTAB=/etc/vfstab
SAVEDIR=/etc/mpxio
RECOVERFILE=$SAVEDIR/recover_instructions
SVCCFG_RECOVERY=$SAVEDIR/svccfg_recover
SUPPORTED_DRIVERS="fp|mpt"
USAGE=`gettext "Usage: stmsboot [-D $SUPPORTED_DRIVERS] -e | -d | -u | -L | -l controller_number"`
TEXTDOMAIN=SUNW_OST_OSCMD
export TEXTDOMAIN
STMSINSTANCE=system/device/mpxio-upgrade:default
STMSBOOT=/usr/sbin/stmsboot
BOOTADM=/sbin/bootadm
MOUNT=/usr/sbin/mount
EGREP=/usr/bin/egrep
GREP=/usr/bin/grep
AWK=/usr/bin/awk
SORT=/usr/bin/sort
UNIQ=/usr/bin/uniq
EXPR=/usr/bin/expr
SED=/usr/bin/sed
SVCPROP=/usr/bin/svcprop
SVCCFG=/usr/sbin/svccfg
SVCS=/usr/bin/svcs
SVCADM=/usr/sbin/svcadm

MACH=`/usr/bin/uname -p`
BOOTENV_FILE=/boot/solaris/bootenv.rc

CLIENT_TYPE_VHCI="/scsi_vhci.*/ssd@|/scsi_vhci.*/disk@"
# The phci client type egrep string will change based on the
# drivers which we are operating on, and the cpu architecture
# and we call stmsboot_util -n -D $drv to get that string
CLIENT_TYPE_PHCI=
reboot_needed=0

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
	sed '
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
		file=`basename $file`
		if [ -f $SAVEDIR/$file ]; then
			mv $SAVEDIR/$file $SAVEDIR/${file}.old
		fi
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

	if [ "x$cmd" = xupdate ]; then
		gettext "\tUndo the modifications you made to STMS configuration.\n\tFor example undo any changes you made to " >> $RECOVERFILE
		echo "/mnt$KDRVCONF." >> $RECOVERFILE
	else
		echo "\tcp /mnt${SAVEDIR}/$DRVCONF /mnt$KDRVCONF" >> $RECOVERFILE
	fi

	if [ $1 -eq 1 ]; then
		echo "\tcp /mnt${SAVEDIR}/vfstab /mnt$VFSTAB" >> $RECOVERFILE

		echo "repository /mnt/etc/svc/repository.db" > $SVCCFG_RECOVERY
		echo "select $STMSINSTANCE" >> $SVCCFG_RECOVERY
		echo "setprop general/enabled=false" >> $SVCCFG_RECOVERY
		echo "exit" >> $SVCCFG_RECOVERY

		echo "\t$SVCCFG -f /mnt$SVCCFG_RECOVERY" >> $RECOVERFILE

		if [ "x$MACH" = "xi386" -a "x$new_bootpath" != "x" ]; then
			echo "\tcp /mnt${SAVEDIR}/bootenv.rc /mnt$BOOTENV_FILE" >> $RECOVERFILE
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

	gettext "WARNING: This operation will require a reboot.\nDo you want to continue ? [y/n] (default: y) "
	read response

	if [ "x$response" != x -a "x$response" != xy -a \
	    "x$response" != xY ]; then
		for d in $DRVLIST; do
			TMPDRVCONF=/var/run/tmp.$d.conf.$$
			rm -f $TMPDRVCONF > /dev/null 2>&1
		done;
		return 0;
	fi

	# set need_bootscript to the number of drivers that
	# we support.
	need_bootscript=`echo $SUPPORTED_DRIVERS|$AWK -F"|" '{print NF}'`

	if [ "x$cmd" = xenable -o "x$cmd" = xdisable ]; then

		for d in $DRVLIST; do
			DRVCONF=$d.conf
			KDRVCONF=/kernel/drv/$d.conf
			TMPDRVCONF=/var/run/tmp.$d.conf.$$

			cp $KDRVCONF $SAVEDIR
			if [ -f $TMPDRVCONF ]; then
				cp $TMPDRVCONF $KDRVCONF
				rm -f $TMPDRVCONF
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

			CLIENT_TYPE_PHCI=`$STMSBOOTUTIL -D $d -n`;

			if [ "x$CLIENT_TYPE_PHCI" = "x" ]; then
				continue;
			fi

			if [ "x$cmd" = "xenable" ]; then
				ls -l /dev/dsk/*s2 2> /dev/null | \
				    $EGREP -s "$CLIENT_TYPE_PHCI"
			else
				ls -l /dev/dsk/*s2 2> /dev/null | \
				    $EGREP -s "$CLIENT_TYPE_VHCI"
			fi

			if [ $? -ne 0 ]; then
				need_bootscript=`$EXPR $need_bootscript - 1`
			fi
		done
	fi

	if [ $need_bootscript -gt 0 ]; then
		need_bootscript=1
		if [ "x$MACH" = "xi386" -a "x$new_bootpath" != "x" ]; then
			#only update bootpath for x86.
			cp $BOOTENV_FILE $SAVEDIR
			/usr/sbin/eeprom bootpath=$new_bootpath
		fi
		#
		# Enable the mpxio-upgrade service, but don't run it now.
		# The service will run during the next reboot and will do
		# the actual job of modifying the system files.
		#
		$SVCADM disable -t $STMSINSTANCE
		$SVCCFG -f - << EOF
select $STMSINSTANCE
setprop general/enabled = true
EOF
	else
		need_bootscript=0
	fi

	build_recover $need_bootscript

	if [ "x$MACH" = "xi386" ]; then
		$BOOTADM update-archive
	fi

	gettext "The changes will come into effect after rebooting the system.\nReboot the system now ? [y/n] (default: y) "
	read response

	if [ "x$response" = x -o "x$response" = xy -o \
	    "x$response" = xY ]; then
		/usr/sbin/reboot
	fi

	return 0
}

#
# Enable or disable mpxio as specified by the cmd.
# Returns 0 on success, 1 on failure.
#
# Args: $cmd = {enable | disable}
#	$d = {fp | mpt}
#
# the global variable $DRVLIST is used
#
configure_mpxio()
{
	mpxiodisableno='mpxio-disable[ 	]*=[ 	]*"no"[ 	]*;'
	mpxiodisableyes='mpxio-disable[ 	]*=[ 	]*"yes"[ 	]*;'

	if [ "x$cmd" = xenable ]; then
		mpxiodisable_cur_entry=$mpxiodisableyes
		propval=no
		msg=`gettext "STMS already enabled"`
	else
		mpxiodisable_cur_entry=$mpxiodisableno
		propval=yes
		msg=`gettext "STMS already disabled"`
	fi

	DRVCONF=$d.conf
	KDRVCONF=/kernel/drv/$d.conf
	TMPDRVCONF=/var/run/tmp.$d.conf.$$
	TMPDRVCONF_MPXIO_ENTRY=/var/run/tmp.$d.conf.mpxioentry.$$;

	if delete_mpxio_disable_entries $KDRVCONF $TMPDRVCONF $TMPDRVCONF_MPXIO_ENTRY; then

		if [ -s $TMPDRVCONF_MPXIO_ENTRY ]; then
			# $DRVCONF does have mpxiodisable entries
			$EGREP -s "$mpxiodisable_cur_entry" $TMPDRVCONF_MPXIO_ENTRY
			if [ $? -ne 0 ]; then
				# if all mpxiodisable entries are no/yes for
				# enable/disable mpxio, notify the user
				rm -f $TMPDRVCONF $TMPDRVCONF_MPXIO_ENTRY > /dev/null 2>&1
				continue;
			else
				reboot_needed=`$EXPR $reboot_needed + 1`
			fi

			# If mpxiodisable entries do not exist, always continue update
		fi
	else
		rm -f $TMPDRVCONF $TMPDRVCONF_MPXIO_ENTRY > /dev/null 2>&1
		gettext "failed to update " 1>&2
		echo "$KDRVCONF." 1>&2 
		gettext "No changes were made to your STMS configuration.\n" 1>&2
		return 1
	fi

	rm $TMPDRVCONF_MPXIO_ENTRY > /dev/null 2>&1
	echo "mpxio-disable=\"${propval}\";" >> $TMPDRVCONF

}

setcmd()
{
	if [ "x$cmd" = xnone ]; then
		cmd=$1
	else
		echo "$USAGE" 1>&2
		exit 2
	fi
}

#
#Need to update bootpath on x86 if boot system from FC disk
#Only update bootpath here when mpxio is enabled
#If mpxio is disabled currently, will update bootpath in mpxio-upgrade
#

get_newbootpath_for_stmsdev() {
	if [ "x$cmd" = "xenable" ]; then
		return 0
	fi

	cur_bootpath=`/usr/sbin/eeprom bootpath | \
	    $SED 's/bootpath=[ 	]*//g' | $SED 's/[ 	]*$//'`
	if [ "x$cur_bootpath" = "x" ]; then
		gettext "failed to get bootpath by eeprom\n" 1>&2
		return 1
	fi

	#only update bootpath for STMS path
	echo $cur_bootpath|$EGREP $CLIENT_TYPE_VHCI > /dev/null 2>&1
	if [ $? -eq 1 ]; then
		return 0
	fi

	new_bootpath=`$STMSBOOTUTIL -p /devices$cur_bootpath`
	if [ $? -ne 0 ]; then
		new_bootpath=""
		return 1
	fi

	# we replace "sd" with "disk" if we need to work on the eeprom
	# bootpath setting, since fibre-channel devices will report as
	# being attached via "disk" and not "sd". One day we'll have a
	# truly unified and architecture-independent view of the device
	# tree, and this block will be redundant
	fp_bootpath=`echo $new_bootpath|grep fp.*sd`
	if [ "x$fp_bootpath" != "x" ]; then
		new_bootpath=`echo $fp_bootpath |sed -e"s,sd,disk,g"`
	fi
}

#
# Emit a warning message to the user that by default we
# operate on all multipath-capable controllers that are
# attached to the system, and that if they want to operate
# on only a specific controller type (fp|mpt|....) then 
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
		for i in `$STMSBOOTUTIL -D $WARNDRV -n | $SED -e"s,|, ,g"`; do
			$GREP "$i.*$WARNDRV.$" /etc/path_to_inst | $AWK -F"\"" '{print "/devices"$2}'
		done;
	done;
	
	echo ""
	gettext "If you do NOT wish to operate on these controllers, please quit stmsboot\n"
	gettext "and re-invoke with -D { fp | mpt } to specify which controllers you wish\n"
	gettext "to modify your multipathing configuration for.\n"

	echo ""
	gettext "Do you wish to continue? [y/n] (default: y) " 
	read response

	if [ "x$response" != "x" -a "x$response" != "xY" -a \
	    "x$response" != "xy" ]; then
		exit
	fi

}

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

if [ "x$cmd" = xnone ]; then
	echo "$USAGE" 1>&2
	exit 2
fi

if [ "x$DRV" = "x" ]; then
	DRVLIST="fp mpt"
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
	if [ -f /var/svc/manifest/system/device/mpxio-upgrade.xml ]; then
		$SVCCFG import /var/svc/manifest/system/device/mpxio-upgrade.xml
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

if [ "x$cmd" = xenable -o "x$cmd" = xdisable -o "x$cmd" = xupdate ]; then
	#
	# The bootup script doesn't work on cache-only-clients as the script
	# is executed before the plumbing for cachefs mounting of root is done.
	#
	if $MOUNT -v | $EGREP -s " on / type (nfs|cachefs) "; then
		gettext "This command option is not supported on systems with nfs or cachefs mounted root filesystem.\n" 1>&2
		exit 1
	fi

	# if the user has left the system with the mpxio-upgrade service
	# in a temporarily disabled state (ie, service is armed for the next
	# reboot), then let them know. We need to ensure that the system is
	# is in a sane state before allowing any further invocations, so 
	# try to get the system admin to do so

	ISARMED=`$SVCS -l $STMSINSTANCE |$GREP "enabled.*temporary"`
	if [ $? -eq 0 ]; then
		echo ""
		gettext "You need to reboot the system in order to complete\n"
		gettext "the previous invocation of stmsboot.\n"
		echo ""
		gettext "Do you wish to reboot the system now? (y/n, default y) "
		read response

		if [ "x$response" = "x" -o "x$response" = "xY" -o \
		    "x$response" = "xy" ]; then
			/usr/sbin/reboot
		else
			echo ""
			gettext "Please reboot this system before continuing\n"
			echo ""
			exit 1
		fi
	fi

	if [ -d $SAVEDIR ]; then
		#
		# keep a copy of the last saved files, useful for manual
		# recovery in case of a problem.
		#
		for d in $DRVLIST; do
			DRVCONF=$d.conf
			KDRVCONF=/kernel/drv/$d.conf
			TMPDRVCONF=/var/run/tmp.$d.conf.$$
			TMPDRVCONF_MPXIO_ENTRY=/var/run/tmp.$d.conf.mpxioentry.$$;

			if [ "x$MACH" = "xsparc" ]; then
				backup_lastsaved $KDRVCONF $VFSTAB
			else
				backup_lastsaved $KDRVCONF $VFSTAB $BOOTENV_FILE
			fi
		done
	else
		mkdir $SAVEDIR
	fi

fi

if [ "x$cmd" = xenable -o "x$cmd" = xdisable ]; then

	msgneeded=`echo "$DRVLIST" |grep " "`
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
		
		if [ "x$MACH" = "xi386" -a "x$cmd" = "xdisable" ]; then
			get_newbootpath_for_stmsdev
			if [ $? -ne 0 ]; then
				rm -f $TMPDRVCONF > /dev/null 2>&1
				gettext "failed to update bootpath.\n" 1>&2
				gettext "No changes were made to your STMS configuration.\n" 1>&2
				return 1
			fi
		fi
		update_sysfiles
	else
		echo "STMS is already ${cmd}d. No changes or reboots needed"
	fi


elif [ "x$cmd" = xupdate ]; then
	if [ "x$MACH" = "xi386" ]; then
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

elif [ "x$cmd" = xlist ]; then
		$STMSBOOTUTIL $GUID -l $controller
else
		$STMSBOOTUTIL $GUID -L
fi

exit $?
