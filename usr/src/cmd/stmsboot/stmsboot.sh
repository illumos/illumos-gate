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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

PATH=/usr/bin:/usr/sbin:$PATH; export PATH
STMSBOOTUTIL=/lib/mpxio/stmsboot_util
STMSMETHODSCRIPT=/lib/svc/method/mpxio-upgrade
STMSINSTANCE=platform/sun4u/mpxio-upgrade:default
FPCONF=/kernel/drv/fp.conf
TMPFPCONF=/var/run/tmp.fp.conf.$$
VFSTAB=/etc/vfstab
SAVEDIR=/etc/mpxio
RECOVERFILE=$SAVEDIR/recover_instructions
SVCCFG_RECOVERY=$SAVEDIR/svccfg_recover
USAGE=`gettext "Usage: stmsboot -e | -d | -u | -L | -l controller_number"`

#
# Copy all entries (including comments) from source driver.conf to destination
# driver.conf except those entries which contain mpxio-disable property.
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
		/mpxio-disable[ 	]*=.*;$/d
		/;$/{ p
		      d
		    }
		:rdnext
		N
		s/[ 	]*$//
		/[^;]$/b rdnext
		/mpxio-disable[ 	]*=/d' $1 > $2

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
		echo "/mnt$FPCONF." >> $RECOVERFILE
	else
		echo "\tcp /mnt${SAVEDIR}/fp.conf /mnt$FPCONF" >> $RECOVERFILE
	fi

	if [ $1 -eq 1 ]; then
		echo "\tcp /mnt${SAVEDIR}/vfstab /mnt$VFSTAB" >> $RECOVERFILE

		echo "repository /mnt/etc/svc/repository.db" > $SVCCFG_RECOVERY
		echo "select $STMSINSTANCE" >> $SVCCFG_RECOVERY
		echo "setprop general/enabled=false" >> $SVCCFG_RECOVERY
		echo "exit" >> $SVCCFG_RECOVERY

		echo "\t/usr/sbin/svccfg -f /mnt$SVCCFG_RECOVERY" >> $RECOVERFILE
	fi

	rootdisk=`mount | grep "/ on " | cut -f 3 -d " "`
	echo "\tumount /mnt\n\treboot\n\n${rootdisk} \c" >> $RECOVERFILE
	gettext "was your root device,\nbut it could be named differently after you boot net.\n" >> $RECOVERFILE
}

#
# Arrange for /etc/vfstab and dump configuration to be updated
# during the next reboot. If the cmd is "enable" or "disable", copy
# $TMPFPCONF to $FPCONF.
#
# Returns 0 on success, 1 on failure.
#
update_sysfiles()
{
	gettext "WARNING: This operation will require a reboot.\nDo you want to continue ? [y/n] (default: y) "
	read response

	if [ "x$response" != x -a "x$response" != xy -a \
	    "x$response" != xY ]; then
		rm -f $TMPFPCONF
		return 0
	fi

	need_bootscript=1
	if [ "x$cmd" = xenable -o "x$cmd" = xdisable ]; then
		cp $FPCONF $SAVEDIR
		cp $TMPFPCONF $FPCONF
		rm -f $TMPFPCONF

		#
		# there is no need to update the system files in the following
		# cases:
		# - we are enabling mpxio and the system has no configured
		#   disks accessible by phci paths.
		# - we are disabling mpxio and the system has no configured
		#   disks accessible by vhci paths.
		#
		if [ "x$cmd" = xenable ]; then
			ls -l /dev/dsk/*s2 2> /dev/null | \
			    egrep -s "/fp@.*/ssd@.*"
		else
			ls -l /dev/dsk/*s2 2> /dev/null | \
			    egrep -s "/scsi_vhci.*/ssd@.*"
		fi

		if [ $? -ne 0 ]; then
			need_bootscript=0
		fi
	fi

	if [ $need_bootscript -eq 1 ]; then
		#
		# Enable the mpxio-upgrade service, but don't run it now.
		# The service will run during the next reboot and will do
		# the actual job of modifying the system files.
		#
		svcadm disable -t $STMSINSTANCE
		svccfg -f - << EOF
select $STMSINSTANCE
setprop general/enabled = true
EOF
	fi

	build_recover $need_bootscript

	gettext "The changes will come into effect after rebooting the system.\nReboot the system now ? [y/n] (default: y) "
	read response

	if [ "x$response" = x -o "x$response" = xy -o \
	    "x$response" = xY ]; then
		reboot
	fi

	return 0
}

#
# Enable or disable mpxio as specified by the cmd.
# Returns 0 on success, 1 on failure.
#
configure_mpxio()
{
	if [ "x$cmd" = xenable ]; then
		propval=no
		msg=`gettext "STMS already enabled."`
	else
		propval=yes
		msg=`gettext "STMS already disabled."`
	fi

	if delete_mpxio_disable_entries $FPCONF $TMPFPCONF; then
		echo "mpxio-disable=\"${propval}\";" >> $TMPFPCONF
		if diff -b $FPCONF $TMPFPCONF > /dev/null; then
			rm -f $TMPFPCONF
			echo "$msg"
			return 0
		fi
		update_sysfiles
		return $?
	else
		rm -f $TMPFPCONF
		gettext "failed to update " 1>&2
		echo "$FPCONF." 1>&2
		gettext "No changes were made to your STMS configuration.\n" 1>&2
		return 1
	fi
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

cmd=none

# process options
while getopts eduLl: c
do
	case $c in
	e)	setcmd enable;;
	d)	setcmd disable;;
	u)	setcmd update;;
	L)	setcmd listall;;
	l)	setcmd list
		controller=$OPTARG;;
	\?)	echo "$USAGE" 1>&2
		exit 2;;
	esac
done

if [ "x$cmd" = xnone ]; then
	echo "$USAGE" 1>&2
	exit 2
fi

set `id`
if [ "$1" != "uid=0(root)" ]; then
	gettext "You must be super-user to run this script.\n" 1>&2
	exit 1
fi

# just a sanity check
if [ ! -f $STMSBOOTUTIL -o ! -f $STMSMETHODSCRIPT ]; then
	fmt=`gettext "Can't find %s and/or %s"`
	printf "$fmt\n" "$STMSBOOTUTIL" "$STMSMETHODSCRIPT" 1>&2
	exit 1
fi

svcprop -q $STMSINSTANCE
if [ $? -ne 0 ]; then
	fmt=`gettext "Can't find %s service"`
	printf "$fmt\n" "$STMSINSTANCE" 1>&2
	exit 1
fi

if [ "x$cmd" = xenable -o "x$cmd" = xdisable -o "x$cmd" = xupdate ]; then
	#
	# The bootup script doesn't work on cache-only-clients as the script
	# is executed before the plumbing for cachefs mounting of root is done.
	#
	if mount -v | egrep -s " on / type (nfs|cachefs) "; then
		gettext "This command option is not supported on systems with nfs or cachefs mounted root filesystem.\n" 1>&2
		exit 1
	fi

	if [ -d $SAVEDIR ]; then
		#
		# keep a copy of the last saved files, useful for manual
		# recovery in case of a problem.
		#
		backup_lastsaved $FPCONF $VFSTAB
	else
		mkdir $SAVEDIR
	fi

fi

if [ "x$cmd" = xenable -o "x$cmd" = xdisable ]; then
	configure_mpxio $cmd
elif [ "x$cmd" = xupdate ]; then
	update_sysfiles
elif [ "x$cmd" = xlist ]; then
	$STMSBOOTUTIL -l $controller
else
	$STMSBOOTUTIL -L
fi

exit $?
