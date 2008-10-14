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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Upgrade a machine from a cpio archive area in about 5 minutes.
# By Roger Faulkner and Jeff Bonwick, April 1993.
# (bfu == Bonwick/Faulkner Upgrade, a.k.a. Blindingly Fast Upgrade)
#
# Usage: bfu    [-f] <archive_dir> [root-dir]	# for normal machines
#        bfu -c [-f] <archive_dir> <exec-dir>	# for diskless clients
#
# The -f flag is to override the built-in safety check which requires
# that the starting-point OS be a least a certain revision.
#
# You have to be super-user.  It's safest to run this from the
# system console, although I've run it under OW and even via
# remote login with no problems.
#
# You will have to reboot the system when the upgrade is complete.
#
# You should add any administrative files you care about to this list.
# Warning: there had better be no leading '/' on any of these filenames.

#
# The CDPATH variable causes ksh's `cd' builtin to emit messages to stdout
# under certain circumstances, which can really screw things up; unset it.
#
unset CDPATH

export LC_ALL="C"

if [ -z "$GATEPATH" ]; then
	GATEPATH=/ws/onnv-gate
	test -d $GATEPATH || GATEPATH=/net/onnv.eng/export/onnv-gate
fi
export GATE=${GATEPATH}
export ARCHIVE=${ARCHIVEPATH:-${GATEPATH}}

#
# NOTE:	Entries in *_files must expand to either the exact files required,
#	or to directories that will be scoured for files.  Any directories
#	(and subdirectories) resulting from a wildcard expansion will be
#	fully recursed by BFU's searching for files.  (E.g. /etc/inet/* will
#	include all files in any of its directories, as well as any files in
#	/etc/inet/ itself.
#
#	These lists should really be generated automatically from the
#	pkgmap(4) metadata.
#

#
# First list: files to be saved in global and non-global zones.
#
all_zones_files="
	etc/.login
	etc/acct/holidays
	etc/auto_*
	etc/cron.d/at.deny
	etc/cron.d/cron.deny
	etc/crypto/pkcs11.conf
	etc/default/*
	etc/dev/reserved_devnames
	etc/dfs/dfstab
	etc/dumpdates
	etc/ftpd/*
	etc/ftpusers
	etc/group
	etc/gss/gsscred.conf
	etc/gss/mech
	etc/gss/qop
	etc/inet/*
	etc/init.d/*
	etc/inittab
	etc/ipf/ipf.conf
	etc/iu.ap
	etc/krb5/kadm5.acl
	etc/krb5/kdc.conf
	etc/krb5/kpropd.acl
	etc/krb5/krb5.conf
	etc/krb5/warn.conf
	etc/ksh.kshrc
	etc/logadm.conf
	etc/logindevperm
	etc/lp/Systems
	etc/mail/*.cf
	etc/mail/*.hf
	etc/mail/*.rc
	etc/mail/aliases
	etc/mail/helpfile
	etc/mail/local-host-names
	etc/mail/trusted-users
	etc/named.conf
	etc/net/*/services
	etc/netconfig
	etc/nfs/nfslog.conf
	etc/nfssec.conf
	etc/nscd.conf
	etc/nsswitch.*
	etc/pam.conf
	etc/passwd
	etc/policy.conf
	etc/printers.conf
	etc/profile
	etc/project
	etc/publickey
	etc/remote
	etc/resolv.conf
	etc/rmmount.conf
	etc/rpc
	etc/rpld.conf
	etc/saf/_sactab
	etc/saf/_sysconfig
	etc/saf/zsmon/_pmtab
	etc/security/audit_class
	etc/security/audit_control
	etc/security/audit_event
	etc/security/audit_startup
	etc/security/audit_user
	etc/security/audit_warn
	etc/security/auth_attr
	etc/security/crypt.conf
	etc/security/exec_attr
	etc/security/policy.conf
	etc/security/prof_attr
	etc/sfw/openssl/openssl.cnf
	etc/shadow
	etc/skel/.profile
	etc/skel/local.*
	etc/smartcard/.keys
	etc/smartcard/desktop.properties
	etc/smartcard/ocf.classpath
	etc/smartcard/opencard.properties
	etc/ssh/ssh_config
	etc/ssh/sshd_config
	etc/syslog.conf
	etc/ttydefs
	etc/ttysrch
	etc/user_attr
	etc/uucp/[A-Z]*
	etc/vfstab
	var/smb/*
	var/spool/cron/crontabs/*
	var/yp/Makefile
	var/yp/aliases
	var/yp/nicknames
"

#
# Second list: files to be saved in the global zone only.
#
global_zone_only_files="
	boot/grub/menu.lst
	boot/solaris/bootenv.rc
	boot/solaris/devicedb/master
	boot/solaris/filelist.ramdisk
	etc/aggregation.conf
	etc/dladm/*
	etc/bootrc
	etc/crypto/kcf.conf
	etc/devlink.tab
	etc/driver_aliases
	etc/driver_classes
	etc/lvm/devpath
	etc/lvm/lock
	etc/lvm/md.cf
	etc/lvm/md.ctlrmap
	etc/lvm/md.tab
	etc/lvm/mddb.cf
	etc/lvm/runtime.cf
	etc/mach
	etc/minor_perm
	etc/name_to_major
	etc/name_to_sysnum
	etc/nca/nca.if
	etc/nca/ncakmod.conf
	etc/nca/ncalogd.conf
	etc/nca/ncaport.conf
	etc/openwin/server/etc/OWconfig
	etc/path_to_inst
	etc/power.conf
	etc/ppp/chap-secrets
	etc/ppp/options
	etc/ppp/pap-secrets
	etc/security/device_policy
	etc/security/extra_privs
	etc/security/tsol/tnrhdb
	etc/security/tsol/tnrhtp
	etc/security/tsol/tnzonecfg
	etc/security/tsol/label_encodings
	etc/security/tsol/relabel
	etc/security/tsol/devalloc_defaults
	etc/system
	etc/zones/index
	kernel/drv/aac.conf
	kernel/drv/elxl.conf
	kernel/drv/md.conf
	kernel/drv/options.conf
	kernel/drv/ra.conf
	kernel/drv/scsa2usb.conf
	kernel/drv/scsi_vhci.conf
	kernel/drv/sd.conf
	kernel/drv/mpt.conf
	platform/*/kernel/drv/*ppm.conf
	platform/i86pc/kernel/drv/aha.conf
	platform/i86pc/kernel/drv/asy.conf
	platform/sun4u/boot.conf
"

#
# Third list: files extracted from generic.root but which belong in the global
# zone only: they are superfluous (and some even harmful) in nonglobal zones.
#
# (note: as /etc/init.d scripts are converted to smf(5) "Greenline" services,
# they (and their /etc/rc?.d hardlinks) should be removed from this list when
# they are added to smf_obsolete_rc_files, below)
#
superfluous_nonglobal_zone_files="
	dev/dsk
	dev/fd
	dev/pts
	dev/rdsk
	dev/rmt
	dev/stderr
	dev/stdin
	dev/stdout
	dev/swap
	dev/term
	dev/vt
	devices
	etc/dacf.conf
	etc/dat
	etc/default/metassist.xml
	etc/default/power
	etc/flash/postdeployment/svm.cleanup
	etc/flash/predeployment/svm.save
	etc/inet/ipqosconf.1.sample
	etc/inet/ipqosconf.2.sample
	etc/inet/ipqosconf.3.sample
	etc/inet/sock2path
	etc/init.d/devlinks
	etc/init.d/dodatadm.udaplt
	etc/init.d/drvconfig
	etc/init.d/llc2
	etc/init.d/ncakmod
	etc/init.d/ncalogd
	etc/init.d/pcmcia
	etc/init.d/pppd
	etc/init.d/wrsmcfg
	etc/llc2
	etc/lvm
	etc/nca
	etc/openwin
	etc/ppp
	etc/rc0.d/K34ncalogd
	etc/rc0.d/K50pppd
	etc/rc0.d/K52llc2
	etc/rc1.d/K34ncalogd
	etc/rc1.d/K50pppd
	etc/rc1.d/K52llc2
	etc/rc2.d/S40llc2
	etc/rc2.d/S42ncakmod
	etc/rc2.d/S47pppd
	etc/rc2.d/S81dodatadm.udaplt
	etc/rc2.d/S94ncalogd
	etc/rcS.d/K34ncalogd
	etc/rcS.d/K44wrsmcfg
	etc/rcS.d/K50pppd
	etc/rcS.d/K52llc2
	etc/rcS.d/S29wrsmcfg
	etc/rcm
	etc/sock2path
	etc/usb
	etc/wrsm
	etc/zones
	kernel
	lib/libmeta.so
	lib/libmeta.so.1
	lib/svc/method/sf880dr
	lib/svc/method/svc-cvcd
	lib/svc/method/svc-dcs
	lib/svc/method/svc-drd
	lib/svc/method/svc-dscp
	lib/svc/method/svc-dumpadm
	lib/svc/method/svc-intrd
	lib/svc/method/svc-hal
	lib/svc/method/svc-labeld
	lib/svc/method/svc-mdmonitor
	lib/svc/method/svc-metainit
	lib/svc/method/svc-metasync
	lib/svc/method/svc-oplhpd
	lib/svc/method/svc-poold
	lib/svc/method/svc-pools
	lib/svc/method/svc-power
	lib/svc/method/svc-resource-mgmt
	lib/svc/method/svc-rmvolmgr
	lib/svc/method/svc-scheduler
	lib/svc/method/svc-sckmd
	lib/svc/method/svc-syseventd
	lib/svc/method/svc-tnctl
	lib/svc/method/svc-tnd
	lib/svc/method/svc-vntsd
	lib/svc/method/svc-zones
	lib/svc/method/vtdaemon
	platform/*/kernel
	platform/SUNW,Sun-Fire-15000/lib/cvcd
	platform/SUNW,Ultra-Enterprise-10000/lib/cvcd
	platform/i86pc/biosint
	platform/i86pc/multiboot
	platform/sun4u/cprboot
	platform/sun4u/lib/libwrsmconf.so
	platform/sun4u/lib/libwrsmconf.so.1
	platform/sun4u/lib/sparcv9/libwrsmconf.so
	platform/sun4u/lib/sparcv9/libwrsmconf.so.1
	platform/sun4u/sbin
	platform/sun4u/wanboot
	platform/sun4v/wanboot
	sbin/metadb
	sbin/metadevadm
	sbin/metainit
	sbin/metarecover
	sbin/metastat
	usr/include/sys/dcam
	usr/lib/devfsadm/linkmod/SUNW_dcam1394_link.so
	usr/lib/ldoms
	usr/platform/SUNW,SPARC-Enterprise/lib/dscp.ppp.options
	usr/platform/SUNW,SPARC-Enterprise/lib/libdscp.so
	usr/platform/SUNW,SPARC-Enterprise/lib/libdscp.so.1
	usr/platform/SUNW,SPARC-Enterprise/lib/llib-ldscp.ln
	usr/platform/SUNW,SPARC-Enterprise/sbin/prtdscp
	var/adm/pool
	var/log/pool
	var/svc/manifest/network/rpc/mdcomm.xml
	var/svc/manifest/network/rpc/meta.xml
	var/svc/manifest/network/rpc/metamed.xml
	var/svc/manifest/network/rpc/metamh.xml
	var/svc/manifest/network/tnctl.xml
	var/svc/manifest/network/tnd.xml
	var/svc/manifest/platform/i86pc/eeprom.xml
	var/svc/manifest/platform/sun4u/dcs.xml
	var/svc/manifest/platform/sun4u/dscp.xml
	var/svc/manifest/platform/sun4u/efdaemon.xml
	var/svc/manifest/platform/sun4u/oplhpd.xml
	var/svc/manifest/platform/sun4u/sckmd.xml
	var/svc/manifest/platform/sun4u/sf880drd.xml
	var/svc/manifest/platform/sun4v
	var/svc/manifest/system/cvc.xml
	var/svc/manifest/system/dumpadm.xml
	var/svc/manifest/system/fmd.xml
	var/svc/manifest/system/hal.xml
	var/svc/manifest/system/intrd.xml
	var/svc/manifest/system/labeld.xml
	var/svc/manifest/system/mdmonitor.xml
	var/svc/manifest/system/metainit.xml
	var/svc/manifest/system/metasync.xml
	var/svc/manifest/system/picl.xml
	var/svc/manifest/system/poold.xml
	var/svc/manifest/system/pools.xml
	var/svc/manifest/system/power.xml
	var/svc/manifest/system/resource-mgmt.xml
	var/svc/manifest/system/scheduler.xml
	var/svc/manifest/system/sysevent.xml
	var/svc/manifest/system/vtdaemon.xml
	var/svc/manifest/system/zones.xml
	var/svc/manifest/system/filesystem/rmvolmgr.xml
"

#
# Fourth list: files to be preserved, ie unconditionally restored to
# "child" versions
#
preserve_files="
	etc/hostid
	kernel/misc/amd64/sysinit
	kernel/misc/amd64/usbs49_fw
	kernel/misc/sparcv9/usbs49_fw
	kernel/misc/sysinit
	kernel/misc/usbs49_fw
	var/adm/aculog
	var/adm/spellhist
	var/adm/utmpx
	var/adm/wtmpx
	var/log/authlog
	var/log/syslog
	var/saf/zsmon/log
"

realmode_files="
	boot/solaris/bootenv.rc
	boot/solaris/devicedb/master
"

#
# /usr/sadm/install/scripts/i.build class runs class client provided
# script. The files below are managed by build class and its build script.
# They are added /bfu.conflict/NEW and the acr.sh process runs the script
# as part of conflict resolution. 
#
build_class_script_files="
	etc/mpapi.conf
	etc/hba.conf
	etc/ima.conf
"

fail() {
	print "$*" >& 2
	print "bfu aborting" >& 2
	rm -f "$bfu_zone_list"
	exit 1
}

filelist() {
	files="$all_zones_files $preserve_files"
	if [ $1 = "global" ]; then
		files="$global_zone_only_files $files"
	fi
	find $files -depth -type f ! -name core -print 2>/dev/null | sort -u || {
		#
		# Force cpio to return non-zero by printing an error message
		# to stdout that it won't be able to lstat().
		#
		echo 'filelist: sort failed'
		fail "sort failed"
	}
}

realmode_filelist() {
	find $realmode_files -depth -type f ! -name core -print 2>/dev/null | sort
}

smf_inetd_conversions="
	100134
	100150
	100155
	100229
	100230
	100234
	100242
	100422
	chargen
	comsat
	daytime
	discard
	echo
	eklogin
	exec
	finger
	ftp
	gssd
	klogin
	krb5_prop
	kshell
	ktkt_warnd
	login
	metad
	metamedd
	metamhd
	name
	ocfserv
	printer
	rexd
	rquotad
	rstatd
	rusersd
	shell
	smserverd
	sprayd
	sun-dr
	talk
	telnet
	time
	uucp
	walld
"

enable_next_boot () {
	if [ -x /tmp/bfubin/svccfg ]; then
	    svcadm disable -t $1
	    [ $? = 0 ] || echo "warning: unable to temporarily disable $1"
	    svccfg -s $1 setprop general/enabled = true
	    [ $? = 0 ] || echo "warning: unable to enable $1 for next boot"
	fi
}

#
# If we're in the global zone, import the manifest for the specified service.
# Note that we will need to see whether we are in an smf root if we are using
# an alternate root. If so, import the service directly; otherwise, print the
# warning messages.
#
# $1: the path of the xml file (the related path to /var/svc/manifest)
# $2: the service name - specified only if the service is enabled after reboot.
#
smf_import_service() {
	if [[ $zone = global && -f $rootprefix/var/svc/manifest/$1 ]]; then
		if [[ -n $rootprefix && -x /usr/sbin/svccfg ]]; then
			SVCCFG_REPOSITORY=$rootprefix/etc/svc/repository.db \
			/usr/sbin/svccfg import $rootprefix/var/svc/manifest/$1
		elif [[ -n $rootprefix ]]; then
			echo "Warning: This system does not have SMF, so I"
			echo "cannot ensure the pre-import of $1. If it does"
			echo "not work, reboot your alternate root to fix it."
		elif [[ -x /tmp/bfubin/svccfg ]]; then
			if [[ "${2}a" == a ]]; then
				/tmp/bfubin/svccfg import /var/svc/manifest/$1
			else
				tmpfile=/tmp/`echo "$1" | tr / :`.$$
				sed -e "s/enabled='true'/enabled='false'/" \
				    /var/svc/manifest/$1 > "$tmpfile"
				/tmp/bfubin/svccfg import "$tmpfile"
				#
				# Make sure the service is enabled after reboot.
				#
				enable_next_boot $2
			fi
		fi
	fi
}

smf_inetd_disable() {
	inetconf=$rootprefix/etc/inet/inetd.conf
	inettmp=/tmp/inetd.tmp.$$

	sed "$(for i in $smf_inetd_conversions; do 
		echo "s:^[ 	]*$i[ 	/]:#SMFbfu# &:"
	done)" $inetconf > $inettmp && ! cmp -s $inettmp $inetconf &&
	    cp $inettmp $inetconf

	rm -f -- $inettmp
}

smf_inetd_reenable() {
	inetconf=$rootprefix/etc/inet/inetd.conf
	inettmp=/tmp/inetd.tmp.$$

	sed 's/^#SMFbfu# //' $inetconf > $inettmp && cp $inettmp $inetconf

	rm -f -- $inettmp
}

smf_tftp_reinstall() {
	inetconf=$rootprefix/etc/inet/inetd.conf
	inettmp=/tmp/inetd.tmp.$$

	if grep '^#SMFbfu# tftp' $inetconf >/dev/null ; then
		# BFU previously commented out, put it back in place
	    	sed 's/^#SMFbfu# tftp/tftp/' $inetconf > $inettmp &&
		    cp $inettmp $inetconf
	elif ! grep '^[#	 ]*tftp' $inetconf >/dev/null; then
		# No entry, append to end
		cat >>$inetconf <<EOF
# TFTPD - tftp server (primarily used for booting)
#tftp	dgram	udp6	wait	root	/usr/sbin/in.tftpd	in.tftpd -s /tftpboot
EOF
	fi

	rm -f -- $inettmp
}

inetd_conf_svm_hack() {
	# Since inetd.conf is updated by SUNWmdr's postinstall script,
	# we will update the actual inetd.conf here to reflect the postinstall
	# changes.

	inetconf=$rootprefix/etc/inet/inetd.conf
	inettmp=/tmp/inetd.tmp.$$
	inetnew=/tmp/inetd.new.$$

	#
	# only change inetd.conf if the rpc.metad entry is out of date
	#

	if ! grep "^[# 	]*100229/1-2" $inetconf > /dev/null ; then

		# Grab existing rpc entries for rpc.metad
		# and convert spaces to tabs within the rpc entry, as well as
		# the transport method; 
		# or add a new entry in case there was none.
		if grep "^[# 	]*100229/1" $inetconf > /dev/null ; then
			grep "^# METAD - SLVM metadb" $inetconf > $inettmp
			grep "^[# 	]*100229/1" $inetconf | \
			    sed -e 's/[ 	][ 	]*/	/g' \
				-e 's?100229/1?100229/1-2?' >> $inettmp
		else
			echo '# METAD - SVM metadb Daemon' > $inettmp
			echo "100229/1-2\ttli\trpc/tcp\twait\troot\t/usr/sbin/rpc.metad\trpc.metad" >> $inettmp
		fi

		grep -v '^# METAD - SLVM metadb' $inetconf | \
		    grep -v '^[# 	]*100229/1' > $inetnew
		cat $inettmp >> $inetnew

		if ! diff $inetnew $inetconf > /dev/null ; then
			print "Updating inet.conf metad entry ... \c"
			if cp $inetnew $inetconf ; then
				print "done."
			else
				print "failed."
			fi
		fi
		rm -f $inettmp $inetnew
	fi

	#
	# only change inetd.conf if the rpc.mdcommd entry is out of date
	#

	if ! grep "^[# 	]*100422/1" $inetconf > /dev/null ; then

		# Grab existing rpc entries for rpc.mdcommd
		# and convert spaces to tabs within the rpc entry,
		# or add a new entry in case there was none.
		if grep "^[#    ]*100422/1" $inetconf > /dev/null ; then
			grep "^# MDMN_COMMD - SVM Multi node" $inetconf > $inettmp
			grep "^[#       ]*100422/1" $inetconf | \
				sed -e 's/[         ][      ]*/     /g' >> $inettmp 
		else
			echo '# MDMN_COMMD - SVM Multi node communication daemon' >$inettmp
			echo '100422/1\ttli\trpc/tcp\twait\troot\t/usr/sbin/rpc.mdcommd\trpc.mdcommd' >> $inettmp
		fi

		grep -v '^# MDMN_COMMD - SVM Multi node' $inetconf | \
		grep -v '^[#        ]*100422/1' > $inetnew
		cat $inettmp >> $inetnew

		if ! diff $inetnew $inetconf > /dev/null ; then
			print "Updating inetd.conf rpc.mdcommd entry ... \c"
			if cp $inetnew $inetconf; then
				print "done."
			else
				print "failed."
			fi
		fi

		rm -f $inettmp $inetnew
	fi
}

upgrade_aggr_and_linkprop () {
	# Since aggregation.conf and linkprop.conf are upgraded by
	# SUNWcnetr's postinstall script, put the relevant portions of the
	# postinstall script here, modified to rename the old files instead
	# of removing them.

	#
	# Convert datalink configuration into a series of dladm(1M) commands
	# and keep them in an upgrade script. This script will then be run
	# in the network-physical service.
	#
	# Note that we cannot use the /var/svc/profile/upgrade script because
	# that script is run in the manifest-import service which is too late
	# for the datalink configuration.
	#
	UPGRADE_SCRIPT=/var/svc/profile/upgrade_datalink

	AGGR_CONF=/etc/aggregation.conf
	ORIG=$rootprefix$AGGR_CONF
	if [[ ! -f $ORIG ]]; then
		# Try the alternate location.
		AGGR_CONF=/etc/dladm/aggregation.conf
		ORIG=$rootprefix$AGGR_CONF
	fi

	if [[ -f $ORIG ]]; then
		# Strip off comments, then each remaining line defines
		# an aggregation the administrator configured on the old
		# system.  Each line corresponds to one dladm command
		# that is appended to the upgrade script.
		cat $ORIG | grep '^[^#]' | while read line; do
			echo $line | while read aggr_index rest
			do
				policy=`echo $rest | /usr/bin/awk '{print $1}'`
				nports=`echo $rest | /usr/bin/awk '{print $2}'`
				ports=`echo $rest | /usr/bin/awk '{print $3}'`
				mac=`echo $rest | /usr/bin/awk '{print $4}'`
				lacp_mode=`echo $rest | /usr/bin/awk \
				    '{print $5}'`
				lacp_timer=`echo $rest | /usr/bin/awk \
				    '{print $6}'`
				dladm_string="dladm create-aggr -P $policy -l \
				    $lacp_mode -T $lacp_timer"
				# A fixed MAC address
				if [[ $mac != "auto" ]]; then
					dladm_string="$dladm_string -u $mac"
				fi
				i=1
				while [ $i -le $nports ]; do
					device=`echo $ports | cut -d, -f$i`
					# Older aggregation.conf files have the
					# format of device_name/port_number.
					# We don't need the port number, so get
					# rid of it if it is there.
					device=`echo $device | cut -d/ -f1`
					((i = i + 1))
					dladm_string="$dladm_string -d \
					    $device"
				done
				dladm_string="$dladm_string $aggr_index"
				echo $dladm_string >> \
					$rootprefix$UPGRADE_SCRIPT
			done
		done
		mv $ORIG $ORIG.bak
	fi

	# Upgrade linkprop.conf
	ORIG=$rootprefix/etc/dladm/linkprop.conf

	if [[ -f $ORIG ]]; then
		# Strip off comments, then each remaining line lists
		# properties the administrator configured for a	
		# particular interface.  Each line includes several
		# properties, but we can only set one property per
		# dladm invocation.
		cat $ORIG | grep '^[^#]' | while read line; do
			echo $line | while read link rest
			do
				while [ -n "$rest" ]; do
					linkprop=`echo $rest | cut -d";" -f1`
					rest=`echo $rest | cut -d";" -f2-`
					echo dladm set-linkprop -p $linkprop \
					    $link >> $rootprefix$UPGRADE_SCRIPT
				done
			done
		done
		mv $ORIG $ORIG.bak
	fi
}

# Update aac.conf for set legacy-name-enable properly
update_aac_conf()
{
	conffile=$rootprefix/kernel/drv/aac.conf
	childconffile=$rootprefix/bfu.child/kernel/drv/aac.conf

	# Already using autoenumeration mode, return
	egrep -s "legacy-name-enable" $childconffile && \
	    grep "legacy-name-enable" $childconffile | egrep -s "no" && return

	# Else enable legacy mode
	sed -e 's/legacy-name-enable="no"/legacy-name-enable="yes"/g' \
	    < $conffile > /tmp/aac.conf.$$
	mv -f /tmp/aac.conf.$$ $conffile
}

# update x86 version mpt.conf for property tape
mpttapeprop='[ 	]*tape[ 	]*=[ 	]*"sctp"[ 	]*;'
update_mptconf_i386()
{
	conffile=$rootprefix/kernel/drv/mpt.conf
	test -f $conffile || return
	egrep -s "$mpttapeprop" $conffile
	if [ $? -ne 0 ] ; then
	    echo 'tape="sctp";' >> $conffile
	fi
}

# update x86 etc/mach file after xVM_uppc is added,
# which makes xpv_psm a non-default psm module
update_etc_mach_i386()
{
	etc_mach=$rootprefix/etc/mach
	test -f $etc_mach || return
	grep -w "xpv_psm" $etc_mach > /dev/null 2>&1
	if [ $? -ne 0 ] ; then
	    echo 'xpv_psm' >> $etc_mach
	fi
}

# check and update driver class for scsi-self-identifying
chk_update_drv_class()
{

    drvclassfile=$rootprefix/etc/driver_classes
    name2majorfile=$rootprefix/etc/name_to_major
    drvname=$1
    classentry="^$drvname[ 	].*scsi-self-identifying"

    [ -f $drvclassfile ] || return
    [ -f $name2majorfile ] || return

    grep -w $drvname $name2majorfile > /dev/null 2>&1 || return

    egrep -s "$classentry" $drvclassfile
    if [ $? -ne 0 ]; then
	echo "$drvname	scsi-self-identifying" >> $drvclassfile
    fi
}

update_drvclass_i386()
{
    chk_update_drv_class ahci
    chk_update_drv_class si3124
    chk_update_drv_class marvell88sx
    chk_update_drv_class nv_sata
}

update_policy_conf() {
	# update /etc/security/policy.conf with the default
	# Solaris crypt(3c) policy.
	
	dest=$rootprefix/etc/security/policy.conf

	grep 'CRYPT_' $dest > /dev/null 2>&1
	if [ $? = 1 ] ; then
		print "Updating entries for crypt(3c), see policy.conf(4)"
	cat >> $dest <<EOM

# crypt(3c) Algorithms Configuration
#
# CRYPT_ALGORITHMS_ALLOW specifies the algorithms that are allowed to
# be used for new passwords.  This is enforced only in crypt_gensalt(3c).
#
CRYPT_ALGORITHMS_ALLOW=1,2a,md5

# To deprecate use of the traditional unix algorithm, uncomment below
# and change CRYPT_DEFAULT= to another algorithm.  For example,
# CRYPT_DEFAULT=1 for BSD/Linux MD5.
#
#CRYPT_ALGORITHMS_DEPRECATE=__unix__

# The Solaris default is the traditional UNIX algorithm.  This is not
# listed in crypt.conf(4) since it is internal to libc.  The reserved
# name __unix__ is used to refer to it.
#
CRYPT_DEFAULT=__unix__
EOM
	fi
	grep PRIV_ $dest >/dev/null 2>&1
	if [ $? = 1 ]; then
		echo "Updating entries for privileges(5)," \
		     "see policy.conf(4) for details."
cat >> $dest <<EOM
#
# These settings determine the default privileges users have.  If not set,
# the default privileges are taken from the inherited set.
# There are two different settings; PRIV_DEFAULT determines the default
# set on login; PRIV_LIMIT defines the Limit set on login.
# Individual users can have privileges assigned or taken away through
# user_attr.  Privileges can also be assigned to profiles in which case
# the users with those profiles can use those privileges through pfexec(1m).
# For maximum future compatibility, the specifications should
# always include "basic" or "all"; privileges should then be removed using
# the negation.  E.g., PRIV_LIMIT=all,!sys_linkdir takes away only the
# sys_linkdir privilege, regardless of future additional privileges.
# Similarly, PRIV_DEFAULT=basic,!file_link_any takes away only the
# file_link_any privilege from the basic privilege set; only that notation
# is immune from a future addition of currently unprivileged operations to
# the basic privilege set.
# NOTE: removing privileges from the the Limit set requires EXTREME care
# as any set-uid root program may suddenly fail because it lacks certain
# privilege(s).
#
#PRIV_DEFAULT=basic
#PRIV_LIMIT=all
EOM
	fi

}

#
# Cleanup nfsmapid configuration before extracting
# root bits.  Remove if they exist:
#	nfsmapid entry in inetd.conf
#	nfsmapid entry in /etc/net/ti*/services
#
# Going forward neither should exist, but no harm if services entry exists
# Going way backwards (pre-04/28/2004), inetd.conf must exist but will
# be a conflict that should be merged in
#
nfsmapid_cfg() {
	inetdconf=$rootprefix/etc/inet/inetd.conf
	tmpinetcf=/tmp/inetd.conf.$$
	cp -pf ${inetdconf} ${tmpinetcf}
	cat /dev/null > ${inetdconf} 2>&1
       	sed -e "/^#[#	 ]*NFSv4/d"		\
	    -e "/^[#	 ]*100166\/1/d"		\
	    ${tmpinetcf} > ${inetdconf} 2>&1
	rm -f ${tmpinetcf}

	tmpservices=/tmp/services.$$

	services=$rootprefix/etc/net/ticotsord/services
	cp -pf ${services} ${tmpservices}
	cat /dev/null > ${services} 2>&1
       	sed -e "/^[#	 ]*nfsmapid/d"		\
	    ${tmpservices} > ${services} 2>&1
	rm -f ${tmpservices}

	services=$rootprefix/etc/net/ticots/services
	cp -pf ${services} ${tmpservices}
	cat /dev/null > ${services} 2>&1
       	sed -e "/^[#	 ]*nfsmapid/d"		\
	    ${tmpservices} > ${services} 2>&1
	rm -f ${tmpservices}

	services=$rootprefix/etc/net/ticlts/services
	cp -pf ${services} ${tmpservices}
	cat /dev/null > ${services} 2>&1
       	sed -e "/^[#	 ]*nfsmapid/d"		\
	    ${tmpservices} > ${services} 2>&1
	rm -f ${tmpservices}
}

#
# Define global variables
#
CALL_DEVID_DESTROY=""
#
# List of SDS commands that must be deleted.
#
SDSCMDLIST="
growfs
metaclear
metadb
metadetach
metahs
metainit
metaoffline
metaonline
metaparam
metarename
metareplace
metaroot
metaset
metastat
metasync
metattach
rpc.metad
rpc.metamhd
"
#
# List of SDS configuration files that must be deleted.
#
SDSCONFIGLIST="
lock
md.cf
mddb.cf
md.tab
devpath
md.ctlrmap
"
#
# List of rc scripts that must be deleted.
#
RCLIST="
etc/init.d/SUNWmd.init
etc/init.d/SUNWmd.sync
etc/init.d/lvm.init
etc/init.d/lvm.sync
etc/rcS.d/S35SUNWmd.init
etc/rcS.d/S35lvm.init
etc/rc2.d/S95SUNWmd.sync
etc/rc2.d/S95lvm.sync
etc/rcS.d/S35slvm.init
etc/rc2.d/S95slvm.sync
etc/init.d/slvm.init
etc/init.d/slvm.sync
etc/init.d/init.mdlogd
etc/rc3.d/S25mdlogd
"
#
# List of flashprom-related files that must be deleted.
#
FLASHPROMLIST="
etc/rc2.d/S75flashprom
etc/init.d/flashprom
usr/platform/SUNW,Ultra-2/lib/flash-update.sh
usr/platform/SUNW,Ultra-4/lib/flash-update.sh
usr/platform/SUNW,Ultra-Enterprise/lib/flash-update.sh
usr/platform/sun4u/doc/flashupdate.txt
usr/platform/sun4u/lib/flash-update.sh
usr/platform/sun4u/lib/prom/SUNW,Ultra-2
usr/platform/sun4u/lib/prom/SUNW,Ultra-4
usr/platform/sun4u/lib/prom/SUNW,Ultra-Enterprise
"

#
# delete the entries associated with bootlist from /etc/system
#

delete_system_bootlist() {
	sed -e /"Begin MDD database info"/,/"End MDD database info"/d \
	    < ${SYSTEM_FILE} > /tmp/system.$$
	cp /tmp/system.$$ ${SYSTEM_FILE} || \
	    echo "copy error: /tmp/system.$$ to ${SYSTEM_FILE}"
}

#
# Add entries in md.conf for bootlist
#

fix_mdconf() {
	cp ${mdconf} /tmp/md.conf.$$
	echo >> /tmp/md.conf.$$
	echo "# Begin MDD database info (do not edit)" >> /tmp/md.conf.$$
	sed -e 's/^set md://' -e 's/$/;/' ${SYSTEM_FILE} | \
	    grep mddb_bootlist >> /tmp/md.conf.$$
	echo "# End MDD database info (do not edit)" >> /tmp/md.conf.$$
	cp /tmp/md.conf.$$ ${mdconf} || \
	    echo "copy error: /tmp/md.conf.$$ to ${mdconf}"
}

#
# add_devid_destroy(filename)
# returns contents in filename
# md_devid_destroy property is required when upgrading
# from pre SVM to SVM releases or when the device ID returned from
# the driver changes.
# It is specifically placed between
# # Begin MDD database info and # End MDD database info because
# on the subsequent reboot, this line will be removed automatically when
# metadevadm is run in rc2.d.
#
add_devid_destroy() {
	cat $1 | awk '{
		if ( $2 == "End" && $4 == "database") {
			print "md_devid_destroy=1;"
		}
		print $0
	}' >> /tmp/t$$
	mv /tmp/t$$ $1
}

#
# Reads existing configuration values in /etc/rcap.conf and puts 
# them in repository upon reboot(via /var/svc/profile/upgrade).
#
migrate_rcap_conf() {
	RCAP_CONF="${rootprefix}/etc/rcap.conf"
	PROFILE_UPGRADE="${rootprefix}/var/svc/profile/upgrade"
	SVCCFG="/usr/sbin/svccfg"
	RCAP_FMRI="svc:/system/rcap:default"
	PG="config"

	pressure=`awk '$1 == "RCAPD_MEMORY_CAP_ENFORCEMENT_PRESSURE" \
	    && NF == 3 {print $3}' $RCAP_CONF`

	reconfig_int=`awk '$1 == "RCAPD_RECONFIGURATION_INTERVAL" \
	    && NF == 3 {print $3}' $RCAP_CONF`

	walk_int=`awk '$1 == "RCAPD_PROC_WALK_INTERVAL" && \
	    NF == 3 {print $3}' $RCAP_CONF`

	report_int=`awk '$1 == "RCAPD_REPORT_INTERVAL" && \
	    NF == 3 {print $3}' $RCAP_CONF`

	rss_sample_int=`awk '$1 == "RCAPD_RSS_SAMPLE_INTERVAL" && \
	    NF == 3 {print $3}' $RCAP_CONF`

	# Blindly update default configuration values with
	# pre-existing values
	#
	echo "# Migrating pre-existing rcap configuration" >> \
	    $PROFILE_UPGRADE

	echo "$SVCCFG -s $RCAP_FMRI setprop ${PG}/pressure = " \
	    "$pressure" >> $PROFILE_UPGRADE

	echo "$SVCCFG -s $RCAP_FMRI " \
	    "setprop ${PG}/reconfig_interval = $reconfig_int" >> \
	    $PROFILE_UPGRADE

	echo "$SVCCFG -s $RCAP_FMRI " \
	    "setprop ${PG}/walk_interval = $walk_int" >> \
	    $PROFILE_UPGRADE

	echo "$SVCCFG -s $RCAP_FMRI " \
	    "setprop ${PG}/report_interval = $report_int" >> \
	    $PROFILE_UPGRADE

	echo "$SVCCFG -s $RCAP_FMRI " \
	    "setprop ${PG}/rss_sample_interval = $rss_sample_int" >> \
	    $PROFILE_UPGRADE

	echo "/usr/sbin/svcadm refresh $RCAP_FMRI" >> \
	    $PROFILE_UPGRADE

	echo "rm /etc/rcap.conf" >> \
	    $PROFILE_UPGRADE
}

#
# Migrate an existing extended accounting configuration from /etc/acctadm.conf
# to the smf(5) repository upon reboot.  Enable the instance if the 
# configuration differs from the default configuration.
#
migrate_acctadm_conf()
{
	cat >> $rootprefix/var/svc/profile/upgrade <<\_EOF
	if [ -f /etc/acctadm.conf ]; then 
		. /etc/acctadm.conf

		fmri="svc:/system/extended-accounting:flow"
		svccfg -s $fmri setprop config/file = \
		    ${ACCTADM_FLOW_FILE:="none"}
		svccfg -s $fmri setprop config/tracked = \
		    ${ACCTADM_FLOW_TRACKED:="none"}
		svccfg -s $fmri setprop config/untracked = \
		    ${ACCTADM_FLOW_UNTRACKED:="extended"}
		if [ ${ACCTADM_FLOW_ENABLE:="no"} = "yes" ]; then
			svccfg -s $fmri setprop config/enabled = "true"
		else
			svccfg -s $fmri setprop config/enabled = "false"
		fi
		if [ $ACCTADM_FLOW_ENABLE = "yes" -o \
		    $ACCTADM_FLOW_FILE != "none" -o \
		    $ACCTADM_FLOW_TRACKED != "none" ]; then
			svcadm enable $fmri
		fi

		fmri="svc:/system/extended-accounting:process"
		svccfg -s $fmri setprop config/file = \
		    ${ACCTADM_PROC_FILE:="none"}
		svccfg -s $fmri setprop config/tracked = \
		    ${ACCTADM_PROC_TRACKED:="none"}
		svccfg -s $fmri setprop config/untracked = \
		    ${ACCTADM_PROC_UNTRACKED:="extended"}
		if [ ${ACCTADM_PROC_ENABLE:="no"} = "yes" ]; then
			svccfg -s $fmri setprop config/enabled = "true"
		else
			svccfg -s $fmri setprop config/enabled = "false"
		fi
		if [ $ACCTADM_PROC_ENABLE = "yes" -o \
		    $ACCTADM_PROC_FILE != "none" -o \
		    $ACCTADM_PROC_TRACKED != "none" ]; then
			svcadm enable $fmri
		fi

		fmri="svc:/system/extended-accounting:task"
		svccfg -s $fmri setprop config/file = \
		    ${ACCTADM_TASK_FILE:="none"}
		svccfg -s $fmri setprop config/tracked = \
		    ${ACCTADM_TASK_TRACKED:="none"}
		svccfg -s $fmri setprop config/untracked = \
		    ${ACCTADM_TASK_UNTRACKED:="extended"}
		if [ ${ACCTADM_TASK_ENABLE:="no"} = "yes" ]; then
			svccfg -s $fmri setprop config/enabled = "true"
		else
			svccfg -s $fmri setprop config/enabled = "false"
		fi
		if [ $ACCTADM_TASK_ENABLE = "yes" -o \
		    $ACCTADM_TASK_FILE != "none" -o \
		    $ACCTADM_TASK_TRACKED != "none" ]; then
			svcadm enable $fmri
		fi

		rm /etc/acctadm.conf
	fi
_EOF
}

#
# smf(5) "Greenline" doesn't install the init.d or rc*.d scripts for
# converted services.  Clean up previous scripts for such services.
#
smf_obsolete_rc_files="
	etc/init.d/ANNOUNCE
	etc/init.d/MOUNTFSYS
	etc/init.d/RMTMPFILES
	etc/init.d/acctadm
	etc/init.d/audit
	etc/init.d/autofs
	etc/init.d/coreadm
	etc/init.d/cron
	etc/init.d/cryptosvc
	etc/init.d/cvc
	etc/init.d/devfsadm
	etc/init.d/dhcp
	etc/init.d/dhcpagent
	etc/init.d/domainname
	etc/init.d/efcode
	etc/init.d/inetd
	etc/init.d/inetinit
	etc/init.d/inetsvc
	etc/init.d/initboot
	etc/init.d/ipfboot
	etc/init.d/kdc
	etc/init.d/kdc.master
	etc/init.d/keymap
	etc/init.d/ldap.client
	etc/init.d/libc.mount
	etc/init.d/network
	etc/init.d/nfs.client
	etc/init.d/nodename
	etc/init.d/nscd
	etc/init.d/perf
	etc/init.d/picld
	etc/init.d/power
	etc/init.d/rcapd
	etc/init.d/rootusr
	etc/init.d/rpc
	etc/init.d/savecore
	etc/init.d/sckm
	etc/init.d/sf880dr
	etc/init.d/slpd
	etc/init.d/sshd
	etc/init.d/standardmounts
	etc/init.d/svm.init
	etc/init.d/svm.sync
	etc/init.d/sysid.net
	etc/init.d/sysid.sys
	etc/init.d/syslog
	etc/init.d/utmpd
	etc/init.d/volmgt
	etc/init.d/xntpd
	etc/init.d/zones
	etc/rc0.d/K00ANNOUNCE
	etc/rc0.d/K01zones
	etc/rc0.d/K03sshd
	etc/rc0.d/K05volmgt
	etc/rc0.d/K07snmpdx
	etc/rc0.d/K10rcapd
	etc/rc0.d/K21dhcp
	etc/rc0.d/K28kdc
	etc/rc0.d/K28kdc.master
	etc/rc0.d/K28nfs.server
	etc/rc0.d/K32cryptosvc
	etc/rc0.d/K33audit
	etc/rc0.d/K33efcode
	etc/rc0.d/K34svm.sync
	etc/rc0.d/K36sendmail
	etc/rc0.d/K36utmpd
	etc/rc0.d/K37power
	etc/rc0.d/K40cron
	etc/rc0.d/K40inetd
	etc/rc0.d/K40nscd
	etc/rc0.d/K40sf880dr
	etc/rc0.d/K40slpd
	etc/rc0.d/K40syslog
	etc/rc0.d/K40xntpd
	etc/rc0.d/K41autofs
	etc/rc0.d/K41ldap.client
	etc/rc0.d/K41nfs.client
	etc/rc0.d/K41rpc
	etc/rc0.d/K42sckm
	etc/rc0.d/K43inet
	etc/rc0.d/K68picld
	etc/rc0.d/K83devfsadm
	etc/rc0.d/K90dhcpagent
	etc/rc1.d/K00ANNOUNCE
	etc/rc1.d/K01zones
	etc/rc1.d/K03sshd
	etc/rc1.d/K05volmgt
	etc/rc1.d/K07snmpdx
	etc/rc1.d/K10rcapd
	etc/rc1.d/K21dhcp
	etc/rc1.d/K28kdc
	etc/rc1.d/K28kdc.master
	etc/rc1.d/K28nfs.server
	etc/rc1.d/K33audit
	etc/rc1.d/K33efcode
	etc/rc1.d/K34svm.sync
	etc/rc1.d/K36sendmail
	etc/rc1.d/K36utmpd
	etc/rc1.d/K37power
	etc/rc1.d/K40cron
	etc/rc1.d/K40inetd
	etc/rc1.d/K40nscd
	etc/rc1.d/K40sf880dr
	etc/rc1.d/K40slpd
	etc/rc1.d/K40syslog
	etc/rc1.d/K40xntpd
	etc/rc1.d/K41autofs
	etc/rc1.d/K41ldap.client
	etc/rc1.d/K41rpc
	etc/rc1.d/K42sckm
	etc/rc1.d/K43inet
	etc/rc1.d/K99libc.mount
	etc/rc1.d/S01MOUNTFSYS
	etc/rc2.d/K01zones
	etc/rc2.d/K03sshd
	etc/rc2.d/K05volmgt
	etc/rc2.d/K07snmpdx
	etc/rc2.d/K21dhcp
	etc/rc2.d/K28kdc
	etc/rc2.d/K28kdc.master
	etc/rc2.d/K28nfs.server
	etc/rc2.d/S01MOUNTFSYS
	etc/rc2.d/S05RMTMPFILES
	etc/rc2.d/S21perf
	etc/rc2.d/S30sysid.net
	etc/rc2.d/S65ipfboot
	etc/rc2.d/S69domainname
	etc/rc2.d/S69inet
	etc/rc2.d/S70sckm
	etc/rc2.d/S71ldap.client
	etc/rc2.d/S71rpc
	etc/rc2.d/S71sysid.sys
	etc/rc2.d/S72inetsvc
	etc/rc2.d/S72slpd
	etc/rc2.d/S73nfs.client
	etc/rc2.d/S74autofs
	etc/rc2.d/S74syslog
	etc/rc2.d/S74xntpd
	etc/rc2.d/S75cron
	etc/rc2.d/S75savecore
	etc/rc2.d/S76nscd
	etc/rc2.d/S77inetd
	etc/rc2.d/S77sf880dr
	etc/rc2.d/S85power
	etc/rc2.d/S88sendmail
	etc/rc2.d/S88utmpd
	etc/rc2.d/S95svm.sync
	etc/rc2.d/S98efcode
	etc/rc2.d/S98libc.mount
	etc/rc2.d/S99audit
	etc/rc2.d/S99rcapd
	etc/rc3.d/S13kdc.master
	etc/rc3.d/S14kdc
	etc/rc3.d/S15nfs.server
	etc/rc3.d/S34dhcp
	etc/rc3.d/S76snmpdx
	etc/rc3.d/S81volmgt
	etc/rc3.d/S89sshd
	etc/rc3.d/S99zones
	etc/rcS.d/K01zones
	etc/rcS.d/K03sshd
	etc/rcS.d/K05volmgt
	etc/rcS.d/K07snmpdx
	etc/rcS.d/K10rcapd
	etc/rcS.d/K21dhcp
	etc/rcS.d/K28kdc
	etc/rcS.d/K28kdc.master
	etc/rcS.d/K28nfs.server
	etc/rcS.d/K33audit
	etc/rcS.d/K33efcode
	etc/rcS.d/K34svm.sync
	etc/rcS.d/K36sendmail
	etc/rcS.d/K36utmpd
	etc/rcS.d/K37power
	etc/rcS.d/K40cron
	etc/rcS.d/K40inetd
	etc/rcS.d/K40nscd
	etc/rcS.d/K40sf880dr
	etc/rcS.d/K40slpd
	etc/rcS.d/K40syslog
	etc/rcS.d/K40xntpd
	etc/rcS.d/K41autofs
	etc/rcS.d/K41ldap.client
	etc/rcS.d/K41rpc
	etc/rcS.d/K42sckm
	etc/rcS.d/K43inet
	etc/rcS.d/K99libc.mount
	etc/rcS.d/S10cvc
	etc/rcS.d/S28network.sh
	etc/rcS.d/S29nodename.sh
	etc/rcS.d/S30rootusr.sh
	etc/rcS.d/S33keymap.sh
	etc/rcS.d/S35svm.init
	etc/rcS.d/S40standardmounts.sh
	etc/rcS.d/S42coreadm
	etc/rcS.d/S45initboot
	etc/rcS.d/S50devfsadm
	etc/rcS.d/S72cryptosvc
	etc/rcS.d/S95picld
"

# Obsolete smf manifests
smf_obsolete_manifests="
	var/svc/manifest/application/print/cleanup.xml
	var/svc/manifest/network/tftp.xml
	var/svc/manifest/network/lp.xml
	var/svc/manifest/system/filesystem/volfs.xml
	var/svc/manifest/network/pfil.xml
	var/svc/manifest/platform/sun4u/mpxio-upgrade.xml
	var/svc/manifest/network/tname.xml
	var/svc/manifest/network/aggregation.xml
	var/svc/manifest/network/datalink.xml
	var/svc/manifest/network/datalink-init.xml
"

# smf services whose manifests have been renamed
smf_renamed_manifests="
	var/svc/manifest/milestone/name-service.xml
	var/svc/manifest/system/filesystem/boot-archive.xml
"

# Obsolete smf methods
smf_obsolete_methods="
	lib/svc/method/print-cleanup
	lib/svc/method/print-server
	lib/svc/method/svc-volfs
	lib/svc/method/pfil
	lib/svc/method/aggregation
	lib/svc/method/datalink
	lib/svc/method/datalink-init
	lib/svc/method/svc-kdc
	lib/svc/method/svc-kdc.master
	lib/svc/method/svc-kdc.slave
	lib/svc/share/krb_include.sh
"

smf_cleanup () {
	(
		cd $root;
		print "Removing obsolete rc.d scripts ... \c"
		rm -f $smf_obsolete_rc_files
		print "done."
	)
}

smf_new_profiles () {
	[[ "$bfu_isa" = "sparc" ]] || return 0

	[[ -x /tmp/bfubin/svccfg ]] || return 0

	print "Clearing platform profile hash ..."

	# platform_SUNW,Sun-Fire.xml (and other new and
	# corrected platforms) were delivered in Build 68.
	if [ ! -f \
		$rootprefix/var/svc/profile/platform_SUNW,Sun-Fire.xml \
		]; then
		for pfx in " " "v"; do
			for plname in \
			    none \
			    SUNW_Sun_Fire_880 \
			    SUNW_Sun_Fire_V890 \
			    SUNW_Sun_Fire_15000 \
			    SUNW_UltraEnterprise_10000; do
				svccfg -f - <<EOF
select smf/manifest
delpg ${pfx}ar_svc_profile_platform_${plname}_xml
exit
EOF
			done
		done
	fi
}

smf_handle_new_services () {
	#
	# Detect, prior to extraction the arrival of new,
	# default-enabled-in-profile services.  If so, add a command
	# such that they are enabled.
	#
	if [ ! -f $rootprefix/var/svc/profile/system/sac.xml ]; then
		echo /usr/sbin/svcadm enable system/sac >> \
		    $rootprefix/var/svc/profile/upgrade
	fi
	if [[ $zone = global &&
            ! -f $rootprefix/var/svc/manifest/system/intrd.xml ]]; then
		echo /usr/sbin/svcadm enable system/intrd >> \
		    $rootprefix/var/svc/profile/upgrade
	fi
	if [[ $zone = global &&
	    ! -f $rootprefix/var/svc/manifest/system/scheduler.xml ]]; then
		echo /usr/sbin/svcadm enable system/scheduler >> \
		    $rootprefix/var/svc/profile/upgrade
	fi
	if [[ $zone = global &&
	    ! -f $rootprefix/var/svc/manifest/system/hal.xml ]]; then
		echo /usr/sbin/svcadm enable system/hal >> \
		    $rootprefix/var/svc/profile/upgrade
	fi
	if [[ $zone = global &&
	    ! -f $rootprefix/var/svc/manifest/system/filesystem/rmvolmgr.xml ]]; then
		echo /usr/sbin/svcadm enable system/filesystem/rmvolmgr >> \
		    $rootprefix/var/svc/profile/upgrade
	fi
	if [[ $zone = global &&
	    ! -f $rootprefix/var/svc/manifest/network/ipsec/manual-key.xml &&
	    -f $rootprefix/etc/inet/secret/ipseckeys ]]; then
		smf_enable svc:/network/ipsec/manual-key:default
	fi
	if [[ $zone = global &&
	    ! -f $rootprefix/var/svc/manifest/network/ipsec/ike.xml &&
	    -f $rootprefix/etc/inet/ike/config ]]; then
		smf_enable svc:/network/ipsec/ike:default
	fi
	if [[ $zone = global &&
	    ! -f $rootprefix/var/svc/manifest/system/pools.xml &&
	    -f $rootprefix/etc/pooladm.conf ]]; then
		smf_enable svc:/system/pools:default
	fi
}

smf_copy_manifest() {
	mfstbase=`basename $1`
	mymfs=$rootprefix/var/svc/manifest/$2/$mfstbase
	if [[ ! -f $mymfs ]] || ! cmp -s $manifest_src/$1 $mymfs ; then
		cp $manifest_src/$1 $mymfs ||
		    echo "bfu: could not copy $manifest_src/$1"
	fi
}

smf_copy_method() {
	cp $manifest_src/$1 $rootprefix/lib/svc/method ||
	    echo "bfu: could not copy $manifest_src/$1"
}

smf_cleanup_initd() {
	rm -f $rootprefix/etc/rc?.d/[SK]??$1
}

smf_delete_manifest() {
(
	mfst=$1
	cd $root
	[[ -f $mfst ]] || return;
	if [ -r /etc/svc/volatile/repository_door ]; then
		ENTITIES=`/tmp/bfubin/svccfg inventory $mfst`
		for fmri in $ENTITIES; do
			if [[ -n $root && $root != "/" ]]; then
				SVCCFG_REPOSITORY=$root/etc/svc/repository.db
				export SVCCFG_REPOSITORY
			fi
			/tmp/bfubin/svccfg delete -f $fmri >/dev/null 2>&1
			if [[ -n $root && $root != "/" ]]; then
				unset SVCCFG_REPOSITORY
			fi
		done
	fi
	rm $mfst
)
}

smf_delete_methods() {
(
	cd $root;
	rm -f $smf_obsolete_methods
)
}	

smf_delete_renamed_manifests() {
(
	cd $root;
	rm -f $smf_renamed_manifests
)
}

smf_cleanup_dlmgmtd() {
(
	#
	# Delete the service instance, then refresh all its dependents in the
	# cases of alternative root and zones.
	#
	smf_delete_manifest "var/svc/manifest/network/dlmgmt.xml"

	if [[ -n $root && $root != "/" ]]; then
		export SVCCFG_REPOSITORY=$root/etc/svc/repository.db
		/tmp/bfubin/svccfg -s svc:/network/physical:nwam refresh
		/tmp/bfubin/svccfg -s svc:/network/physical:default refresh
		/tmp/bfubin/svccfg -s svc:/system/device/local:default refresh
		unset SVCCFG_REPOSITORY
	fi
	cd $root
	rm -f lib/svc/method/svc-dlmgmtd
	rm -f etc/.dlmgmt_door
	rm -f sbin/dlmgmtd
)
}

smf_cleanup_vt() {
	(
		smf_delete_manifest var/src/manifest/system/vtdaemon.xml
		cd $root
		rm -f lib/svc/method/vtdaemon

		vt_conslogin_instances=`/tmp/bfubin/svcs -o FMRI | \
		    grep console-login:vt`
		for i in $vt_conslogin_instances; do
			/tmp/bfubin/svccfg delete -f $i
		done
	)
}

old_mfst_dir="var/svc/manifest.orig"
new_mfst_dir="var/svc/manifest"

smf_enable() {
	echo "svcadm enable $*" >> $rootprefix/var/svc/profile/upgrade
}

smf_check_repository() {
	repository=etc/svc/repository.db
	[[ -f $rootprefix/$repository ]] || return

	print -n "$rootprefix/$repository: " >&2

	sqlite="${SQLITEBIN-$GATE/public/bin/$bfu_isa/sqlite}"
	[[ -x $sqlite ]] || sqlite=/lib/svc/bin/sqlite
	if [[ ! -x $sqlite ]]; then
		echo "no sqlite binary: skipped integrity check" >&2
		return
	fi

	rm -f /tmp/bfurepo.db;
	cp $rootprefix/$repository /tmp/bfurepo.db
	bad_errors=`echo "PRAGMA integrity_check;" |
	    $sqlite /tmp/bfurepo.db 2>&1 | grep -v '^ok$'`
	if [[ $? -eq 0 ]]; then
		echo "integrity check failed:" >&2
		echo "$bad_errors" >&2
		echo >&2
		if [[ $force_override = no ]]; then
			cat >&2 <<EOF
Reseed the repository (see http://greenline.eng/quickstart.shtml#newrep)
before BFUing (or use the -f flag to force BFU to continue).  Re-seeding
will lose all smf(5) customizations.
EOF
			echo >&2
			exit 2;
		else
			echo "driving on anyway" >&2
		fi
	else
		echo "passed integrity check" >&2;
	fi
}

smf_bkbfu_warning() {
	print ""
	print "*************************************************************"
	print " WARNING: BFU'ing $1 backwards across 5090532."
	print " Fixes have been made but the services cannot be refreshed"
	print " on the $1's inactive repository. Next boot for the"
	print " $1 will probably result in maintenance mode due to"
	print " dependency cycles. If so, at the $1's console, run:"
	print ""
	print " /usr/sbin/svcadm refresh system/sysidtool:system"
	print " /usr/sbin/svcadm refresh system/sysidtool:net"
	print " /usr/sbin/svcadm clear milestone/single-user"
	print " /usr/sbin/svcadm clear system/sysidtool:system"
	print " /usr/sbin/svcadm clear system/sysidtool:net"
	print ""
	print " to resolve."
	print " To avoid these problems, reseed the zone's repository."
	print " See http://greenline.eng/quickstart.shtml#newrep ."
	print " Note: Re-seeding will lose all smf(5) customization."
	print "*************************************************************"
	print ""
}

smf_is_sysconfig() {
	#
	# Return success if going to post-5090532, i.e. post-sysconfig bits
	#
	# By now, we're going to post-smf bits - so multi-user.xml must
	# exist (since it was introduced by first SMF putback).
	# 
	# Function return status is return status of last command executed.
	# So, no need to check return status from grep below.

	grep sysconfig $rootprefix/var/svc/manifest/milestone/multi-user.xml \
		>/dev/null 2>&1
}

smf_bkbfu_past_sysconfig() {
	#
	# Check if bfu'ing back from post-5090532 to pre-5090532 bits.
	#
	if [[ -f $rootprefix/var/svc/manifest/milestone/sysconfig.xml ]] &&
	    ! smf_is_sysconfig ; then
		return 0
	fi
	return 1
}

smf_bkbfu_repair_sysconfig() {
	#
	# Perform the necessary corrections when bfu'ing backwards
	# from post-5090532 to pre-5090532 bits.
	#
	# Get the pre-5090532 non-ON manifests, and issue minimal fixes
	# to the repository, to enable re-boot.
	#
	smf_copy_manifest pre-5090532/sysidtool.xml system
	if [[ $zone = global && $karch = i86pc ]]; then
		smf_copy_manifest pre-5090532/kdmconfig.xml platform/i86pc
	fi
	#
	# Now, remove sysidtool:{system, net}'s dependency on
	# single-user and filesystem-local.
	#
	# If $rootprefix is not empty, this could be the global zone,
	# with an alternate root BFU, or a non-global zone. For either
	# case, the repository to be updated is not the live one: use
	# SVCCFG_REPOSITORY to point to the repository to be updated.
	#
	# Note that in the alternate-root case, doing this seems better
	# than forcing the user to re-seed, or to dis-allow it. The
	# issue of svccfg and the repository not matching seems remote,
	# given that from initial SMF integration (on10_64) to on10_74,
	# there was no mismatch. In the remote possibility that there is a
	# mis-match (in the future) causing these calls to be suspect,
	# the user is already being advised, via the warning message, to
	# reseed the repository in case of trouble. If a mis-match is ever
	# introduced, code such as this would have to be fixed, so this
	# aspect of the warning is useful only during the interim period.
	#
	# NOTE that this is not an issue for non-global zones'
	# repositories - they couldn't be out-of-sync with
	# /tmp/bfubin/svccfg.
	#
	if [[ -n $rootprefix ]]; then
		export SVCCFG_REPOSITORY=$rootprefix/etc/svc/repository.db
		if [[ $zone = global ]]; then
			smf_bkbfu_warning "alternate root"
		else
			smf_bkbfu_warning "zone"
		fi
	fi
	#
	# Using the newer "-s" option to svccfg in the following is OK
	# since its introduction preceded 5090532 (and this routine wouldn't
	# be called unless the machine is running post-5090532 bits).
	#
	/tmp/bfubin/svccfg -s system/sysidtool:net delpg single-user
	/tmp/bfubin/svccfg -s system/sysidtool:system delpg single-user
	/tmp/bfubin/svccfg -s system/sysidtool:net delpg filesystem_local
	/tmp/bfubin/svccfg -s system/sysidtool:system delpg filesystem_local

	#
	# On a live system, issue the refresh; For alternate root or non-global
	# zone, the user was asked to issue the refreshes and "clear"s in the
	# message above after a post-bfu reboot.
	#
	if [[ -z $rootprefix ]]; then
		/tmp/bfubin/svcadm refresh system/sysidtool:system \
		    system/sysidtool:net
	fi

	#
	# Now, reset SVCCFG_REPOSITORY, if it was set
	#
	[[ -n $rootprefix ]] && unset SVCCFG_REPOSITORY

	#
	# Remove the sysconfig.xml manifest when going back.  So backward
	# bfu check continues to work, and all manifests are correct.
	#
	cat >> $rootprefix/var/svc/profile/upgrade <<-EOF
	rm -f /var/svc/manifest/milestone/sysconfig.xml
	EOF
}

#
# Return true if $file exists in $archive.  $file may also be a pattern.
#
archive_file_exists()
{
	archive=$1
	file=$2

	$ZCAT $cpiodir/${archive}${ZFIX} | cpio -it 2>/dev/null | \
	    egrep -s "$file"
}

#
# extract one or more files from an archive into a temporary directory
# provided by the caller.  The caller is responsible for checking to
# to see whether the desired file or files were extracted
#
# $1 - archive
# $2 - temporary dir
# remaining args: file(s) to be extracted.
#
archive_file_peek() {
	compressed_archive=`pwd`/$1
	tdir=$2
	shift
	shift
	if [ ! -d $tdir ] ; then
		return
	fi
	(cd $tdir; $ZCAT $compressed_archive | cpio -idmucB $* 2>&1 )
}

#
# If we're no longer delivering the eeprom service, remove it from the system,
# as eeprom -I is removed as well.
#
smf_fix_i86pc_profile () {
	mfst="var/svc/manifest/platform/i86pc/eeprom.xml"
	profile="var/svc/profile/platform_i86pc.xml"

	if [ ! "$karch" = "i86pc" ]; then
		return
	fi

	if ! archive_file_exists generic.root "^$profile"; then
		rm -f $rootprefix/$profile
		rm -f $rootprefix/var/svc/profile/platform.xml
	fi

	if [ ! -f $rootprefix/$mfst ]; then
		return
	fi

	if archive_file_exists generic.root "^$mfst"; then
		return
	fi

	rm -f $rootprefix/$mfst

	#
	# we must disable via svccfg directly, as manifest-import runs after
	# this service tries to run
	#
	[[ -n "$rootprefix" ]] &&
	    export SVCCFG_REPOSITORY=$rootprefix/etc/svc/repository.db
	/tmp/bfubin/svccfg delete -f platform/i86pc/eeprom
	[[ -n "$rootprefix" ]] && unset SVCCFG_REPOSITORY
}

smf_apply_conf () {
	#
	# Go thru the original manifests and move any that were unchanged
	# (or are not system-provided) back to their proper location.  This
	# will avoid superfluous re-import on reboot, as the inode and mtime
	# are both part of the hash.
	#
	if [ -d $rootprefix/$old_mfst_dir ]; then
		for f in `cd $rootprefix/$old_mfst_dir ; find . -type f`
		do
			old=$rootprefix/$old_mfst_dir/$f
			new=$rootprefix/$new_mfst_dir/$f
			if [ ! -f $new ]; then
				mkdir -m 0755 -p `dirname $new`
				mv $old $new
				continue
			fi
			cmp -s $old $new && mv $old $new
		done
		rm -rf $rootprefix/$old_mfst_dir
	fi

	if [ -f $rootprefix/etc/init.d/inetd ]; then
		#
		# BFUing to non-SMF system -- undo our previous changes,
		# run an old hack, and skip the remainder of this function.
		#
		smf_inetd_reenable
		smf_tftp_reinstall

		# Update inetd.conf only if we find rpc.metad file.
		[ -f $usr/sbin/rpc.metad ] &&
		    inetd_conf_svm_hack

		return
	fi

	#
	# At this point, the archive in question is a SMF version.  If
	# the smf(5) repository does not yet exist, create it by copying
	# the appropriate seed repository.  Since updating of non-global
	# zones only occurs when the live system is bfu'ed, the
	# appropriate seed is guaranteed to exist under the /lib
	# directory.
	#
	repository=$rootprefix/etc/svc/repository.db
	if [ ! -f $repository ]; then
		print "Initializing service configuration repository ..."
		if [ $zone = global ]; then
			cp $rootprefix/lib/svc/seed/global.db $repository
		else
			cp /lib/svc/seed/nonglobal.db $repository
		fi
		chmod 0600 $repository
		chown root:sys $repository
	fi

	print "Removing obsolete smf services ..."
	for f in $smf_obsolete_manifests; do
		smf_delete_manifest $f
	done
	smf_delete_methods
	smf_delete_renamed_manifests

	if [[ $dlmgmtd_status = cleanup ]]; then
		smf_cleanup_dlmgmtd
	fi

	#
	# When doing backwards BFU, if the target does not contain
	# vtdaemon manifest, delete it and delete all the additional
	# console-login service instances which were used to provide
	# additional console sessions.
	#
	if ((! $ZCAT $cpiodir/generic.root$ZFIX | cpio -it 2>/dev/null | \
	    grep vtdaemon.xml > /dev/null 2>&1) && [ $zone = global ]); then
		smf_cleanup_vt
	fi

	print "Disabling unneeded inetd.conf entries ..."
	smf_inetd_disable
	smf_tftp_reinstall

	print "Connecting platform and name service profiles ..."

	rm -f $rootprefix/var/svc/profile/name_service.xml

	grep ldap $rootprefix/etc/nsswitch.conf >/dev/null 2>&1
	is_ldap=$?
	grep nisplus $rootprefix/etc/nsswitch.conf >/dev/null 2>&1
	is_nisplus=$?
	grep nis $rootprefix/etc/nsswitch.conf >/dev/null 2>&1
	is_nis=$?

	if [ $is_ldap  = 0 ]; then
		ns_profile=ns_ldap.xml
	elif [ $is_nisplus = 0  ]; then
		ns_profile=ns_nisplus.xml
	elif [ $is_nis = 0 ]; then
		ns_profile=ns_nis.xml
	else
		ns_profile=ns_files.xml
	fi

	ln -s $ns_profile $rootprefix/var/svc/profile/name_service.xml

	rm -f $rootprefix/var/svc/profile/inetd_services.xml
	ln -s inetd_upgrade.xml $rootprefix/var/svc/profile/inetd_services.xml

	print "Marking converted services as enabled ..."

	[ -f $rootprefix/etc/resolv.conf ] && smf_enable network/dns/client
	[ -f $rootprefix/etc/inet/dhcpsvc.conf ] && \
	    smf_enable network/dhcp-server
  
	# Not concerned about enabling/disabling rcap but will migrate
	# configuration parameters if rcap.conf exists
	#
	if [ -f $rootprefix/etc/rcap.conf ]; then
		migrate_rcap_conf
	fi

	migrate_acctadm_conf

	if [ $zone = global ]; then
		if [ -f $rootprefix/etc/dfs/dfstab ] &&
		    grep '^[ 	]*[^# 	]' $rootprefix/etc/dfs/dfstab \
		    > /dev/null; then
		    	smf_enable network/nfs/server
		fi
	else
		echo "/usr/sbin/svcadm disable network/nfs/server" >> \
		    $rootprefix/var/svc/profile/upgrade
	fi

	[ -f $rootprefix/etc/inet/ntp.conf ] && smf_enable network/ntp


	domainname=`cat $rootprefix/etc/defaultdomain 2>/dev/null`
        if [ ! -z "$domainname" -a -d $rootprefix/var/yp/$domainname ]; then
		smf_enable network/nis/server

		# Determining whether we're a NIS master requires
		# looking through the maps.
		cat >>$rootprefix/var/svc/profile/upgrade <<\_EOF
# Determine whether we are a YP master.
domain=`/usr/bin/domainname`
hostname=`uname -n | cut -d. -f1 | tr '[A-Z]' '[a-z]'`

if [ -x /usr/sbin/makedbm ]; then
	if [ -f /var/yp/NISLDAPmapping ]; then
		master=`/usr/sbin/makedbm -u /var/yp/\$domain/LDAP_passwd.byname | grep YP_MASTER_NAME | nawk '{ print $2 }'`
	else
		master=`/usr/sbin/makedbm -u /var/yp/\$domain/passwd.byname | grep YP_MASTER_NAME | nawk '{ print $2 }'`
	fi
fi

# If we are the master server, enable appropriate services.
if [ "$master" = "$hostname" -a "$YP_SERVER" = "TRUE" ]; then
	/usr/sbin/svcadm enable network/nis/xfr
	/usr/sbin/svcadm enable network/nis/passwd

	if [ ! -f /var/yp/NISLDAPmapping ]; then
		[ -f /var/yp/updaters ] && \
		    /usr/svc/svcadm enable network/nis/update
	fi
fi
_EOF
	fi

	# Check if mddbs don't exist on the image.  If so, disable SVM services.
	MDDB_STATUS=1
	if [ -f $rootprefix/kernel/drv/md.conf ]; then
		sed -e 's/#.*$//' $rootprefix/kernel/drv/md.conf | \
		    egrep '^[        ]*mddb_bootlist' >/dev/null 2>&1
		MDDB_STATUS=$?
	fi

	if [ $MDDB_STATUS -ne 0 ]; then
		for svc in metainit mdmonitor; do
		    echo "/usr/sbin/svcadm disable system/$svc:default" >> \
			$rootprefix/var/svc/profile/upgrade
		done

		for svc in meta mdcomm metamed metamh; do
		    echo "/usr/sbin/svcadm disable network/rpc/$svc:default" \
			>> $rootprefix/var/svc/profile/upgrade
		done
	fi

	# Workaround inetd's handling of "tcp6/udp6" when no IPv6 interfaces
	# are configured.
	for svc in meta mdcomm metamed metamh; do
	    echo "/usr/sbin/inetadm -m network/rpc/$svc:default proto=tcp" \
		">/dev/null 2>&1" >> $rootprefix/var/svc/profile/upgrade
	done

	manifest_src=${MANIFEST_SRC-$GATE/public/smf}
	[[ -d $manifest_src ]] ||
	    manifest_src=${GATE}/public/smf
	[[ -d $manifest_src ]] || manifest_src=/net/greenline.eng/meta0/smf

	if smf_bkbfu_past_sysconfig ; then
		echo "BFU'ing backwards across 5090532! Now repairing..."
		smf_bkbfu_repair_sysconfig
	fi

	#
	# If bfu'ing milestone/sysconfig bits or onwards, update the
	# corresponding non-ON manifests - sysidtool and kdmconfig.
	#
	sysidmfst=$rootprefix/var/svc/manifest/system/sysidtool.xml
	kdmmfst=$rootprefix/var/svc/manifest/platform/i86pc/kdmconfig.xml
	if smf_is_sysconfig ; then
		if [[ ! -f $sysidmfst ]]; then
			#
			# if WOS build on machine is pre-greenline, and
			# we're bfu'ing to the sysconfig bits.
			#
			smf_copy_manifest post-5090532/sysidtool.xml system
			if [[ $zone = global ]]; then
				smf_copy_method sysidtool-net
				smf_copy_method sysidtool-system
			fi
			echo "Converted system/sysidtool (post-5090532)"
		else
			#
			# If sysidtool.xml already exists, update it
			# if necessary. Future updates of sysidtool.xml
			# must occur in the dir: $manifest_src/post-5090532
			#
			smf_copy_manifest post-5090532/sysidtool.xml system
		fi
		if [[ $zone = global && $karch = i86pc ]]; then
			if [[ ! -f $kdmmfst ]]; then
				#
				# if WOS build on machine is pre-greenline, and
				# we're bfu'ing to the sysconfig bits.
				#
				smf_copy_manifest post-5090532/kdmconfig.xml \
				    platform/i86pc
				smf_copy_method   svc-kdmconfig
				smf_cleanup_initd kdmconfig
				echo "Converted platform/i86pc/kdmconfig"
				echo "(post-5090532)"
			else
				#
				# If kdmconfig.xml already exists, update
				# it if necessary. Future updates of
				# kdmconfig.xml must occur in the dir:
				# $manifest_src/post-5090532
				#
				smf_copy_manifest post-5090532/kdmconfig.xml \
				    platform/i86pc
			fi
		fi
	else
		if [[ ! -f $sysidmfst ]]; then
			smf_copy_manifest pre-5090532/sysidtool.xml system
			if [[ $zone = global ]]; then
				smf_copy_method sysidtool-net
				smf_copy_method sysidtool-system
			fi
			echo "Converted system/sysidtool"
		fi
		if [[ $zone = global && $karch = i86pc && ! -f $kdmmfst ]];
		then
			smf_copy_manifest pre-5090532/kdmconfig.xml \
			    platform/i86pc
			smf_copy_method   svc-kdmconfig
			smf_cleanup_initd kdmconfig
			echo "Converted platform/i86pc/kdmconfig"
		fi
	fi

	# If we've still got the old dtlogin manifest delivered by earlier
	# versions of bfu, delete it, as it was broken and should have
	# never been delivered.  A new version delivered by the CDE
	# consolidation should be left alone.
	if [[ -f $rootprefix/var/svc/manifest/application/dtlogin.xml &&
	    `grep -c GLXXX \
	    $rootprefix/var/svc/manifest/application/dtlogin.xml` -gt 0 &&
	    -x /tmp/bfubin/svccfg ]]; then

		# Delete the obsolete manifest.
		rm -f $rootprefix/var/svc/manifest/application/dtlogin.xml

		# Delete the service from repository, then use dtconfig -e to
		# revert to whatever the WOS bits are using if dtlogin was
		# enabled.
		cat >> $rootprefix/var/svc/profile/upgrade <<-EOFA
if /usr/bin/svcprop -q application/cde-login; then
	if [ \`/usr/bin/svcprop -p general/enabled \
		application/cde-login:default\` = "true" ]; then
		do_dtconfig=1;
	else
		do_dtconfig=0;
	fi

	/usr/sbin/svccfg delete -f application/cde-login
	type instance_refresh 2>&1 > /dev/null
	if [ \$? = 0 ]; then
		instance_refresh system/console-login
	else
		/usr/sbin/svcadm refresh system/console-login
	fi

	if [ \$do_dtconfig -eq 1 -a -x /usr/dt/bin/dtconfig ]; then
		/usr/dt/bin/dtconfig -e
	fi
fi
EOFA
	fi


	# Enable the inetd-upgrade service to convert any changes to inetd.conf
	smf_enable network/inetd-upgrade

	# If global zone, and bfu'ing from smf, and the inetd-upgrade
	# service has an obsolete dependency, then add a clear of inetd
	# and inetd-upgrade to the upgrade file as either may drop into
	# maintenance due to a dependency loop resulting from the new
	# inetd manifest
	if [[ $zone = global && -x /tmp/bfubin/svccfg ]]; then
		/tmp/bfubin/svcprop -q -p network/entities network/inetd-upgrade
		if [[ $? = 0 ]]; then
		    	echo "/usr/sbin/svcadm clear network/inetd" >> \
			    $rootprefix/var/svc/profile/upgrade
			echo "/usr/sbin/svcadm clear network/inetd-upgrade" >> \
			    $rootprefix/var/svc/profile/upgrade
		fi
	fi

	#
	# Import the name-service-cache service. This is to get the service
	# (with correct dependencies) in the repository before reboot.
	#
	smf_import_service system/name-service-cache.xml

	#
	# Import the datalink-management service.
	#
	smf_import_service network/dlmgmt.xml \
	    svc:/network/datalink-management:default

	#
	# Import the ldap/client service. This is to get the service
	# (with correct dependencies) in the repository before reboot.
	#
	smf_import_service network/ldap/client.xml

	# Enable new NFS status and nlockmgr services if client is enabled
	cat >> $rootprefix/var/svc/profile/upgrade <<-EOF
	    cl="svc:/network/nfs/client:default"
	    if [ \`/usr/bin/svcprop -p general/enabled \$cl\` = "true" ]; then
		/usr/sbin/svcadm enable svc:/network/nfs/status:default
		/usr/sbin/svcadm enable svc:/network/nfs/nlockmgr:default
	    fi

EOF

	kpmani="$rootprefix/var/svc/manifest/network/security/krb5_prop.xml"
	if grep svc-kdc.slave $kpmani > /dev/null 2>&1; then
		cat >> $rootprefix/var/svc/profile/upgrade <<EOF
		# We are deleting and reimporting kpropd's manifest, because we
		# need to change the restarter.
		kpfmri="svc:/network/security/krb5_prop"
		kkfmri="svc:/network/security/krb5kdc:default"
		lkpmani="/var/svc/manifest/network/security/krb5_prop.xml"
		restarter=\`svcprop -c -p general/restarter \$kpfmri 2>&1\`
		case \$restarter in
			*network/inetd:default)
				kken=\`svcprop -c -p general/enabled \$kkfmri\`
				svccfg delete -f \$kpfmri
				svccfg import \$lkpmani 
				# Enable kpropd if krb5kdc is enabled, since
				# krb5kdc would have run kpropd
				if [ \$kken = "true" ]; then
					svcadm enable \$kpfmri
				fi
				;;
		esac
EOF
	fi

	# Enable print server if there are local queues
	queues=`echo $rootprefix/etc/lp/printers/*/configuration`
	if [ "$queues" != "$rootprefix/etc/lp/printers/*/configuration" ]; then
		smf_enable application/print/server
	fi

	# Enable rarpd and bootparamd if they would have been running pre-SMF
	if [ -d $rootprefix/tftpboot ] || [ -d $rootprefix/rplboot ]; then
		smf_enable network/rarp
		smf_enable network/rpc/bootparams
	fi

	# To handle the transition from pre-smf ipfilter to smf-aware ipfilter,
	# check if ipfilter had been enabled with at least one rule, and if so
	# enable the smf instance.
	if grep '^[ \t]*[^# \t]' $rootprefix/etc/ipf/ipf.conf >/dev/null 2>&1 &&
	    [[ $zone = global ]]; then
		smf_enable network/ipfilter
	fi

	touch $rootprefix/var/svc/profile/.upgrade_prophist

	cat >> $rootprefix/var/svc/profile/upgrade <<EOF
	# We are deleting and reimporting dcs's manifest, because we
	# need to change the restarter.
	dcsfmri="svc:/platform/sun4u/dcs:default"
	dcsmani="/var/svc/manifest/platform/sun4u/dcs.xml"
	restarter=\`svcprop -c -p general/restarter \$dcsfmri 2>&1\`
	case \$restarter in
		*network/inetd:default)
			en=\`svcprop -c -p general/enabled \$dcsfmri\`
			svccfg delete -f \$dcsfmri
			svccfg import \$dcsmani
			if [ \$en = "true" ]; then
				svcadm enable \$dcsfmri
			fi
			;;
	esac
EOF

	smf_fix_i86pc_profile
}

tx_check_update() {
#
# If a lbl_edition file is found it's a likely sign that old unbundled
# Trusted Extensions packages are installed and TX is active.  Update
# etc/system if needed, to complete enabling of the bundled TX.
#
	LMOD1=$rootprefix/kernel/sys/lbl_edition
	LMOD2=$rootprefix/kernel/sys/amd64/lbl_edition
	LMOD3=$rootprefix/kernel/sys/sparcv9/lbl_edition

	grep "^set sys_labeling=" $rootprefix/bfu.child/etc/system > \
	    /dev/null 2>&1
	if [ $? -eq 0 ]; then
		return
	fi

	if [ -f $LMOD1 -o -f $LMOD2 -o -f $LMOD3 ]; then
		echo "set sys_labeling=1" >> $rootprefix/bfu.child/etc/system
		if [ $? -ne 0 ]; then
    			echo "cannot set sys_labeling in $rootprefix/bfu.child/etc/system"
			return
		fi

		rm -f $LMOD1 $LMOD2 $LMOD3
	fi
}

tx_check_bkbfu() {
#
# Emit a warning message if bfu'ing a Trusted Extensions-enabled system
# backwards to pre TX-merge bits.  In this case, unbundled packages must
# be reinstalled to complete restoration of old TX bits.
#
	bsmconv=$rootprefix/etc/security/bsmconv

	# This check is only needed in global zone
	if [[ $zone != global ]]; then
		return
	fi

	# No warning needed if TX is not currently enabled
	grep "^set sys_labeling=" $rootprefix/bfu.child/etc/system > \
	    /dev/null 2>&1
	if [ $? -ne 0 ]; then
		return
	fi

	if [ ! -f $bsmconv ]; then
		return
	fi
	grep " -x /usr/bin/plabel " $bsmconv > /dev/null 2>&1
	if [ $? != 0 ]; then
		return
	fi

	print ""
	print "*************************************************************"
	print " WARNING: BFU'ing TX backwards across 6533113."
	print " Must re-install unbundled TX packages to remain Trusted."
	print "*************************************************************"
	print ""
}

#
# The directboot putback moved the console property from
# /boot/solaris/bootenv.rc to /boot/grub/menu.lst.  It should be kept in both.
#
cleanup_eeprom_console()
{
	bootenvrc="$root/boot/solaris/bootenv.rc"
	menu_console=`eeprom console 2>/dev/null | \
	    grep -v 'data not available' | cut -d= -f2-`
	bootenv_console=`grep '^setprop[	 ]\{1,\}console\>' $bootenvrc`
	if [ -n "$menu_console" ] && [ -z "$bootenv_console" ]; then
		echo "setprop console '$menu_console'" >> $bootenvrc
	fi
}

EXTRACT_LOG=/tmp/bfu-extract-log.$$

rm -f $EXTRACT_LOG

extraction_error() {
	echo error $* >> $EXTRACT_LOG
}

#
# Make a local copy of bfu in /tmp and execute that instead.
# This makes us immune to loss of networking and/or changes
# to the original copy that might occur during execution.
#
cd .
abspath=`[[ $0 = /* ]] && print $0 || print $PWD/$0`
if [[ $abspath != /tmp/* ]]; then
	localpath=/tmp/bfu.$$
	print "Copying $abspath to $localpath"
	cp $abspath $localpath
	chmod +x $localpath
	print "Executing $localpath $*\n"
	exec $localpath $*
fi

export PATH=/usr/bin:/usr/sbin:/sbin

usage() {
	echo "Usage:"
	echo "    bfu    [-fh] <archive_dir> [root-dir]"
	echo "\tUpdate a single machine by loading archives on root-dir."
	echo "\troot-dir defaults to / (a live bfu).\n"
	echo "    bfu -c [-fh] <archive_dir> <exec-dir>"
	echo "\tUpdate all diskless clients by loading archives on each client"
	echo "\tthat mounts exec-dir as /usr.  <exec-dir> must start with"
	echo "\t/export/exec and each client's root must be in /export/root.\n"
	echo "\t-f        force bfu to continue even if it doesn't seem safe"
	fail "\t-h|-help  print this usage message and exit\n"
}

diskless=no
force_override=no
while [ $# -gt 0 ]; do
	case $1 in
		-c)		diskless=yes;;
		-f)		force_override=yes;;
		-h|-help)	usage;;
		*)      	break;;
	esac
	shift
done

# Variables for x86 platforms
boot_is_pcfs=no
have_realmode=no
is_pcfs_boot=no
new_dladm=no

# Set when moving to either directboot or multiboot
multi_or_direct=no

#
# Shows which type of archives we have, which type of system we are
# running on (before the bfu), and what the failsafe archives are
# (again, before the bfu).  failsafe_type is only needed on diskful
# bfu's, so it's not set in the diskless case.
# Possible values: unknown, dca, multiboot, directboot, xpv
#
archive_type=unknown
system_type=unknown
failsafe_type=unknown

test $# -ge 1 || usage

if [ -x /usr/bin/ppriv ]; then
	# We prefer to use ppriv, as it is a more accurate test, and also
	# has the benefit of preventing use from within a nonglobal zone.
	ppriv $$ | grep -w "E: all" > /dev/null 2>&1 || \
	    fail "bfu requires all privileges"
else
	# Fall back to old id check if system does not yet have ppriv.
	uid=`id | nawk '{print $1}'`
	[ "$uid" = "uid=0(root)" ] || \
	    fail "You must be super-user to run this script."
fi

bfu_isa=`uname -p`
target_isa=$bfu_isa
karch=`uname -m`
plat=`uname -i`

cpiodir=$1

if [ "$cpiodir" = again ]; then
	cpiodir=`nawk '/^bfu.ed from / { print $3; exit }' /etc/motd`
fi

[[ "$cpiodir" = */* ]] || cpiodir=$ARCHIVE/archives/$target_isa/$1

[[ "$cpiodir" = /* ]] || fail "archive-dir must be an absolute path"

cd $cpiodir
case `echo generic.root*` in
	generic.root)		ZFIX="";	ZCAT="cat";;
	generic.root.gz)	ZFIX=".gz";	ZCAT="gzip -d -c";;
	generic.root.Z)		ZFIX=".Z";	ZCAT="zcat";;
	*) fail "generic.root missing or in unknown compression format";;
esac

#
# Determine what kind of archives we're installing, using the following rules:
#
# 1. If i86xpv archives exist, the archives are xpv
# 2. If strap.com is present, the archives are pre-multiboot
# 3. If symdef is present, the archives are directboot
# 4. Otherwise, the archives are multiboot
#
if [ $target_isa = i386 ]; then
	if [ -f $cpiodir/i86xpv.root$ZFIX ]; then
		archive_type=xpv
		multi_or_direct=yes
	elif [ -f $cpiodir/i86pc.boot$ZFIX ] && \
	    archive_file_exists i86pc.boot "strap.com"; then
		archive_type=dca
	elif [ -f $cpiodir/i86pc.root$ZFIX ] && \
	    archive_file_exists i86pc.boot symdef; then
		archive_type=directboot
		multi_or_direct=yes
	else
		archive_type=multiboot
		multi_or_direct=yes
	fi
fi

if [ $diskless = no ]; then
	root=${2:-/}
	[[ "$root" = /* ]] || fail "root-dir must be an absolute path"
	usrroot=$root
	usr=${usrroot%/}/usr
	rootlist=$root

	[[ -f $root/etc/system ]] || \
	    fail "$root/etc/system not found; nonglobal zone target not allowed"

	rootfstype=`df -n $root | awk '{print $3}'`

	if [ "$rootfstype" = "zfs" ]; then
		archive_has_zfs_root_support=no
		mkdir /tmp/zfschk.$$
		archive_file_peek generic.lib /tmp/zfschk.$$ \
		    "lib/svc/share/fs_include.sh"
		if [ -f /tmp/zfschk.$$/lib/svc/share/fs_include.sh ] ; then
			if grep '^readswapdev' \
			     /tmp/zfschk.$$/lib/svc/share/fs_include.sh \
			     >/dev/null 2>&1 ; then
				archive_has_zfs_root_support=yes
			fi
		fi
		rm -fr /tmp/zfschk.$$

		if [ "$archive_has_zfs_root_support" = "no" ] ; then
			fail "Cannot bfu a system with zfs root to an archive with no zfs root support"
		fi
	fi

	# Make sure we extract the sun4u-us3 libc_psr.so.1
	if [ -d $root/platform/sun4u -a \
	   ! -d $root/platform/sun4u-us3 ]
	then
		mkdir $root/platform/sun4u-us3
		chmod 755 $root/platform/sun4u-us3
		chown root $root/platform/sun4u-us3
		chgrp sys $root/platform/sun4u-us3
	fi

	if [ $target_isa = i386 ]; then
		if [ $archive_type = xpv ]; then
			#
			# On i386, we want to apply the archives for both
			# platforms (i86pc and i86xpv) if they exist.  We
			# force the platform to i86xpv so that both will be
			# applied.
			#
			karch=i86pc
			plat=i86xpv
		fi
		if [ ! -d $root/platform/i86hvm ]; then
			mkdir $root/platform/i86hvm
		fi
	fi

	if [ $karch != $plat -a -f ${cpiodir}/${plat}.usr$ZFIX ]; then
		usrarchs="$karch $plat"
	else
		usrarchs="$karch"
	fi
	if [ $karch != $plat -a -f ${cpiodir}/${plat}.root$ZFIX ]; then
		rootarchs="$karch $plat"
	else
		rootarchs="$karch"
	fi

	if [ -h ${root}/platform/${plat} ]; then
		rm -f ${root}/platform/${plat}
	fi
	if [ -h ${usr}/platform/${plat} ]; then
		rm -f ${usr}/platform/${plat}
	fi

	if [ $plat != $karch -a -f ${cpiodir}/${plat}.root$ZFIX \
	    -a -f ${cpiodir}/${plat}.usr$ZFIX ]
	then
		cd $cpiodir
		#
		#  Look through all the archives we build and match
		#  the names of built archives with the names of
		#  directories installed on this machine.  We assume
		#  here that we can get the names of all architectures
		#  by pattern matching the names of .root archives - so
		#  if we ever had a case where we had only a .usr archive
		#  we wouldn't find that archive.
		#
		for i in *.root*
		do
			platname=${i%.root*}
			if [ -z "${platname}" -o ${platname} = $karch -o \
			    $platname = generic -o ${platname} = $plat ]; then
				continue;
			fi
			if [ -d ${root}/platform/${platname} -o \
			    -h ${root}/platform/${platname} ]; then
				rootarchs="${rootarchs} ${platname}"
			fi
			if [ -d ${usr}/platform/${platname} -o \
			    -h ${usr}/platform/${platname} ]; then
				usrarchs="${usrarchs} ${platname}"
			fi
			if [ -h ${root}/platform/${platname} ]; then
				rm -f ${root}/platform/${platname}
			fi
			if [ -h ${usr}/platform/${platname} ]; then
				rm -f ${usr}/platform/${platname}
			fi
		done
	fi
	if [ "$rootfstype" = "ufs" ] ; then
		rootslice=`df -k $root | nawk 'NR > 1 { print $1 }' | \
		    sed s/dsk/rdsk/`
	fi

	print "Loading $cpiodir on $root"
else
	usrroot=$2
	usr=$2/usr
	[[ "$usr" = /export/exec/* ]] || fail "exec-dir $usrroot sounds bogus"
	case $2 in
	    *sparc*)
		target_isa=sparc ;;
	    *i386*)
		target_isa=i386 ;;
	esac
	cd $cpiodir
	test -f generic.root$ZFIX || fail "$cpiodir/generic.root$ZFIX missing"
	allarchs=$(echo $(ls *.root$ZFIX | grep -v generic.root$ZFIX | \
		sed -e 's/.root.*//'))

	if [ $target_isa = i386 -a $archive_type = xpv ]; then
		#
		# On i386, we want to apply the archives for both platforms
		# (i86pc and i86xpv) if they exist.  We force the platform
		# to i86xpv so that both will be applied.
		#
		karch=i86pc
		plat=i86xpv
	else
		# XXX Pick karch as last available root arch
		karch=${allarchs##* }
		# XXX Pick plat as first available root arch
		plat=${allarchs%% *}
	fi

	rootlist=""
	for root in /export/root/*
	do
		test -f $root/etc/vfstab &&
			egrep -s $usrroot $root/etc/vfstab &&
			rootlist="$rootlist $root"
	done
	test -n "$rootlist" || fail "no clients to upgrade"
	print "Loading $cpiodir usr archives on:\n\t$usr\n"
	print "Loading $cpiodir root archives on:"
	for root in $rootlist
	do
		print "\t$root"
	done
fi

if grep '^[ 	]*zfsroot:' $root/etc/system >/dev/null && \
	    archive_file_exists i86pc.boot boot/grub/zfs_stage1_5; then
	echo "Cannot BFU a system with the mountroot version"\
		"of zfs boot support."
	echo "For information on how to transition this system to the new"
	echo "zfs boot support, see:"
	echo "http://www.opensolaris.org/os/community/zfs/boot/zfsboot-manual/mntroot-transition/"
	fail ""
fi

nss_lib="$usr/lib/mps/libnss3.so"
nss_lib64="$usr/lib/mps/64/libnss3.so"
valid_rpath="\$ORIGIN:/usr/lib/mps/secv1:/usr/lib/mps"
rpath_msg="R(UN)?PATH from file ${nss_lib}\)"
if [ ! -x /usr/bin/ldd ]; then
	if [ "$force_override" = yes ]; then
		echo "/usr/bin/ldd is missing but -f is set; continuing."
	else
		echo "/usr/bin/ldd is missing."
		fail "Install the SUNWtoo package."
	fi
fi
nss_rpath=`ldd -s $nss_lib | egrep "$rpath_msg" | head -1 | cut -d'=' -f2 | \
		awk '{print $1}'`
update_script="${GATE}/public/bin/update_nsspkgs"
if [ $valid_rpath != "$nss_rpath" ]; then
	if [ "$force_override" = yes ]; then
		echo "$nss_lib is not valid but -f is set; continuing."
	else
		echo "$nss_lib is not valid."
		fail "Run $update_script to update the SUNWtls package."
	fi
fi
if [ $target_isa = i386 -a ! -f $nss_lib64 ]; then
	echo "$nss_lib64 does not exist."
	fail "Run $update_script to update the NSS packages."
fi

update_script="${GATE}/public/bin/migrate_bind9"
if [[ ! -f $usr/lib/dns/libdns.so ]] && ! $ZCAT $cpiodir/generic.usr$ZFIX | \
	    cpio -it 2>/dev/null |  egrep -s '^usr/sbin/ndc' ; then
	if [ "$force_override" = yes ]; then
		echo "BIND 9 has not been installed, but -f is set; continuing."
	else
		echo "BIND 8 has been removed from ON; BIND 9 is available from SFW."
		fail "Run $update_script to migrate to BIND 9."
	fi
fi

update_script="${GATE}/public/bin/update_ce"
if ifconfig -a | egrep '^ce' >/dev/null 2>/dev/null; then
	# CE version 1.148 or later is required
	cever=`modinfo | grep 'CE Ethernet' | sed 's/.*v1\.//' | tr -d ')' | \
	    nawk '{ if ($1 < 148) print "BAD"; else print $1 }'`
	if [ "$cever" = "BAD" ]; then
		fail "You must run $update_script to upgrade your ce driver."
	fi
fi

update_script="${GATE}/public/bin/update_dbus"
if [ ! -x $usr/lib/dbus-daemon ]; then
	fail "Run $update_script to update D-Bus."
fi

#
# We need biosdev if we're moving from pre-multiboot to multiboot or directboot
# kernels.  If we already have an i86xpv kernel, then we must already be a
# directboot kernel, and can therefore skip the check.
#
if [ $target_isa = i386 ] && [ $multi_or_direct = yes ] && \
    [ $diskless = no ] && [ ! -d /platform/i86xpv/ ]; then
	prtconf -v | grep biosdev >/dev/null 2>&1
	if [ $? -ne 0 ] && [ ! -f $rootprefix/platform/i86pc/multiboot ]; then
		echo "biosdev cannot be run on this machine."
		echo "Transitioning from classic to multiboot requires a"
		echo "bootconf which is compatible with biosdev."
		echo "bfu to onnv_12 first, then to a build with multiboot."
		fail ""
	fi
fi

#
# Check whether the archives have a datalink-management services; this is
# later used to determine whether we need to upgrade the existing datalink
# configuration and if the datalink-management service needs to be removed.
#
if archive_file_exists generic.sbin "sbin/dlmgmtd"; then
	dlmgmtd_exists=true
else
	dlmgmtd_exists=false
fi
#
# Set the value of dlmgmtd_status based on the existence of the
# /sbin/dlmgmtd file
#
dlmgmtd_status=none
if [[ -f $root/sbin/dlmgmtd ]] && ! $dlmgmtd_exists ; then
	dlmgmtd_status=cleanup
elif [[ ! -f $root/sbin/dlmgmtd ]] && $dlmgmtd_exists ; then
	dlmgmtd_status=new
fi

#
# Check whether the archives have an etc/dladm directory; this is
# later used to determine if aggregation.conf needs to be moved.
#
if $ZCAT $cpiodir/generic.root$ZFIX | cpio -it 2>/dev/null | \
    grep etc/dladm > /dev/null 2>&1 ; then
	new_dladm=yes
fi

#
# Check whether the build is boot-archive or ufsboot sparc
# boot based on the existence of a generic.boot archive
#
newboot_sparc=no
if [ $target_isa = sparc -a -f $cpiodir/generic.boot$ZFIX ]; then
	newboot_sparc=yes
fi

time_ref=/tmp/bfu.time_ref.$$
rm -f $time_ref
touch $time_ref || fail "$time_ref: Unable to create time reference."
time_ref_seconds=$SECONDS

print "\nCreating bfu execution environment ..."

#
# Save off a few critical libraries and commands, so that bfu will
# continue to function properly even in the face of major
# kernel/library/command incompatibilities during a live upgrade.
#
bfucmd="
	/usr/bin/awk
	/usr/bin/cat
	/usr/bin/chgrp
	/usr/bin/chmod
	/usr/bin/chown
	/usr/bin/cmp
	/usr/bin/cp
	/usr/bin/cpio
	/usr/bin/csh
	/usr/bin/cut
	/usr/bin/date
	/usr/bin/dd
	/usr/bin/df
	/usr/bin/diff
	/usr/bin/du
	/usr/bin/echo
	/usr/bin/ed
	/usr/bin/egrep
	/usr/bin/env
	/usr/bin/ex
	/usr/bin/expr
	/usr/bin/false
	/usr/bin/fgrep
	/usr/bin/file
	/usr/bin/find
	/usr/bin/gettext
	/usr/bin/grep
	/usr/bin/head
	/usr/bin/id
	/usr/bin/ksh
	/usr/bin/line
	/usr/bin/ln
	/usr/bin/ls
	/usr/bin/mkdir
	/usr/bin/mktemp
	/usr/bin/more
	/usr/bin/mv
	/usr/bin/nawk
	/usr/bin/pgrep
	/usr/bin/pkginfo
	/usr/bin/pkill
	/usr/bin/printf
	/usr/bin/ps
	/usr/bin/ptree
	/usr/bin/rm
	/usr/bin/rmdir
	/usr/bin/sed
	/usr/bin/sh
	/usr/bin/sleep
	/usr/bin/sort
	/usr/bin/strings
	/usr/bin/stty
	/usr/bin/su
	/usr/bin/sum
	/usr/bin/tail
	/usr/bin/tee
	/usr/bin/touch
	/usr/bin/tr
	/usr/bin/true
	/usr/bin/truss
	/usr/bin/tty
	/usr/bin/uname
	/usr/bin/uniq
	/usr/bin/uptime
	/usr/bin/vi
	/usr/bin/w
	/usr/bin/wc
	/usr/bin/xargs
	/usr/bin/zcat
	/usr/sbin/add_drv
	/usr/sbin/chroot
	/usr/sbin/halt
	/usr/sbin/lockfs
	/usr/sbin/lofiadm
	/usr/sbin/mkfile
	/usr/sbin/mkfs
	/usr/sbin/mknod
	/usr/sbin/mount
	/usr/sbin/newfs
	/usr/sbin/pkgrm
	/usr/sbin/prtconf
	/usr/sbin/reboot
	/usr/sbin/sync
	/usr/sbin/tar
	/usr/sbin/uadmin
	/usr/sbin/umount
	/usr/sbin/update_drv
	/usr/sbin/wall
	/usr/sbin/zonecfg
	${FASTFS-$GATE/public/bin/$bfu_isa/fastfs}
	${GZIPBIN-$GATE/public/bin/$bfu_isa/gzip}
"
#
# Conditionally add extract_hostid program to the bfucmd list if we
# are on x86 - to migrate hostid from /kernel/misc/sysinit to /etc/hostid
#
if [ $target_isa = i386 ]; then
    bfucmd="$bfucmd ${EXTRACT_HOSTID-$GATE/public/bin/$bfu_isa/extract_hostid}"
fi

#
# Scripts needed by BFU. These must be modified to use the interpreters in
# /tmp/bfubin. The interpreters in /usr/bin may not be compatible with the
# libraries in the archives being extracted.
#
bfuscr="
	${ACR-${GATE}/public/bin/acr}
"
#
# basename and dirname may be ELF executables, not shell scripts;
# make sure they go into the right list.
#
if `file /usr/bin/basename | grep ELF >/dev/null`
then	bfucmd="$bfucmd /usr/bin/basename"
else	bfuscr="$bfuscr /usr/bin/basename"
fi

if `file /usr/bin/dirname | grep ELF >/dev/null`
then	bfucmd="$bfucmd /usr/bin/dirname"
else	bfuscr="$bfuscr /usr/bin/dirname"
fi

rm -rf /tmp/bfubin
mkdir /tmp/bfubin
set $bfucmd
isalist=`isalist`
while [ $# -gt 0 ]
do
	dir=${1%/*}
	cmd=${1##*/}
	cd $dir
	isacmd=`(find $isalist -name $cmd 2>/dev/null; echo $cmd) | head -1`
	cp $dir/$isacmd /tmp/bfubin || fail "cannot copy $dir/$isacmd"
	shift
done

#
# Optional commands.  We warn, but do not abort, if we are crossing a
# feature boundary (where a command is not present in the parent).
# Clauses requiring these commands must explicitly test for their
# presence in /tmp/bfubin.
#
bfuoptcmd="
	/sbin/biosdev
	/sbin/bootadm
	/sbin/installgrub
	/usr/sbin/fdisk
	/usr/sbin/metastat
	/usr/bin/mkisofs
	/usr/sbin/svcadm
	/usr/sbin/svccfg
	/usr/bin/svcprop
	/usr/bin/svcs
"

set $bfuoptcmd
isalist=`isalist`
while [ $# -gt 0 ]
do
	dir=${1%/*}
	cmd=${1##*/}
	cd $dir
	isacmd=`(find $isalist -name $cmd 2>/dev/null; echo $cmd) | head -1`
	cp $dir/$isacmd /tmp/bfubin 2>/dev/null
	shift
done


#
# set up installgrub and friends if transitioning to multiboot or directboot
# do this now so ldd can determine library dependencies
#
# We split the binaries into two groups: the type where we want to make any
# effort to get the newest version (like symdef and bootadm), and the type
# where any old version will do (like installgrub and biosdev).
#
# If we're bfu'ing across the directboot/multiboot boundary, we need the new
# bootadm and symdef to properly handle menu.lst changes.  If the system is
# directboot, we can use the local copies.  If the system is multiboot but
# the archives are directboot, we extract the binaries early.  Otherwise,
# we're not crossing the boundary, and which one we use doesn't matter.
#
# NB - if bootadm or symdef is ever changed to require a new library, the
# early extraction will blow up horribly.
#
# For testing purposes, a user can set DIRECTBOOT_BIN_DIR in the environment,
# and we'll use that instead.
#
MULTIBOOT_BIN_DIR=${MULTIBOOT_BIN_DIR:=${GATE}/public/multiboot}
have_new_bootadm=unknown

if [ -f "$root/platform/i86xpv/kernel/unix" ]; then
	root_is_xpv=yes
	root_is_directboot=yes
elif [ -x "$root/boot/solaris/bin/symdef" ] && \
    "$root"/boot/solaris/bin/symdef "$root/platform/i86pc/kernel/unix" \
    dboot_image; then
	root_is_xpv=no
	root_is_directboot=yes
else
	root_is_xpv=no
	root_is_directboot=no
fi

#
# A comma-separated list of the command and the archive it's in
#
multiboot_new_cmds="
	sbin/bootadm,generic.sbin
	boot/solaris/bin/symdef,i86pc.boot
"

if [ $multi_or_direct = yes ]; then
	for line in $multiboot_new_cmds
	do
		cmd=${line%,*}
		file=${cmd##*/}
		archive=${line#*,}
		if [ -n "$DIRECTBOOT_BIN_DIR" ] && \
		    [ -f $DIRECTBOOT_BIN_DIR/$file ]; then
			cp $DIRECTBOOT_BIN_DIR/$file /tmp/bfubin/
		else
			if [[ $root_is_xpv = yes ||
			    $root_is_directboot = yes &&
			    $archive_type = multiboot ]]; then
				cp $root/$cmd /tmp/bfubin/
				have_new_bootadm=yes
			elif [ $archive_type = directboot ] || \
			    [ $archive_type = xpv ]; then
				DBOOT_TMPDIR=/tmp/dboot.$$
				trap "rm -rf $DBOOT_TMPDIR" EXIT
				OLD_PWD=$(pwd)
				rm -rf $DBOOT_TMPDIR
				mkdir $DBOOT_TMPDIR
				cd $DBOOT_TMPDIR
				$ZCAT $cpiodir/${archive}$ZFIX | \
				    cpio -id "$cmd" 2>/dev/null
				if [ -x $cmd ]; then
					cp $cmd /tmp/bfubin/
					have_new_bootadm=yes
				fi
				cd $OLD_PWD
				rm -rf $DBOOT_TMPDIR
				trap - EXIT
			fi
		fi

		#
		# If all else fails, grab the local version
		#
		if [ ! -x /tmp/bfubin/$file ]; then
			[ -x /$cmd ] && cp /$cmd /tmp/bfubin
		fi
	done
	if [ $archive_type = directboot ] && [ $root_is_directboot = yes ]; then
		cleanup_eeprom_console
	fi
fi

multiboot_cmds="
	/sbin/biosdev
	/sbin/installgrub
"
copying_mboot_cmds=no
if [ $multi_or_direct = yes ]; then
	for cmd in $multiboot_cmds
	do
		file=`basename $cmd`
		if [ -f $cmd ]; then
			cp $cmd /tmp/bfubin
		elif [ -n "$DIRECTBOOT_BIN_DIR" ] &&
		    [ -d $DIRECTBOOT_BIN_DIR ] &&
		    [ -x $DIRECTBOOT_BIN_DIR/$file ]; then
			cp $DIRECTBOOT_BIN_DIR/$file /tmp/bfubin/
		else
			if [ ! -d $MULTIBOOT_BIN_DIR ]; then
				echo "$MULTIBOOT_BIN_DIR: not found"
			elif [ ! -f $MULTIBOOT_BIN_DIR/$file ]; then
				echo "$MULTIBOOT_BIN_DIR/$file: not found"
			fi
			if [ $copying_mboot_cmds = no ]; then
				echo "installing files from $MULTIBOOT_BIN_DIR"
				copying_mboot_cmds=yes
			fi
			cp $MULTIBOOT_BIN_DIR/$file /tmp/bfubin
		fi

	done
fi

#
# If available, use ldd to determine which libraries bfu depends on.
# Otherwise, just make an educated guess.
#
if [ -x /usr/bin/ldd ]; then
	bfulib="`ldd /tmp/bfubin/* | nawk '$3 ~ /lib/ { print $3 }' | sort -u`"
else
	bfulib="
		/lib/libc.so.1
		/lib/libm.so.2
		/lib/libdoor.so.1
		/lib/libm.so.2
		/lib/libmd.so.1
		/lib/libmd5.so.1
		/lib/libnvpair.so.1
		/lib/libscf.so.1
		/lib/libuutil.so.1
		/usr/lib/libbsm.so.1
		/usr/lib/libc2.so
		/usr/lib/libdl.so.1
		/usr/lib/libelf.so.1
		/usr/lib/libkstat.so.1
		/usr/lib/libmapmalloc.so.1
		/usr/lib/libmp.so.1
		/usr/lib/libnsl.so.1
		/usr/lib/libpam.so.1
		/usr/lib/libsec.so.1
		/usr/lib/libsocket.so.1
		/usr/lib/libtecla.so.1
	"
fi

# add dlopen()'ed stuff
bfulib="
	$bfulib
	/lib/ld.so.1
	/usr/lib/nss_*
"

# add libc_psr.so.1, if available and not empty
if [ -s /platform/`uname -i`/lib/libc_psr.so.1 ]; then
	bfulib="
		$bfulib
		/platform/`uname -i`/lib/libc_psr.so.1
	"
fi

rm -rf /tmp/bfulib /tmp/bl
mkdir /tmp/bfulib /tmp/bl

#
# Create 64 bit directory structure and determine 64 bit arch name.
#
if [ -h /usr/lib/64 ]
then
	link=`ls -dl /usr/lib/64  | awk '{print $NF}'`
	ln -s $link /tmp/bfulib/64
	ln -s $link /tmp/bl/64
	mkdir /tmp/bfulib/$link /tmp/bl/$link
	bfulib="$bfulib /usr/lib/64/nss_*"
	#
	# Copy libraries to proper directories
	#
	for lib in $bfulib
	do
		case $lib in
		*/64/* | */$link/*)
			cp $lib /tmp/bfulib/64;;
		*)
			cp $lib /tmp/bfulib;;
		esac
	done
	#
	# Private 64 bit runtime linker.
	#
	cp /lib/64/ld.so.1 /tmp/bfulib/64/bf.1
	cp /lib/64/ld.so.1 /tmp/bl/64/bf.1
else
	cp $bfulib /tmp/bfulib
fi
cp /lib/ld.so.1 /tmp/bfulib/bf.1	# bfu's private runtime linker
cp /lib/ld.so.1 /tmp/bl/bf.1

${BFULD-$GATE/public/bin/$bfu_isa/bfuld} /tmp/bfubin/* || fail "bfuld failed"

for x in $bfuscr
do
	sed -e 's/\/usr\/bin\//\/tmp\/bfubin\//g' \
	    -e 's/\/bin\//\/tmp\/bfubin\//g' < $x > /tmp/bfubin/`basename $x`
	chmod +x /tmp/bfubin/`basename $x`
done

#
# scripts used together with multiboot
#
multiboot_scr="
	/boot/solaris/bin/create_ramdisk
	/boot/solaris/bin/create_diskmap
	/boot/solaris/bin/root_archive
"

if [ $multi_or_direct = yes ]; then
	for cmd in $multiboot_scr
	do
		file=`basename $cmd`
		if [ -f $cmd ]; then
			cp $cmd /tmp/bfubin
		else
			if [ ! -d $MULTIBOOT_BIN_DIR ]; then
				echo "$MULTIBOOT_BIN_DIR: not found"
				fail ""
			fi

			if [ ! -f $MULTIBOOT_BIN_DIR/$file ]; then
				echo "$MULTIBOOT_BIN_DIR/$file: not found"
				fail ""
			fi
			echo "copying $file from $MULTIBOOT_BIN_DIR"
			cp $MULTIBOOT_BIN_DIR/$file /tmp/bfubin
		fi

		#
		# We do two substitutions here to replace references to
		# both /usr/bin/ and /bin/ with /tmp/bfubin/
		#
		mv /tmp/bfubin/${file} /tmp/bfubin/${file}-
		sed -e 's/\/usr\/bin\//\/tmp\/bfubin\//g' \
		    -e 's/\/bin\//\/tmp\/bfubin\//g' \
		    < /tmp/bfubin/${file}- > /tmp/bfubin/${file}
		chmod +x /tmp/bfubin/${file}
	done
fi

#
# For directboot archives, /boot/platform/i86pc/kernel/unix will be
# overwritten, which could cause a mis-match with the failsafe
# miniroot.  Extract unix from the miniroot and save it off for now.
#
if [ $archive_type = directboot ] && [ $diskless = no ]; then
	if gunzip -c "$root/boot/x86.miniroot-safe" \
	    >/tmp/bfubin/miniroot-unzipped; then
		lofifile=/tmp/bfubin/miniroot-unzipped
	else
		# Shouldn't happen?  See if someone already unzipped it.
		lofifile="$root/boot/x86.miniroot-safe"
	fi
	lofidev=`lofiadm -a $lofifile 2>/dev/null`
	if [ -n "$lofidev" ]; then
		mkdir /tmp/bfubin/mnt
		mount -r $lofidev /tmp/bfubin/mnt

		unix=/tmp/bfubin/mnt/boot/platform/i86pc/kernel/unix
		if [ -f $unix ]; then
			cp $unix /tmp/bfubin/unix
			failsafe_type=directboot
		elif [ -f /tmp/bfubin/mnt/platform/i86pc/multiboot ]
		then
			failsafe_type=multiboot
		fi

		umount /tmp/bfubin/mnt
		rmdir /tmp/bfubin/mnt
		lofiadm -d $lofidev
	fi
	rm -f /tmp/bfubin/miniroot-unzipped
fi

revert_aggregation_conf()
{
	aggrconf=$rootprefix/etc/aggregation.conf
	nawk '
		/^[ \t]*#/ || /^[ \t]*$/ || $4 ~ "/0" {
			print;
			next;
		}

		{
			OFS="\t";
			gsub(/[^,]*/, "&/0", $4);
			print;
		}' $aggrconf > $aggrconf.bfutmp
	mv -f $aggrconf.bfutmp $aggrconf
}

remove_initd_links()
{
	# If we're delivering a new version of an existing /etc/init.d script,
	# remove all hard links to the existing file in /etc/rc?.d whose
	# names begin with [SK][0-9][0-9].  Additionally, in case an S or K
	# file was previously delivered as a symbolic link or the hard link
	# was broken, remove any file in /etc/rc?.d whose name is
	# [SK][0-9][0-9] followed by the basename of the file we're going
	# to update in /etc/init.d.

	print "Removing init.d links ... \c"
	scripts=`$ZCAT $cpiodir/generic.root$ZFIX |
		cpio -it 2>/dev/null | grep '^etc/init\.d/'`
	if [ -n "$scripts" ]; then
		inodes=`ls -li $scripts 2>/dev/null | \
			nawk '{ print "-inum " $1 " -o " }'`
		names=`ls -1 $scripts 2>/dev/null | \
			nawk -F/ '{ print "-name [SK][0-9][0-9]" $NF }'`
		find etc/rc?.d \( $inodes $names \) -print | xargs rm -f
	fi
	print "done."
}

#
# Remove the old 5.005_03 version of perl.
#
remove_perl_500503()
{
	# Packages to remove.
	typeset -r perl_pkgs='SUNWopl5m SUNWopl5p SUNWopl5u'
	typeset pkg

	#
	# First, attempt to remove the packages cleanly if possible.
	#
	printf 'Removing perl 5.005_03 packages'
	for pkg in $perl_pkgs
	do
		if pkginfo $pkgroot -q $pkg; then
			printf ' %s' $pkg
			pkgrm $pkgroot -n $pkg >/dev/null 2>&1
		fi
	done
	printf '\n'

	#
	# In case that didn't work, do it manually.
	#
	printf 'Removing perl 5.005_03 from %s/var/sadm/install/contents' \
	    $rootprefix
	for pkg in $PKGS
	do
		printf ' %s' $pkg
		if [ -d $rootprefix/var/sadm/pkg/$pkg ]; then
			rm -rf $rootprefix/var/sadm/pkg/$pkg
			grep -vw $pkg $rootprefix/var/sadm/install/contents > \
			    /tmp/contents.$$
			cp /tmp/contents.$$ /var/sadm/install/contents.$$
			rm /tmp/contents.$$
		fi
	done
	printf '\n'

	#
	# Remove any remaining 5.005_03 files,
	#
	printf 'Removing perl 5.005_03 from %s/perl5\n' $usr

	# Directories.
	rm -rf $usr/perl5/5.00503
	rm -rf $usr/perl5/site_perl/5.005
}

#
# Remove Wildcat (aka Sun Fire Link)
#
remove_eof_wildcat()
{
	# Packages to remove
	typeset -r wildcat_pkgs='SUNWwrsa SUNWwrsd SUNWwrsu SUNWwrsm'
	typeset pkg

	#
	# First, attempt to remove the packages cleanly if possible.
	# Use a custom "admin" file to specify that removal scripts
	# in the packages being removed should be run even if they
	# will run as root.
	#
	typeset -r admfile='/tmp/wcat_eof.$$'
	echo "action=nocheck" > $admfile

	printf 'Removing Wildcat packages...'
	for pkg in $wildcat_pkgs
	do
		if pkginfo $pkgroot -q $pkg; then
			printf ' %s' $pkg
			pkgrm $pkgroot -n -a $admfile $pkg >/dev/null 2>&1
		fi
	done
	printf '\n'

	#
	# In case that didn't work, do it manually.
	#
	printf 'Removing Wildcat from %s/var/sadm/install/contents...' \
	    $rootprefix
	for pkg in $wildcat_pkgs
	do
		printf ' %s' $pkg
		if [ -d $rootprefix/var/sadm/pkg/$pkg ]; then
			rm -rf $rootprefix/var/sadm/pkg/$pkg
			grep -vw $pkg $rootprefix/var/sadm/install/contents > \
			    /tmp/contents.$$
			cp /tmp/contents.$$ \
			    $rootprefix/var/sadm/install/contents
			rm /tmp/contents.$$
		fi
	done
	printf '\n'

	#
	# Cleanup any remaining Wildcat files, symlinks, and directories.
	#
	rm -f $usr/platform/sun4u/include/sys/wci_common.h
	rm -f $usr/platform/sun4u/include/sys/wci_regs.h
	rm -f $usr/platform/sun4u/include/sys/wci_offsets.h
	rm -f $usr/platform/sun4u/include/sys/wci_cmmu.h
	rm -f $usr/platform/sun4u/include/sys/wrsm.h
	rm -f $usr/platform/sun4u/include/sys/wrsm_common.h
	rm -f $usr/platform/sun4u/include/sys/wrsm_config.h
	rm -f $usr/platform/sun4u/include/sys/wrsm_types.h
	rm -f $usr/platform/sun4u/include/sys/wrsm_plat.h
	rm -f $usr/platform/sun4u/include/sys/wrsm_plugin.h
	rm -f $usr/platform/sun4u/include/sys/wrsmconf.h

	rm -f $usr/platform/sun4u/lib/mdb/kvm/sparcv9/wrsm.so
	rm -f $usr/platform/sun4u/lib/mdb/kvm/sparcv9/wrsmd.so

	rm -f $rootprefix/platform/SUNW,Sun-Fire-15000/kernel/misc/sparcv9/gptwo_wci

	rm -f $rootprefix/platform/sun4u/kernel/kmdb/sparcv9/wrsm
	rm -f $rootprefix/platform/sun4u/kernel/kmdb/sparcv9/wrsmd

	rm -f $admfile
}

#
# Remove ASET
#
remove_eof_aset()
{
	# Packages to remove
	typeset -r aset_pkgs='SUNWast'
	typeset pkg

	printf 'Removing ASET... '

	#
	# First, attempt to remove the packages cleanly if possible.
	#
	for pkg in $aset_pkgs
	do
		if pkginfo $pkgroot -q $pkg; then
			printf ' %s' $pkg
			pkgrm $pkgroot -n $pkg >/dev/null 2>&1
		fi
	done
	printf '\n'

	#
	# In case that didn't work, do it manually.
	# Remove ASET from $rootprefix/var/sadm/install/contents
	#
	for pkg in $aset_pkgs
	do
		if [ -d $rootprefix/var/sadm/pkg/$pkg ]; then
			rm -rf $rootprefix/var/sadm/pkg/$pkg
			grep -vw $pkg $rootprefix/var/sadm/install/contents > \
			    /tmp/contents.$$
			cp /tmp/contents.$$ $rootprefix/var/sadm/install/contents.$$
			rm /tmp/contents.$$
		fi
	done

	#
	# Cleanup any remaining ASET files, symlinks, and directories.
	#
	rm -rf $usr/aset
}

#
# Remove BIND 8 named server/tools packages
#
remove_eof_bind8()
{
	# Packages to remove
	typeset -r bind8_pkg='SUNWinamd'
	typeset pkg

	printf 'Removing BIND 8 named server/tools... '

	#
	# We cann't pkgrm SUNWinamd at this time as the BIND 9 binaries are
	# already in /usr/sbin.
	# Remove BIND 8 packages from $rootprefix/var/sadm/install/contents
	#
	for pkg in $bind8_pkgs
	do
		if [ -d $rootprefix/var/sadm/pkg/$pkg ]; then
			rm -rf $rootprefix/var/sadm/pkg/$pkg
			grep -vw $pkg $rootprefix/var/sadm/install/contents > \
			    /tmp/contents.$$
			cp /tmp/contents.$$ /var/sadm/install/contents.$$
			rm /tmp/contents.$$
		fi
	done

	#
	# Cleanup any BIND 8 specific files, symlinks.
	#

	# files and symlinks.
	rm -f $usr/sbin/named-xfer
	rm -f $usr/lib/nslookup.help
	rm -f $usr/sbin/dnskeygen
	rm -f $usr/sbin/named-bootconf
	rm -f $usr/sbin/nstest
	rm -rf $rootprefix/var/run/ndc.d
	printf 'done.\n'
}

#
# Remove the 5.8.3 version of perl.
#
remove_perl_583()
{
	#
	# Copy perl 5.8.3 into the new 5.8.4 locations.  This will preserve
	# any add-on modules that might have been installed, and any 5.8.3
	# core files that get copied over will be replaced by the new 5.8.4
	# versions when the cpio archives are subsequently extracted.
	#
	printf 'Preserving user-installed perl modules...\n'
	mkdir -p $usr/perl5/5.8.4
	cp -rp $usr/perl5/5.8.3/* \
	    $usr/perl5/5.8.4
	mkdir -p $usr/perl5/site_perl/5.8.4
	cp -rp $usr/perl5/site_perl/5.8.3/* \
	    $usr/perl5/site_perl/5.8.4
	mkdir -p $usr/perl5/vendor_perl/5.8.4
	cp -rp $usr/perl5/vendor_perl/5.8.3/* \
	    $usr/perl5/vendor_perl/5.8.4

	#
	# Update the #! lines in any scripts in /usr/perl5/5.8.4/bin to refer
	# to 5.8.4 instead of 5.8.3.  Take care to edit only scripts.
	#
	typeset bindir="$usr/perl5/5.8.4/bin"
	typeset script
	for script in $(ls $bindir); do
		script="$bindir/$script"
		if [[ $script = "$usr/perl5/5.8.4/bin/perl5.8.3" ]]; then
			rm -f $script
		elif file $script | \
		    egrep -s 'executable .*perl .*script'; then
			sed -e \
			    's!/usr/perl5/5.8.3/bin/perl!/usr/perl5/5.8.4/bin/perl!g' \
			    < $script > $script.tmp
			mv -f $script.tmp $script
		fi
	done

	#
	# Packages to remove.
	#
	typeset -r perl_pkgs='SUNWperl583man SUNWperl583usr SUNWperl583root'

	#
	# First, attempt to remove the packages cleanly if possible.
	#
	typeset pkg
	printf 'Removing perl 5.8.3 packages'
	for pkg in $perl_pkgs
	do
		if pkginfo $pkgroot -q $pkg; then
			printf ' %s' $pkg
			pkgrm $pkgroot -n $pkg >/dev/null 2>&1
		fi
	done
	printf '\n'

	#
	# In case that didn't work, do it manually.
	#
	printf 'Removing perl 5.8.3 from %s/var/sadm/install/contents' \
	    $rootprefix
	for pkg in $PKGS
	do
		printf ' %s' $pkg
		if [ -d $rootprefix/var/sadm/pkg/$pkg ]; then
			rm -rf $rootprefix/var/sadm/pkg/$pkg
			grep -vw $pkg $rootprefix/var/sadm/install/contents > \
			    /tmp/contents.$$
			cp /tmp/contents.$$ /var/sadm/install/contents.$$
			rm /tmp/contents.$$
		fi
	done
	printf '\n'

	#
	# Remove any remaining 5.8.3 files,
	# and fix up the symlinks if necessary.
	#
	printf 'Removing perl 5.8.3 from %s/perl5\n' $usr

	# Directories.
	rm -rf $usr/perl5/5.8.3
	rm -rf $usr/perl5/site_perl/5.8.3
	rm -rf $usr/perl5/vendor_perl/5.8.3

	# bin symlink.
	rm -f $usr/perl5/bin
	ln -s ./5.8.4/bin $usr/perl5/bin

	# pod symlink.
	rm -f $usr/perl5/pod
	ln -s ./5.8.4/lib/pod $usr/perl5/pod

	#
	# man symlink.  In earlier S10 builds the man symlink mistakenly points
	# to the 5.6.1 manpages, instead of 5.8.3.  Fix to point to 5.8.4.
	#
	rm -f $usr/perl5/man
	ln -s ./5.8.4/man $usr/perl5/man

	# Symlink /bin/perl to 5.8.4.
	rm -f $usr/bin/perl
	ln -s ../perl5/5.8.4/bin/perl $usr/bin/perl
}

#
# Remove FNS/XFN packages
#
remove_eof_fns()
{
	# Packages to remove
	typeset -r fns_pkgs='SUNWfnx5x SUNWfnsx5 SUNWfnsx SUNWfns'
	typeset pkg

	printf 'Removing FNS/XFN ... '

	#
	# First, attempt to remove the packages cleanly if possible.
	#
	for pkg in $fns_pkgs
	do
		if pkginfo $pkgroot -q $pkg; then
			printf ' %s' $pkg
			pkgrm $pkgroot -n $pkg >/dev/null 2>&1
		fi
	done
	printf '\n'

	#
	# In case that didn't work, do it manually.
	# Remove FNS/XFN from $rootprefix/var/sadm/install/contents
	#
	for pkg in $fns_pkgs
	do
		if [ -d $rootprefix/var/sadm/pkg/$pkg ]; then
			rm -rf $rootprefix/var/sadm/pkg/$pkg
			grep -vw $pkg $rootprefix/var/sadm/install/contents > \
			    /tmp/contents.$$
			cp /tmp/contents.$$ $rootprefix/var/sadm/install/contents.$$
			rm /tmp/contents.$$
		fi
	done

	#
	# Cleanup if any remaining FNS/XFN files, symlinks, and directories.
	#

	# directories.
	rm -rf $rootprefix/etc/fn
	rm -rf $usr/include/xfn
	rm -rf $usr/lib/fn
	rm -rf $rootprefix/var/fn

	# files and symlinks.
	rm -f $rootprefix/etc/fn.conf
	rm -f $usr/bin/fnattr
	rm -f $usr/bin/fnbind
	rm -f $usr/bin/fncreate_printer
	rm -f $usr/bin/fnlist
	rm -f $usr/bin/fnlookup
	rm -f $usr/bin/fnrename
	rm -f $usr/bin/fnsearch
	rm -f $usr/bin/fnunbind
	rm -f $usr/sbin/fncheck
	rm -f $usr/sbin/fncopy
	rm -f $usr/sbin/fncreate
	rm -f $usr/sbin/fncreate_fs
	rm -f $usr/sbin/fndestroy
	rm -f $usr/sbin/fnselect
	rm -f $usr/sbin/fnsypd
	rm -f $usr/lib/libfn_p.so
	rm -f $usr/lib/libfn_p.so.1
	rm -f $usr/lib/libfn_spf.so
	rm -f $usr/lib/libfn_spf.so.1
	rm -f $usr/lib/libxfn.so
	rm -f $usr/lib/libxfn.so.1
	rm -f $usr/lib/libxfn.so.2
	rm -f $usr/lib/sparcv9/libfn_p.so
	rm -f $usr/lib/sparcv9/libfn_p.so.1
	rm -f $usr/lib/sparcv9/libfn_spf.so
	rm -f $usr/lib/sparcv9/libfn_spf.so.1
	rm -f $usr/lib/sparcv9/libxfn.so
	rm -f $usr/lib/sparcv9/libxfn.so.1
	rm -f $usr/lib/sparcv9/libxfn.so.2
}

remove_eof_face() {
	# Packages to remove
	typeset -r face_pkgs='SUNWfac'
	typeset pkg

	printf 'Removing AT&T FACE... '

	#
	# First, attempt to remove the packages cleanly if possible.
	#
	for pkg in $face_pkgs
	do
		if pkginfo $pkgroot -q $pkg; then
			printf ' %s' $pkg
			pkgrm $pkgroot -n $pkg >/dev/null 2>&1
		fi
	done
	printf '\n'

	#
	# In case that didn't work, do it manually.
	# Remove FACE from $rootprefix/var/sadm/install/contents
	#
	for pkg in $face_pkgs
	do
		if [ -d $rootprefix/var/sadm/pkg/$pkg ]; then
			rm -rf $rootprefix/var/sadm/pkg/$pkg
			grep -vw $pkg $rootprefix/var/sadm/install/contents > \
			    /tmp/contents.$$
			cp /tmp/contents.$$ $rootprefix/var/sadm/install/contents.$$
			rm /tmp/contents.$$
		fi
	done

	#
	# Cleanup any remaining FACE files, symlinks, and directories.
	#
	rm -rf $usr/oasys
	rm -rf $usr/vmsys
}

remove_eof_dmi() {
	# Packages to remove
	typeset -r dmi_pkgs='SUNWsadmi'
	typeset pkg

	printf 'Removing DMI... '

	#
	# First, attempt to remove the packages cleanly if possible.
	#
	for pkg in $dmi_pkgs
	do
		if pkginfo $pkgroot -q $pkg; then
			printf ' %s' $pkg
			pkgrm $pkgroot -n $pkg >/dev/null 2>&1
		fi
	done
	printf '\n'

	#
	# In case that didn't work, do it manually.
	# Remove DMI from $rootprefix/var/sadm/install/contents
	#
	for pkg in $dmi_pkgs
	do
		if [ -d $rootprefix/var/sadm/pkg/$pkg ]; then
			rm -rf $rootprefix/var/sadm/pkg/$pkg
			grep -vw $pkg $rootprefix/var/sadm/install/contents > \
			    /tmp/contents.$$
			cp /tmp/contents.$$ $rootprefix/var/sadm/install/contents.$$
			rm /tmp/contents.$$
		fi
	done

	#
	# Cleanup any remaining DMI files, symlinks, and directories.
	#
	rm -rf $usr/lib/dmi
	rm -rf $rootprefix/var/dmi
	rm -rf $rootprefix/etc/dmi
	rm -f $usr/lib/libdmi.so
	rm -f $usr/lib/libdmici.so
	rm -f $usr/lib/libdmimi.so
	rm -f $usr/lib/libdmi.so.1
	rm -f $usr/lib/libdmici.so.1
	rm -f $usr/lib/libdmimi.so.1
	rm -f $usr/lib/sparcv9/libdmi.so
	rm -f $usr/lib/sparcv9/libdmici.so
	rm -f $usr/lib/sparcv9/libdmimi.so
	rm -f $usr/lib/sparcv9/libdmi.so.1
	rm -f $usr/lib/sparcv9/libdmici.so.1
	rm -f $usr/lib/sparcv9/libdmimi.so.1
	rm -f $usr/lib/amd64/libdmi.so
	rm -f $usr/lib/amd64/libdmici.so
	rm -f $usr/lib/amd64/libdmimi.so
	rm -f $usr/lib/amd64/libdmi.so.1
	rm -f $usr/lib/amd64/libdmici.so.1
	rm -f $usr/lib/amd64/libdmimi.so.1
	rm -f $usr/sbin/dmi_cmd
	rm -f $usr/sbin/dmiget
	rm -f $rootprefix/etc/init.d/init.dmi
	rm -f $rootprefix/etc/rc0.d/K07dmi
	rm -f $rootprefix/etc/rc1.d/K07dmi
	rm -f $rootprefix/etc/rc2.d/K07dmi
	rm -f $rootprefix/etc/rcS.d/K07dmi
	rm -f $rootprefix/etc/rc3.d/S77dmi
}

#
# Remove vold
#
remove_eof_vold()
{
	printf 'Removing vold... '

	rm -rf $usr/lib/vold
	rm -rf $usr/lib/rmmount
	rm -f $usr/lib/fs/hsfs/ident_hsfs.so.1
	rm -f $usr/lib/fs/pcfs/ident_pcfs.so.1
	rm -f $usr/lib/fs/udfs/ident_udfs.so.1
	rm -f $usr/lib/fs/ufs/ident_ufs.so.1
	rm -f $usr/sbin/vold
	rm -f $usr/kernel/drv/vol
	rm -f $usr/kernel/drv/amd64/vol
	rm -f $usr/kernel/drv/sparcv9/vol
	rm -f $usr/include/rmmount.h
	rm -f $usr/include/vol.h
	rm -f $rootprefix/etc/vold.conf
	rm -f $rootprefix/etc/rmmount.conf

	printf '\n'
}

#
# Remove the obsolete Mobile IP packages
#
remove_eof_mobileip() {
	typeset -r mip_pkgs='SUNWmipr SUNWmipu'
	typeset pkg

	printf 'Removing Mobile IP... '

	for pkg in $mip_pkgs
	do
		if pkginfo $pkgroot -q $pkg; then
			printf ' %s' $pkg
			pkgrm $pkgroot -n $pkg >/dev/null 2>&1
		fi
	done

	# In case that did not work, do it manually.
	if [[ -d $rootprefix/var/sadm/pkg/SUNWmipr ]]; then
		rm -f "$rootprefix/etc/inet/mipagent.conf-sample"
		rm -f "$rootprefix/etc/inet/mipagent.conf.fa-sample"
		rm -f "$rootprefix/etc/inet/mipagent.conf.ha-sample"
		rm -f "$rootprefix/etc/init.d/mipagent"
		rm -f "$rootprefix/etc/rc0.d/K06mipagent"
		rm -f "$rootprefix/etc/rc1.d/K06mipagent"
		rm -f "$rootprefix/etc/rc2.d/K06mipagent"
		rm -f "$rootprefix/etc/rc3.d/S80mipagent"
		rm -f "$rootprefix/etc/rcS.d/K06mipagent"
		rm -f "$rootprefix/etc/snmp/conf/mipagent.acl"
		rm -f "$rootprefix/etc/snmp/conf/mipagent.reg"
	fi
	if [[ -d $rootprefix/var/sadm/pkg/SUNWmipu ]]; then
		rm -f "$rootprefix/usr/lib/inet/mipagent"
		rm -f "$rootprefix/usr/sbin/mipagentconfig"
		rm -f "$rootprefix/usr/sbin/mipagentstat"
	fi
	printf '\n'
}

remove_properties() {

	#
	# Remove obsolete smartii setprop from bootenv.rc
	#
	srcbootenvrc=$root/boot/solaris/bootenv.rc
	tmpbootenvrc=/tmp/tmp.bootenvrc.$$

	# Don't touch bootenv.rc unless it contains obsolete property
	egrep -s 'target-driver-for-smartii' $srcbootenvrc 2>/dev/null
	res=$?
	if [ -f $srcbootenvrc -a $res -eq 0 ]; then
		egrep -v "target-driver-for-smartii"\
			$srcbootenvrc > $tmpbootenvrc 2>/dev/null
		cp $tmpbootenvrc $srcbootenvrc
	fi
	rm -f $tmpbootenvrc
}

rbac_cleanup()
{
# This is a copy of the RBAC portions of the SUNWcsr postinstall
# We need to ensure that the RBAC profiles are self-consistent
# as refinements are made that add granularity to the profiles

	print "Cleaning up old RBAC profiles... \c"
	auth_attr=$rootprefix/etc/security/auth_attr
	exec_attr=$rootprefix/etc/security/exec_attr

	if [ -f $auth_attr ]; then
		sed '/^solaris\.\*/d' $auth_attr > /tmp/a.$$
		cp /tmp/a.$$ $auth_attr
		rm -f /tmp/a.$$
	fi

	if [ -f $exec_attr ]; then
		sed -e '/^Network Security.*sbin\/ipsec.*/ D' \
		-e '/^Network Security.*sbin\/ike.*/ D' \
		-e '/^Network Security.*inet\/in\.iked.*/ D' \
		-e '/^Network Security.*inet\/cert.*/ D' $exec_attr > /tmp/e.$$
		cp /tmp/e.$$ $exec_attr
		rm -f /tmp/e.$$
	fi
	print "\n"
}

remove_eof_SUNWcry()
{
	print "SUNWcry/SUNWcryr removal cleanup...\n"

	# This clean up of ipsecalgs is not directly related to the EOF
	# of SUNWcry and SUWNcryr, but due to mistakes in this file seen
	# in earlier builds. The following lines will have no effect on
	# most machines.

	ipsecalgs=$rootprefix/etc/inet/ipsecalgs

	cp $ipsecalgs ${ipsecalgs}.tmp

	sed -e 's/_CBC|128\/32-128,8/_CBC|128\/32-448,8/' \
	    -e 's/AES_CBC|128|/AES_CBC|128\/128-256,64|/' \
	    $ipsecalgs > ${ipsecalgs}.tmp

	mv -f ${ipsecalgs}.tmp $ipsecalgs

	# Packages to remove.
	typeset -r sunwcry_pkgs='SUNWcry SUNWcryr'
	typeset pkg

	#
	# First, attempt to remove the packages cleanly if possible.
	# Use a custom "admin" file to specify that removal scripts
	# in the packages being removed should be run even if they
	# will run as root.

	typeset -r admfile='/tmp/sunwcry_eof.$$'
	cat > $admfile <<- EOF
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

	printf '    Removing packages...'
	for pkg in $sunwcry_pkgs
	do
		if pkginfo $pkgroot -q $pkg; then
			printf ' %s' $pkg
			pkgrm $pkgroot -n -a $admfile $pkg >/dev/null 2>&1
		fi
	done
	printf '\n'

	# SUNWcry/SUNWcryr contents go away, if pkgrm didn't take
	# care of them.
	# The userland modules, kernel modules and OpenSSL filter libs
	rm -f $rootprefix/usr/lib/security/pkcs11_softtoken_extra.so.1
	rm -f $rootprefix/usr/lib/security/pkcs11_softtoken_extra.so
	rm -f $rootprefix/usr/lib/security/sparcv9/pkcs11_softtoken_extra.so.1
	rm -f $rootprefix/usr/lib/security/sparcv9/pkcs11_softtoken_extra.so
	rm -f $rootprefix/usr/lib/security/amd64/pkcs11_softtoken_extra.so.1
	rm -f $rootprefix/usr/lib/security/amd64/pkcs11_softtoken_extra.so

	rm -f $rootprefix/kernel/crypto/aes256
	rm -f $rootprefix/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/kernel/crypto/amd64/aes256
	rm -f $rootprefix/platform/SUNW,A70/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Netra-CP3010/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Netra-T12/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Netra-T4/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,SPARC-Enterprise/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Sun-Blade-1000/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Sun-Blade-1500/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Sun-Blade-2500/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Sun-Fire-15000/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Sun-Fire-280R/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Sun-Fire-480R/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Sun-Fire-880/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Sun-Fire-V215/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Sun-Fire-V240/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Sun-Fire-V250/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Sun-Fire-V440/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Sun-Fire-V445/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/SUNW,Sun-Fire/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/platform/sun4u-us3/kernel/crypto/sparcv9/aes256
	rm -f $rootprefix/kernel/crypto/arcfour2048
	rm -f $rootprefix/kernel/crypto/sparcv9/arcfour2048
	rm -f $rootprefix/kernel/crypto/amd64/arcfour2048
	rm -f $rootprefix/platform/sun4u/kernel/crypto/sparcv9/arcfour2048
	rm -f $rootprefix/kernel/crypto/blowfish448
	rm -f $rootprefix/kernel/crypto/sparcv9/blowfish448
	rm -f $rootprefix/kernel/crypto/amd64/blowfish448
	rm -f $rootprefix/usr/sfw/lib/libssl_extra.so.0.9.8
	rm -f $rootprefix/usr/sfw/lib/libcrypto_extra.so.0.9.8

	print "\n"
}

#
# Add metaslot configuration to pkcs11.conf if it doesn't already exist
#
enable_crypto_metaslot()
{
	pkcs11conf=$rootprefix/etc/crypto/pkcs11.conf
	egrep '^metaslot' ${pkcs11conf} > /dev/null 2>& 1
	if [ $? != 0 ] ; then
		print "Adding cryptographic framework's meta slot feature"
		cp $pkcs11conf ${pkcs11conf}.tmp
		export metaslot_config=\
"metaslot:metaslot_status=enabled;metaslot_auto_key_migrate=enabled;"\
"metaslot_token=Sun Software PKCS#11 softtoken;"\
"metaslot_slot=Sun Crypto Softtoken"
		nawk '/^# End SUNWcsr/ \
			{ print ENVIRON["metaslot_config"] } \
			{ print } \
		' ${pkcs11conf}	> ${pkcs11conf}.tmp
		mv -f ${pkcs11conf}.tmp $pkcs11conf
		print "\n"
	fi
}

cleanup_kerberos_mechanisms()
{
#
# This checks to see if the old 'gl' and 'do' directories
# for the Kerberos GSS-API mechanisms can be deleted.
# If the mechanism exists in /usr/lib/gss, then the old
# subdirs may be deleted.
#
	print "Cleaning up old Kerberos GSS-API mechanisms...\c"

	kerneldir=kernel/misc/kgss
	kerneldir_sparc=kernel/misc/kgss/sparcv9

	newmech=no;
	if [ -f $usr/lib/gss/mech_krb5.so.1 ]; then
		#
		# There is a mech  in the "new" location, so
		# the old stuff can be deleted.
		#
		if [ -d $usr/lib/gss/gl ]; then
			rm -rf $usr/lib/gss/gl
		fi
		if [ -d $usr/lib/gss/do ]; then
			rm -rf $usr/lib/gss/do
		fi
		newmech=yes;
	fi
	if [ -f $usr/lib/sparcv9/gss/mech_krb5.so.1 ]; then
		if [ -d $usr/lib/sparcv9/gss/gl ]; then
			rm -rf $usr/lib/sparcv9/gss/gl
		fi
		if [ -d $usr/lib/sparcv9/gss/do ]; then
			rm -rf $usr/lib/sparcv9/gss/do
		fi
	fi
	#
	# Cleanup kernel mechanisms from default location
	#
	if [ -f $rootprefix/$kerneldir/kmech_krb5 ]; then
		if [ -f $rootprefix/$kerneldir/gl_kmech_krb5 ]; then
			rm -f $rootprefix/$kerneldir/gl_kmech_krb5
		fi
		if [ -f $rootprefix/$kerneldir/do_kmech_krb5 ]; then
			rm -f $rootprefix/$kerneldir/do_kmech_krb5
		fi
	fi
	#
	# For SPARC, cleanup from 2 locations.
	#
	# 1.  /kernel/misc/kgss/sparcv9
	#
	if [ -f $rootprefix/$kerneldir_sparc/kmech_krb5 ]; then
		if [ -f $rootprefix/$kerneldir_sparc/gl_kmech_krb5 ]; then
			rm -f $rootprefix/$kerneldir_sparc/gl_kmech_krb5
		fi
		if [ -f $rootprefix/$kerneldir_sparc/do_kmech_krb5 ]; then
			rm -f $rootprefix/$kerneldir_sparc/do_kmech_krb5
		fi
	fi
	#
	# 2.  /platform/sun4u/kernel/misc/kgss/sparcv9
	#
	kerneldir_sparc=platform/$karch/$kerneldir_sparc
	if [ -f $rootprefix/$kerneldir_sparc/kmech_krb5 ]; then
		if [ -f $rootprefix/$kerneldir_sparc/gl_kmech_krb5 ]; then
			rm -f $rootprefix/$kerneldir_sparc/gl_kmech_krb5
		fi
		if [ -f $rootprefix/$kerneldir_sparc/do_kmech_krb5 ]; then
			rm -f $rootprefix/$kerneldir_sparc/do_kmech_krb5
		fi
	fi
	#
	# Make sure the GSS mechanism configuration file is correct
	#
	if [ "$newmech" = "yes" ]; then
		gssmechconf=$rootprefix/etc/gss/mech

		sed -e 's/gl\/mech_krb5\.so/mech_krb5\.so/' \
		-e 's/do\/mech_krb5\.so/mech_krb5\.so/' \
		-e 's/gl_kmech_krb5/kmech_krb5/' \
		-e 's/do_kmech_krb5/kmech_krb5/'\
		$gssmechconf > ${gssmechconf}.tmp

		if [ $? -eq 0 ]; then
			mv -f ${gssmechconf}.tmp $gssmechconf
		else
			echo  "WARNING: update of $gssmechconf failed."
			return 1
		fi
	fi
	print "\n"
}

mpxiodisableno='^[ 	]*mpxio-disable[ 	]*=[ 	]*"no"[ 	]*;'
mpxiodisableyes='^[ 	]*mpxio-disable[ 	]*=[ 	]*"yes"[ 	]*;'

#
# fix up audit permissions
#
fix_up_audit()
{
	chmod 644 $root/etc/security/audit_control
	chmod 644 $root/etc/security/audit_user
}

#
# disable mpxio on fp(7D) ports using fp.conf
#
disable_mpxio_using_fpconf()
{
	conffile=$rootprefix/kernel/drv/fp.conf
	test -f $conffile || return
	egrep -s "$mpxiodisableyes" $conffile && return

	print "To preserve device names, disabled mpxio on fp(7D) ports by"

	if egrep -s "$mpxiodisableno" $conffile; then
		tmpfile=/tmp/fp.conf.$$
		sed "s/$mpxiodisableno/mpxio-disable=\"yes\";/" $conffile \
		    > $tmpfile
		cp $tmpfile $conffile
		rm -f $tmpfile
		print "changing the value of mpxio-disable to \"yes\" in" \
		  "$conffile"
	else
		echo 'mpxio-disable="yes";' >> $conffile
		print "adding mpxio-disable=\"yes\" entry to $conffile"
	fi
}

#
# enable mpxio in scsi_vhci
#
enable_mpxio_using_scsivhciconf()
{
	#
	# depending on whether the bfu restored the child's or parent's version
	# of scsi_vhci.conf file, we may already have the file with the change
	# we need in place. So make the change only if necessary.
	#

	conffile=$rootprefix/kernel/drv/scsi_vhci.conf
	egrep -s "$mpxiodisableno" $conffile && return

	print "To preserve device names, restored your current mpxio" \
	    "configuration by"

	if egrep -s "$mpxiodisableyes" $conffile; then
		tmpfile=/tmp/scsi_vhci.conf.$$
		sed "s/$mpxiodisableyes/mpxio-disable=\"no\";/" $conffile \
		    > $tmpfile
		cp $tmpfile $conffile
		rm -f $tmpfile
		print "changing the value of mpxio-disable to \"no\" in" \
		  "$conffile"
	else
		echo 'mpxio-disable="no";' >> $conffile
		print "adding mpxio-disable=\"no\" entry to $conffile"
	fi
}

#
# restore the pre-bfu MPxIO on/off setting to the post-bfued configuration
#
fixup_mpxio()
{
	conffile=$rootprefix/kernel/drv/scsi_vhci.conf
	parentconffile=$rootprefix/bfu.parent/kernel/drv/scsi_vhci.conf
	childconffile=$rootprefix/bfu.child/kernel/drv/scsi_vhci.conf
	ancestorconffile=$rootprefix/bfu.ancestor/kernel/drv/scsi_vhci.conf

	# if scsi_vhci.conf doesn't exist return
	test -f $conffile || return

	#
	# Determine the mpxio setting in the child. If the system was bfued
	# before and running with mpxio on by deafult bits, can't rely on the
	# mpxio-disable entry in the child's scsi_vhci.conf file as it may
	# contain stale left over entries.
	#
	mpxio_child=1
	if [ -f $ancestorconffile ]; then
		if egrep -s "$mpxiodisableyes" $ancestorconffile; then
			#
			# prior to the bfu the system was running with
			# mpxio off by default bits.
			#
			mpxio_child=0
			egrep -s "$mpxiodisableno" $childconffile && \
			    mpxio_child=1
		fi
	else
		egrep -s "$mpxiodisableyes" $childconffile && mpxio_child=0
	fi

	if egrep -s "$mpxiodisableyes" $parentconffile; then
		# these bits require explicit enabling of mpxio at in scsi_vhci
		if [ $mpxio_child -eq 1 ]; then
			egrep -s "$mpxiodisableyes" \
			    $rootprefix/kernel/drv/fp.conf || \
			    enable_mpxio_using_scsivhciconf
		fi
	else
		#
		# these bits have mpxio enabled by default in scsi_vhci.
		# if mpxio is disabled in the child, disable mpxio on all
		# fp(7D) ports using fp.conf.
		#
		[ $mpxio_child -eq 0 ] && disable_mpxio_using_fpconf
	fi
}

# Migrate hostid from /kernel/misc/sysinit binary to new format
# stored in /etc/hostid.  The ON-private 'extract_hostid' binary
# (built as part of the ON tools) must be in bfu's path - usually
# copied from $GATE/public/$isa/bin/.
#
migrate_hostid()
{
#
# Currently, we only support a single hostid per machine, which
# is set in the global zone.  Don't do anything to non-global zone
# roots.  Still have to allow for alternate roots that aren't in
# a non-global zone, though.
#
numzones=`zoneadm list -pi|wc -l`
if [ $numzones -ne 1 ]; then
    for zmpt in \
	`zoneadm list -pi|nawk -F: '$2 != "global" {print $4} 2>/dev/null'`
    do
	if [ "$zmpt" = "$root" ]; then
	    set -
	    return 0
	fi
    done
fi
#
# if /etc/hostid exists - already migrated - do nothing
#
if [ -f ${rootprefix}/etc/hostid ]; then
    print "New hostid mechanism already in use..."
    return 0
fi
#
# try to get hostid from /kernel/misc/sysinit 
#
if [ -f ${rootprefix}/kernel/misc/sysinit ]; then
    hostid=`extract_hostid ${rootprefix}/kernel/misc/sysinit 2>/dev/null`
	if [ $? -eq 0 ]; then
	    echo "# DO NOT EDIT" > ${rootprefix}/etc/hostid
	    r=`echo "0x${hostid}" | perl -e \
		'while(<STDIN>){chop;tr/!-~/P-~!-O/;print $_,"\n";}exit 0;'`
	    printf "\"%s\"\n"  $r >> ${rootprefix}/etc/hostid
	    print "Moving hostid from /kernel/misc/sysinit to /etc/hostid ... done"
	elif [ "$force_override" = "no" ]; then
	    print "\n\nERROR: Unable to extract current hostid from sysinit file, " \
		"and /etc/hostid does not exist.  Machine will be initialized " \
		"with a new hostid at first reboot after bfu.  If this is OK, you " \
		"must run bfu with the -f flag."
	    exit
	fi
	return 0
fi

return 0
}

#
# Check to see if root in $1 has a mounted boot, and that
# it's mounted at the right place for bfu to handle it.
#
# Returns 0 (true) if bfu can handle the upgrade; fails if not
#

boot_is_upgradeable()
{
	ROOT=$1
	if [ "$ROOT" = "/" ] ; then ROOT=""; fi

        BOOTPARTDEV="$(grep -s -v '^#' ${ROOT}/etc/vfstab | \
	    grep "[ 	]/boot[ 	]*pcfs[ 	]" | \
	    awk '{print $1}')"

	# find out if, and where, boot is mounted

	if [ -n "$BOOTPARTDEV" ] ; then 
		if [ -n "$ROOT" ] ; then
		
			BOOTMNT=$(mount | grep "$BOOTPARTDEV" | \
			    awk '{print $1}')
		else
			BOOTMNT="/boot"
		fi
		if [ "$BOOTMNT" != ${ROOT}/boot ] ; then
			cat << BOOTMOUNTERR

${ROOT} refers to an x86 boot partition, but it's not mounted 
at ${ROOT}/boot.

BOOTMOUNTERR
			fail "Mount ${ROOT}s bootpart at ${ROOT}/boot.\n\n"
		fi
	fi

	return 0
}

# update the realmode boot programs at $1 (root) 
# from classic boot psm/stand/bootblks/ufs/i386/installboot.sh

install_boot_i386()
{
	PBOOT=$1
	BOOTBLK=$2
	DEVICE=$3
	if [ ! -f $PBOOT ]; then
		echo "$PBOOT: File not found"
		return 1
	fi
	if [ ! -f $BOOTBLK ]; then
		echo "$BOOTBLK: File not found"
		return 1
	fi
	if [ ! -c $DEVICE ]; then
		echo "$DEVICE: Not a character device"
		return 1
	fi
	if [ ! -w $DEVICE ]; then
		echo "$DEVICE: Not writeable"
		return 1
	fi

	# pboot at block 0, label at blocks 1 and 2, bootblk from block 3 on
	dd if=$PBOOT of=$DEVICE bs=1b count=1 conv=sync >/dev/null 2>&1

	dd if=$BOOTBLK of=$DEVICE bs=1b oseek=3 conv=sync >/dev/null 2>&1

	return 0
}

update_realmode_booters()
{
	ROOT=$1
	
	TMPDIR=/tmp/rmupdate.$$
	trap "rm -rf $TMPDIR" EXIT

	# go get new versions of boot files into TMPDIR

	OLD_PWD=$(pwd)
	mkdir $TMPDIR
	cd $TMPDIR

	# i86pc.boot archive
	REQFILES="boot/mdboot boot/strap.com"
	$ZCAT $cpiodir/i86pc.boot$ZFIX |  cpio -id $REQFILES 2>/dev/null 
	mv $REQFILES $TMPDIR

	# i86pc.usr archive
	REQFILES="usr/platform/i86pc/lib/fs/ufs/pboot"
	REQFILES="$REQFILES usr/platform/i86pc/lib/fs/ufs/bootblk"
	$ZCAT $cpiodir/i86pc.usr$ZFIX | cpio -id $REQFILES 2>/dev/null
	mv $REQFILES $TMPDIR

	cd $OLD_PWD

	grep -s -v '^#' ${ROOT}/etc/vfstab | \
	    grep "[ 	]/boot[ 	]*pcfs[ 	]" >/dev/null

	if [ $? -eq 0 ] ; then
		echo 'Updating /boot on x86 boot partition.'

		REQFILES="mdboot strap.com"
		for f in ${REQFILES}; do
			if [ ! -f ${TMPDIR}/$f ]; then
				fail "Missing $f, aborting."
			fi
		done

		MDBOOT=${TMPDIR}/mdboot
		STRAP=${TMPDIR}/strap.com

		LUBIN=/usr/lib/lu
		TMP_FDFILE1=${TMPDIR}/fdfile1.$$
		LOGFILE=${TMPDIR}/mkfs.log.$$
		DDCOPY=${TMPDIR}/.dd_x86_boot_copy

		DISKID="$(grep -s -v '^#' ${ROOT}/etc/vfstab | \
		    grep "[ 	]/boot[ 	]*pcfs[ 	]" |\
		    awk '{print $1}' | sed -e 's:p0\:boot::g')"

		DISKID="$(basename ${DISKID})"

		# Obtain the disk table; it will look something like the following:
		#
# * Id    Act  Bhead  Bsect  Bcyl    Ehead  Esect  Ecyl    Rsect    Numsect
#   130   128  27     28     0       242    9      553     1728     8897472
		# 
		# Delete all blank lines, and all lines that begin with *,
		# leaving only actual fdisk entries that we can scan
		# looking for the X86BOOT partition

		fdisk -W - /dev/rdsk/${DISKID}p0 | \
		    grep -v '^*' | grep -v '^$' > ${TMP_FDFILE1}

		num=1

		while read id act bhead bcyl ehead ecyl rsect numsect
		do
			# Ignore entry if not X86 /boot partition
			# ID '190' is the X86BOOT partition (see man fdisk(1M))

			if [ $id -ne "190" ] ; then
				num=$(expr $num + 1)
				continue
			fi

			# Found X86 boot partition - save contents to $DDCOPY
			BOOTPART=/dev/rdsk/${DISKID}p${num}
			echo "Boot device is <${BOOTPART}>"

			ERRMSG="$(dd if=${BOOTPART} of=${DDCOPY} 2>&1)"
			if [ $? -ne 0 ] ; then
				[ -n "${ERRMSG}" ] && echo "${ERRMSG}"
				fail "Unable to save copy of <${BOOTPART}>."
			fi

			# mount copy of old /boot partition 
			LOBOOTDEV=$(lofiadm -a ${DDCOPY} 2>&1)
			if [ $? -ne 0 ] ; then
				[ -n "${LOBOOTDEV}" ] && echo "${LOBOOTDEV}"
				fail "Unable to make lo-device <${DDCOPY}>"
			fi
			SOURCE_BOOT_DEV="${TMPDIR}/tmpbootdev.$$"
			mkdir ${SOURCE_BOOT_DEV}
			ERRMSG=$(mount -F pcfs ${LOBOOTDEV} \
			    ${SOURCE_BOOT_DEV})
			if [ $? -ne 0 ] ; then
				[ -n "${ERRMSG}" ] && echo "${ERRMSG}"
				fail "Unable to mount lo-device <${LOBOOTDEV}>."
			fi

			# recreate existing boot partition with updated 
			# boot files

			# umount ${ROOT}'s /boot if mounted

			BOOTMOUNTPT=$(mount | grep ${DISKID}p0:boot 2>&1 | \
			    awk '{print $1;}')

			if [ -n "${BOOTMOUNTPT}" ] ; then
				echo "unmounting /dev/dsk/${DISKID}p0:boot"
				ERRMSG=$(umount \
				    /dev/dsk/${DISKID}p0:boot 2>&1)
				if [ $? -ne 0 ] ; then
					[ -n "${ERRMSG}" ] && echo "${ERRMSG}"
					fail "Unable to umount X86 boot device."
				fi
			fi

			echo "Making new pcfs file system on ${DISKID}"

			echo y | /usr/lib/fs/pcfs/mkfs -F pcfs \
			    -o S,s,B=$MDBOOT,b=BOOT,i=$STRAP \
			    /dev/rdsk/${DISKID}p0:boot >> ${LOGFILE} 2>&1
			if [ $? -ne 0 ] ; then
				echo "Unable to make pcfs:"
				cat ${LOGFILE}
				fail ""
			fi

			echo "Copying x86 boot partition contents back\c"
			echo " to new /boot fs."

			OLD_PWD=$(pwd)

			echo "Remounting freshened /boot partition"

			if [ -z "${BOOTMOUNTPT}" ] ; then 
				# boot ptn wasn't mounted
				BOOTMOUNT="/tmp/bootpart"
				mkdir ${BOOTMOUNT}
			else
				BOOTMOUNT=${BOOTMOUNTPT}
			fi

			ERRMSG=$(mount -F pcfs \
			    /dev/dsk/${DISKID}p0:boot ${BOOTMOUNT} 2>&1)

			if [ $? -ne 0 ] ; then
				[ -n "${ERRMSG}" ] && echo "${ERRMSG}"
				fail "Unable to mount X86 boot device."
			fi

			# copy old /boot contents
			cd ${SOURCE_BOOT_DEV}
			find . -mount \! -type s -print | \
			    cpio -pcdum ${BOOTMOUNT} 2>&1 | \
			    ${LUBIN}/lustripcpioerr

			if [ $? -ne 0 ] ; then
				fail "Unable to copy boot partition contents."
			fi

			cd ${OLD_PWD}

			# unmount and rm our boot mount, if we created it
			if [ -z "${BOOTMOUNTPT}" ] ; then
				ERRMSG=$(umount ${BOOTMOUNT} 2>&1)
				if [ $? -ne 0 ] ; then
					[ -n "${ERRMSG}" ] && echo "${ERRMSG}"
					fail "Unable to umount <$BOOTMOUNT>." 
				fi
				rm -rf ${BOOTMOUNT}
			fi

			# unmount, un-lofi, and rm SOURCE_BOOT_DEV

			ERRMSG=$(umount ${SOURCE_BOOT_DEV} 2>&1)
			if [ $? -ne 0 ] ; then
				[ -n "${ERRMSG}" ] && echo "${ERRMSG}"
				fail "Cannot umount lo-device <${LOBOOTDEV}>." 
			fi

			ERRMSG=$(lofiadm -d ${DDCOPY} 2>&1)
			if [ $? -ne 0 ] ; then
				[ -n "${ERRMSG}" ] && echo "${ERRMSG}"
				fail "Cannot remove lo-device <${LOBOOTDEV}>." 
			fi
		
			rm -rf ${SOURCE_BOOT_DEV}

		done < ${TMP_FDFILE1}
		rm ${TMP_FDFILE1} ${LOGFILE} ${DDCOPY}

	else

		# non boot-partition: use installboot to get pboot and bootblk
		echo "Updating /boot on Solaris partition."

		if [ -z "${ROOT}" ] ; then SEARCH="/"; else SEARCH="${ROOT}"; fi

		ROOTRAWDEV=$(mount | grep "^${SEARCH} on " | \
		    awk '{print $3}' | sed 's;/dsk;/rdsk;')

		if [ -z "${ROOTRAWDEV}" ] ; then
			[ -n "${ROOTRAWDEV}" && echo "${ROOTRAWDEV}" ] 
			fail "${SEARCH} must be a mounted filesystem"
		fi

		echo "Updating Solaris partition ${ROOTRAWDEV} with installboot"
		REQFILES="pboot bootblk"
		for f in ${REQFILES}; do
			if [ ! -f ${TMPDIR}/$f ]; then
				fail "Missing $f, aborting."
			fi
		done
		PBOOT=${TMPDIR}/pboot
		BOOTBLK=${TMPDIR}/bootblk
		install_boot_i386 $PBOOT $BOOTBLK ${ROOTRAWDEV}
		if [ $? -ne 0 ] ; then
			fail "Unable to installboot to <${ROOTRAWDEV}>." 
		fi
	fi
}

#
print "Verifying archives ..."

for a in generic $allarchs $rootarchs
do
	test -r $cpiodir/$a.root$ZFIX ||
		fail "bfu archive $cpiodir/$a.root$ZFIX missing"
done

if [ ! -r $cpiodir/generic.lib$ZFIX -o ! -r $cpiodir/generic.kernel$ZFIX -o \
    ! -r $cpiodir/generic.sbin$ZFIX ]; then
	old_style_archives="true"
	$ZCAT $cpiodir/generic.root$ZFIX | cpio -it 2>/dev/null | \
	    egrep -s '^etc/zones' && \
		fail "bfu archive $cpiodir/generic.{kernel,lib,sbin}$ZFIX" \
		     "missing;\npossible mkbfu version mismatch: pre-zones" \
		     "style archives with zones files."
fi

for a in generic $allarchs $usrarchs
do
	test -r $cpiodir/$a.usr$ZFIX ||
		fail "bfu archive $cpiodir/$a.usr$ZFIX missing"
done

for root in $rootlist
do
	cd $root || fail "Cannot cd $root"
	prologue=${root%/}/bfu.prologue
	if [ -f $prologue ]; then
		print "Executing $prologue"
		$prologue || fail "$prologue failed with code $?"
	fi
done

print "Performing basic sanity checks ..."

for dir in $usr $rootlist
do
	test -d $dir || fail "$dir does not exist"
	test -w $dir || fail "$dir is not writable"
	cd $dir || fail "Cannot cd $dir"
done

RM_32BIT_KERNEL=0;
if [ "$karch" = "sun4u" ] &&
   ($ZCAT $cpiodir/sun4u.root$ZFIX | cpio -itv 2>&1 |
    grep "^l.*platform/sun4u/kernel/unix -> sparcv9/unix$" > /dev/null);
    then
	RM_32BIT_KERNEL=1;
	if [ "$force_override" = "no" ] && 
	   (prtconf -F 2>&1 | egrep '(cgthree|bwtwo)' > /dev/null);
	    then
		print "\n\nERROR: You are upgrading to a 64-bit-only OS. " \
		      "Your frame buffer does not have a 64-bit driver and " \
		      "will not work after reboot.  To proceed you must run " \
		      "bfu with the -f flag.";
		exit;
	fi;
fi;

if [ $plat = "SUNW,Ultra-1" ] && [ ! -f $cpiodir/SUNW,Ultra-1.root$ZFIX ] &&
   [ "$force_override" = "no" ];
   then
	print "\nERROR: These archives do not have Ultra-1 platform support." \
	      "\nProceeding with this BFU may render this machine unbootable." \
	      "\nTo proceed anyway, you must run bfu with the -f flag.\n";
	exit;
fi;

for root in $rootlist
do
	rootprefix=${root%/}
	smf_check_repository
done

MINIMUM_OS_REV=10

#
# Perform additional sanity checks if we are upgrading the live system.
#
if [ "$rootlist" = "/" ]
then
	#
	# Disallow from older releases
	#
	os_rev=`uname -r | sed -e s/5.//`
	if [ $os_rev -lt $MINIMUM_OS_REV -a "$force_override" = "no" ]; then
		fail "Cannot bfu from pre-Solaris $MINIMUM_OS_REV"
	fi
	if [ ! -x /usr/sbin/svcadm ]; then
		fail "This version of bfu cannot run on pre-Greenline " \
		    "(s10_64) systems"
	fi

	#
	# Filesystem space checks
	#
	set $root 4 $usr 6
	while [ $# -gt 0 ]
	do
		test "`df -b $1 | tail -1 | nawk '{ print $2 }'`" -ge ${2}000 ||
			fail "Less than $2 MB free on $1 -- bfu not safe."
		shift 2
	done
	#
	# Disable kernel module unloading
	#
	print "Disabling kernel module unloading ... \c"
	test -x /usr/bin/adb || fail "/usr/bin/adb not found: bfu not safe."
	echo "moddebug/W20000" | adb -kw /dev/ksyms /dev/mem | grep moddebug
	#
	# Load modules and drivers here not to reload them when you access
	# /devices or its subdirectories later.
	#
	nawk '$1 !~ /^#|^$/ {print $1}' /etc/name_to_major | \
	sed -e 's/#.*$//' | while read driver
	do
		modload -p drv/${driver} >/dev/null 2>&1
	done
	ls $cpiodir >>/dev/null		# loads elfexec and networking

	# exec/intpexec and sys/kaio are needed by lofi
	modload -p exec/intpexec >/dev/null 2>&1
	modload -p sys/kaio >/dev/null 2>&1

	# umount /lib/libc.so.1 if necessary
	if [ -n "`mount | grep '^/lib/libc.so.1'`" ]
	then
		print "Unmounting /lib/libc.so.1 ..."
		umount /lib/libc.so.1
	fi

	PLAT=`/usr/bin/uname -i`
	ARCH=`/usr/bin/uname -m`
	# umount /platform/$PLAT/lib/libc_psr.so.1 if necessary
	if [ -n "`mount | grep "^/platform/$PLAT/lib/libc_psr.so.1"`" ]
	then
		print "Unmounting /platform/$PLAT/lib/libc_psr.so.1 ..."
		umount /platform/$PLAT/lib/libc_psr.so.1
	else
		# umount /platform/$ARCH/lib/libc_psr.so.1 if necessary
		if [ -n "`mount | grep "^/platform/$ARCH/lib/libc_psr.so.1"`" ]
		then
			print "Unmounting /platform/$ARCH/lib/libc_psr.so.1 ..."
			umount /platform/$ARCH/lib/libc_psr.so.1
		fi
	fi

	# umount /platform/$PLAT/lib/sparcv9/libc_psr.so.1 if necessary
	if [ -n "`mount | grep "^/platform/$PLAT/lib/sparcv9/libc_psr.so.1"`" ]
	then
		print "Unmounting /platform/$PLAT/lib/sparcv9/libc_psr.so.1 ..."
		umount /platform/$PLAT/lib/sparcv9/libc_psr.so.1
	else
		# umount /platform/$ARCH/lib/sparcv9/libc_psr.so.1 if necessary
		if [ -n "`mount | grep \
		    "^/platform/$ARCH/lib/sparcv9/libc_psr.so.1"`" ]
		then
			print "Unmounting \c"
			print "/platform/$ARCH/lib/sparcv9/libc_psr.so.1 ..."
			umount /platform/$ARCH/lib/sparcv9/libc_psr.so.1
		fi
	fi

	# umount /platform/sun4u-us3/lib/libc_psr.so.1 if necessary
	if [ -n "`mount | grep '^/platform/sun4u-us3/lib/libc_psr.so.1'`" ]
	then
		print "Unmounting /platform/sun4u-us3/lib/libc_psr.so.1 ..."
		umount /platform/sun4u-us3/lib/libc_psr.so.1
	fi

	# umount /platform/sun4u-us3/lib/sparcv9/libc_psr.so.1 if necessary
	if [ -n "`mount | grep '^/platform/sun4u-us3/lib/sparcv9/libc_psr.so.1'`" ]
	then
		print "Unmounting /platform/sun4u-us3/lib/sparcv9/libc_psr.so.1 ..."
		umount /platform/sun4u-us3/lib/sparcv9/libc_psr.so.1
	fi

	# 
	# The libpiclsbl.so.1 library has been moved from
	# /usr/platform/SUNW,Sun-Fire-T200/lib/... to
	# /usr/platform/sun4v/lib/... .  Other sun4v platforms create
	# symbolic link to T200's libpiclsbl.so.1. Therefore check
	# if library is present in T200's directory and then remove
	# it and the symbolic links.
	if [ -a \
	    $usr/platform/SUNW,Sun-Fire-T200/lib/picl/plugins/libpiclsbl.so.1 ]
	then
		print "Removing libpiclsbl.so library ..."
		find $usr/platform -name libpiclsbl\* -exec rm {} \;
	fi

	if [ -x /usr/sbin/zoneadm ]; then
		#
		# Stop any running zones: the init script will print a
		# message if needed.
		#
		if [ -x /etc/init.d/zones ]; then
			/etc/init.d/zones stop
		elif [ -x /lib/svc/method/svc-zones ]; then
			#
			# We need all zones to be down before proceeding.
			# We can't accomplish this by just disabling the
			# zones service, since it might already be disabled.
			# So we pretend to be SMF, and invoke the stop method.
			#
			# When zones are someday independently managed as
			# service instances, this will need to be revised.
			#
			export SMF_FMRI="svc:/system/zones:default"
			/lib/svc/method/svc-zones stop
			unset SMF_FMRI
		fi

		[ -z `zoneadm list | grep -v global` ] || \
		    fail "zone(s) failed to halt"
		#
		# Determine the installed zones, which we will want to do
		# after we're done with the global zone.  This is done now
		# rather than later in case bfu'ing the global zone causes
		# the zone configuration to become unreadable (e.g., via a
		# DTD flag day).
		#
		bfu_zone_list=$root/.bfu_zone_list
		rm -f $bfu_zone_list

		zoneadm list -pi | nawk -F: '{
			if ($3 == "installed" &&
			    ($6 == "native" || $6 == "" || $6 == "sn1")) {
				printf "%s %s\n", $2, $4
			}
		}' > $bfu_zone_list
	fi

	#
	# Stop sendmail so that mail doesn't bounce during the interval
	# where /etc/mail/aliases is (effectively) empty.
	#
	# (note that unlike other services here, /etc/init.d/sendmail
	# remains post-smf(5) because it is a public interface.)
	#
	if [ -r /etc/svc/volatile/repository_door ]; then
		print "Disabling sendmail temporarily ..."
		svcadm disable -t network/smtp
	else
		print "Killing sendmail ..."
		/etc/init.d/sendmail stop
	fi

	print "Disabling remote logins ..."
	echo "bfu in progress -- remote logins disabled" >/etc/nologin

	#
	# Stop syslogd so it doesn't interfere with saving preserved files.
	#
	if [ -f /etc/init.d/syslog ]; then
		print "Killing syslogd ..."
		/etc/init.d/syslog stop
	elif [ -r /etc/svc/volatile/repository_door ]; then
		print "Disabling syslog temporarily ..."
		svcadm disable -t system/system-log
	fi

	#
	# Stop apache so it doesn't get upset when the entire world changes
	# out from underneath it.
	#
	if [ -f /etc/init.d/apache ]; then
		print "Killing httpd ..."
		/etc/init.d/apache stop
	elif [ -r /etc/svc/volatile/repository_door ]; then
		print "Disabling httpd temporarily ..."
		svcadm disable -t network/http
	fi

	#
	# Kill off fmd so it doesn't get upset when the entire world changes
	# out from underneath it.
	#
	if [ -f /etc/init.d/savecore ]; then
		print "Killing fmd ..."
		pkill -x fmd
	elif [ -r /etc/svc/volatile/repository_door ]; then
		print "Disabling fmd temporarily ..."
		svcadm disable -t system/fmd
	fi

	#
	# Stop nscd so it doesn't interfere with stuff.
	#
	if [ -x /etc/init.d/nscd ]; then
		print "Killing nscd ..."
		/etc/init.d/nscd stop
	elif [ -r /etc/svc/volatile/repository_door ]; then
		print "Disabling nscd temporarily ..."
		svcadm disable -t system/name-service-cache:default
	fi

	if grep -v "^#" $rootprefix/etc/vfstab | grep boot | \
		grep "[ 	]pcfs[ 	]" >/dev/null 2>&1
	then
		boot_is_pcfs=yes
	fi

	smf_new_profiles

else
	#
	# Check ${root}/etc/motd for SunOS value to get `uname -r`
	#
	os_rev=`head -1 ${root}/etc/motd | sed -e 's/^.*SunOS //' | \
		awk '{print $1}' | sed -e s/5.//`
	if [ $os_rev -lt $MINIMUM_OS_REV -a "$force_override" = "no" ]; then
		fail "Cannot bfu from pre-Solaris $MINIMUM_OS_REV"
	fi
	if [ ! -x /usr/sbin/svcadm ]; then
		fail "This version of bfu cannot run on pre-Greenline " \
		    "(s10_64) systems"
	fi
fi

export PATH=/tmp/bfubin:$PATH
export LD_LIBRARY_PATH=/tmp/bfulib

if [ -h /tmp/bfulib/64 ]
then
	ldlib64="LD_LIBRARY_PATH_64=/tmp/bfulib/64"
	export LD_LIBRARY_PATH_64=/tmp/bfulib/64
fi

# turn off auxiliary filters, since they can cause objects to be loaded
# from outside of the protected environment.
export LD_NOAUXFLTR=1

#
# Since we've turned off auxiliary filters, libc_psr will normally not
# be loaded at all.  But libc_psr was overriding broken code in libc
# for over a week before the fix for 6324631, so we need to explicitly
# LD_PRELOAD it to allow users to bfu from the broken libc.  This can be
# removed once there are no sun4u machines bfued to Nevada bits between
# 9/7/2005 and 9/15/2005.
#
if [ -f /tmp/bfulib/libc_psr.so.1 ]; then
	export LD_PRELOAD_32=/tmp/bfulib/libc_psr.so.1
fi

print "Turning on delayed i/o ..."
fastfs -f $rootlist $usr
fastfs $rootlist $usr

#
# The "| tee -a $EXTRACT_LOG" following do_extraction() is not pulled into the
# function itself because it interferes with the cpio exit status detection.
# pcfs boot is an exception, since its cpio exit status is expected to be bad,
# so a heuristic must be employed to infer whether or not any errors occurred.
#
do_extraction() {
	compressed_archive=$1
	shift
	$ZCAT $compressed_archive | cpio -idmucB $* 2>&1 \
		|| extraction_error "extracting archive $1"
}

do_pcfs_boot_extraction() {
	PCFS_BOOT_LOG=/tmp/bfu-pcfs-boot-log.$$
	$ZCAT $1 | cpio -idmucB 2>&1 | grep -v "error.s" | \
		grep -v "cpio: Cannot chown()" | \
		grep -v "cpio: Error during chown()" | tee $PCFS_BOOT_LOG
	cat $PCFS_BOOT_LOG >> $EXTRACT_LOG
	egrep -s -v blocks $PCFS_BOOT_LOG
	if [ $? -eq 0 ]; then
		extraction_error "extracting archive $1 ... see $PCFS_BOOT_LOG"
	else
		rm -f $PCFS_BOOT_LOG
	fi
}

#
# Usage: extract_archives (root|usr|lib|sbin|kernel) arch-list
#
extract_archives() {
	base=$1
	shift
	test $base = usr && cd $usrroot || cd $root
	for archive in $*
	do
		print "Extracting $archive.$base$ZFIX ... \c" \
			| tee -a $EXTRACT_LOG
		test -h platform/$archive && rm platform/$archive
		if [ $base = root ]; then
			exclude="-f dev/fd home proc etc/mnttab"

			#
			# We don't want to overwrite the sharetab if
			# it is a mount-point. We assume it is a
			# mount-point if it is not writable.
			#
			if [ -f etc/dfs/sharetab ]; then
				if [ ! -w etc/dfs/sharetab ]; then
					exclude="$exclude etc/dfs/sharetab"
				fi
			fi

			[ -d system/contract ] &&
				exclude="$exclude system/contract"
			[ -d system/object ] &&
				exclude="$exclude system/object"
			[ -f etc/svc/repository.db ] &&
				exclude="$exclude etc/svc/repository.db"
			[ -e etc/repository_door ] &&
				exclude="$exclude etc/repository_door"
			[ -f etc/svc/volatile ] &&
				exclude="$exclude etc/svc/volatile"
			do_extraction $cpiodir/$archive.$base$ZFIX $exclude |
				tee -a $EXTRACT_LOG
		elif [ $base = usr ]; then
			do_extraction $cpiodir/$archive.$base$ZFIX \
				-f "usr/openwin" | tee -a $EXTRACT_LOG
		else
			do_extraction $cpiodir/$archive.$base$ZFIX \
				| tee -a $EXTRACT_LOG
		fi
	done
	cd $root
}

extract_boot_archives() {
	base=$1
	shift
	cd $root
	for archive in $*
	do
		if [ ! -f $cpiodir/$archive.$base$ZFIX ]; then
			continue
		fi
		print "Extracting $archive.$base$ZFIX ... \c" \
			| tee -a $EXTRACT_LOG
		if [ $boot_is_pcfs = yes ]; then
			do_pcfs_boot_extraction $cpiodir/$archive.$base$ZFIX
		else
			do_extraction $cpiodir/$archive.$base$ZFIX | \
				tee -a $EXTRACT_LOG
		fi
		$ZCAT $cpiodir/$archive.$base$ZFIX | cpio -it 2>&1 | \
		    grep  "boot/solaris/devicedb/master" >/dev/null 2>&1
		if [ "$?" = "0" ]; then
			have_realmode=yes
		fi
	done
	cd $root
}

#
# Classic boot pboot and bootblk compatibility with old archives
#
setup_pboot()
{
	NEWPBOOTDIR=$GATE/public/pboot
	NEWPBOOT=${NEWPBOOTDIR}/pboot
	NEWBOOTBLK=${NEWPBOOTDIR}/bootblk
	PBOOTDIR=$usr/platform/$karch/lib/fs/ufs
	PBOOT=${PBOOTDIR}/pboot
	BOOTBLK=${PBOOTDIR}/bootblk

	# they should already be there, but...
	if [ -f $NEWPBOOT -a ! -f $PBOOT ]; then
		print "Installing pboot from $NEWPBOOTDIR"
		cp $NEWPBOOT $PBOOT
	fi
	if [ -f $NEWBOOTBLK -a ! -f $BOOTBLK ]; then
		print "Installing bootblk from $NEWPBOOTDIR"
		cp $NEWBOOTBLK $BOOTBLK
	fi

	if [ -f $NEWPBOOT -a -f $PBOOT ]; then
		LATEST=`ls -Lt $PBOOT $NEWPBOOT | head -1`
		if [ "$LATEST" = "$NEWPBOOT" ]; then
			print "Updating pboot from $NEWPBOOT"
			cp $NEWPBOOT $PBOOT
		fi
	fi
	if [ -f $NEWBOOTBLK -a -f $BOOTBLK ]; then
		LATEST=`ls -Lt $BOOTBLK $NEWBOOTBLK | head -1`
		if [ "$LATEST" = "$NEWBOOTBLK" ]; then
			print "Updating bootblk from $NEWBOOTBLK"
			cp $NEWBOOTBLK $BOOTBLK
		fi
	fi
	#
	# This function will never be called when upgrading a zfs root,
	# so it's safe to assume a value for rootslice here.
	#
	if [[ "$rootslice" = /dev/rdsk/* ]]; then
		print "Installing boot block."
		( cd $PBOOTDIR ;
		    install_boot_i386 ./pboot ./bootblk ${rootslice%??}s2 )
	fi
	#
	# Since /platform/i86pc/boot/solaris/boot.bin is moved
	# to /boot/solaris, remove the old one if it really
	# exists.
	#
	OLDBOOTDIR=${root}/platform/i86pc/boot/solaris
	OLDBOOTBIN=${OLDBOOTDIR}/boot.bin
	if [ ! -h ${OLDBOOTDIR} -a -f ${OLDBOOTBIN} ] ;
	then
		print "Removing old boot.bin."
		rm -rf ${OLDBOOTBIN}
	fi
}

#
# Multiboot support
#

saved_boot_files="
	solaris/bootenv.rc
	solaris/devicedb/master
"

#
# transition from multiboot to dca
#
check_multi_to_dca_boot()
{
	bootdev=`grep p0:boot $rootprefix/etc/vfstab | \
		grep pcfs | nawk '{print $1}'`
	if [ "$bootdev" != "" ]; then
		is_pcfs_boot=yes
	fi

	if [ $is_pcfs_boot = yes ]; then
		df -h | grep stubboot >/dev/null 2>&1
		if [ $? -eq 0 ]; then

			# save configurable files from /boot
			# before remounting /stubboot.
			# files are relative to /boot.
			for file in $saved_boot_files
			do
				dir="`dirname $rootprefix/stubboot/$file`"
				mkdir -p $dir
				cp $rootprefix/boot/$file $dir
			done

			echo "unmount $bootdev at $rootprefix/stubboot"
			ERRMSG=$(umount $bootdev 2>&1)
			if [ $? -ne 0 ] ; then
				[ -n "${ERRMSG}" ] && echo "${ERRMSG}"
				fail "Unable to umount $bootdev on $rootprefix/stubboot."
			fi

			# adjust vfstab
			sed -e "s/[ 	]\/stubboot[ 	]/	\/boot	/" \
			    <$rootprefix/etc/vfstab >$rootprefix/etc/vfstab+
			mv $rootprefix/etc/vfstab $rootprefix/etc/vfstab-
			mv $rootprefix/etc/vfstab+ $rootprefix/etc/vfstab

			ERRMSG=$(mount -F pcfs $bootdev $rootprefix/boot 2>&1)
			if [ $? -ne 0 ] ; then
				[ -n "${ERRMSG}" ] && echo "${ERRMSG}"
				fail "Unable to mount $bootdev on $rootprefix/boot."
			fi
		fi
	fi
}

check_dca_to_multiboot()
{
	bootdev=`grep p0:boot $rootprefix/etc/vfstab | \
	    grep pcfs | nawk '{print $1}'`
	if [ "$bootdev" != "" ]; then
		is_pcfs_boot=yes
	fi
	if [ $system_type != dca ]; then
		return
	fi

	# ensure bootpath is in $rootprefix/boot/solaris/bootenv.rc
	# It's ok to put a meta device path in there
	bootenvrc=$rootprefix/boot/solaris/bootenv.rc
	grep "^setprop[	 ]*bootpath[	 ]" $bootenvrc > /dev/null
	if [ $? != 0 ]; then
		rootdev=`grep -v "^#" $rootprefix/etc/vfstab | \
		    grep "[	 ]/[	 ]" | nawk '{print $1}'`
		bootpath=`ls -l $rootdev | nawk '{ print $NF }' |\
		    sed "s#../../devices##"`
		echo "setprop bootpath '$bootpath'" >> $bootenvrc
	fi

	rm -f $rootprefix/boot/mdboot
}

#
# Figure out the boot architecture of the current system:
# 1. If an i86xpv kernel exists, it's a xpv system
# 2. If dboot_image is in unix, it's a dboot system
# 3. Otherwise, if multiboot is present, it's a multiboot system
# 4. Otherwise, it's a pre-multiboot system
#
# This is called before we lay down the new archives.
#
check_system_type()
{
	if [ -f $root/platform/i86xpv/kernel/unix ]; then
		system_type=xpv
	elif [ -x $root/boot/solaris/bin/symdef ] && \
	    $root/boot/solaris/bin/symdef $root/platform/i86pc/kernel/unix \
	    dboot_image; then
		system_type=directboot
	elif [ -x $root/platform/i86pc/multiboot ]; then
		system_type=multiboot
	else
		system_type=dca
	fi
}

#
# Detect SVM root and return the list of raw devices under the mirror
#
get_rootdev_list()
{
	if [ -f $rootprefix/etc/lu/GRUB_slice ]; then
		dev=`grep '^PHYS_SLICE' $rootprefix/etc/lu/GRUB_slice |
		    cut -d= -f2`
		if [ "$rootfstype" = "zfs" ]; then
			fstyp -a "$dev" | grep 'path: ' | grep -v phys_path: | 
			    cut -d"'" -f2 | sed 's+/dsk/+/rdsk/+'
		else
			echo "$dev"
		fi
		return
	elif [ "$rootfstype" = "zfs" ]; then
		rootpool=`df -k ${rootprefix:-/} | tail +2 | cut -d/ -f1`
		rootdevlist=`zpool iostat -v "$rootpool" | tail +5 |
		    grep -v mirror | sed -n -e '/--/q' -e p | awk '{print $1}'`
	else
		metadev=`grep -v "^#" $rootprefix/etc/vfstab | \
			grep "[	 ]/[ 	]" | nawk '{print $2}'`
		if [[ $metadev = /dev/rdsk/* ]]; then
       		 	rootdevlist=`echo "$metadev" | sed -e "s#/dev/rdsk/##"`
		elif [[ $metadev = /dev/md/rdsk/* ]]; then
       		 	metavol=`echo "$metadev" | sed -e "s#/dev/md/rdsk/##"`
			rootdevlist=`metastat -p $metavol |\
			grep -v "^$metavol[         ]" |\
			nawk '{print $4}' | sed -e "s#/dev/rdsk/##"`
		fi
	fi
	for rootdev in $rootdevlist
	do
		echo /dev/rdsk/$rootdev
	done
}

#
# Done once per transition from classic (dca) to multi boot
#
setup_stubboot()
{
	bootdev=`grep -v "^#" $rootprefix/etc/vfstab | grep pcfs | \
		grep "[ 	]/boot[ 	]"`
	if [[ -n $bootdev ]] ; then

		bootdev=`echo "$bootdev" | nawk '{print $1}'`
		rbootdev=`echo "$bootdev" | sed -e "s/dev\/dsk/dev\/rdsk/"`

		# Remount boot partition as /stubboot, set up new /boot
		mkdir -p $rootprefix/stubboot

		ERRMSG=$(umount $bootdev 2>&1)
		if [ $? -ne 0 ] ; then
			[ -n "${ERRMSG}" ] && echo "${ERRMSG}"
			fail "Unable to umount $bootdev."
		fi
		ERRMSG=$(mount -F pcfs $bootdev $rootprefix/stubboot 2>&1)
		if [ $? -ne 0 ] ; then
			[ -n "${ERRMSG}" ] && echo "${ERRMSG}"
			fail "Unable to mount $bootdev on $rootprefix/stubboot."
		fi

		mkdir -p $rootprefix/boot
		cp -r $rootprefix/stubboot/* $rootprefix/boot
	
		# adjust /etc/vfstab
		sed <$rootprefix/etc/vfstab \
		    -e "s/[ 	]\/boot[ 	]/	\/stubboot	/" | \
			sed -n >$rootprefix/etc/vfstab+ '
			/p0:boot/ {
				s/[ 	]no/	yes/
				}
				p
			'

		mv $rootprefix/etc/vfstab $rootprefix/etc/vfstab-
		mv $rootprefix/etc/vfstab+ $rootprefix/etc/vfstab
	fi
}

#
# multiboot: install grub on the boot slice
#
install_grub()
{
	STAGE1=$rootprefix/boot/grub/stage1
	STAGE2=$rootprefix/boot/grub/stage2

	if [ -x $rootprefix/boot/solaris/bin/update_grub ]; then
		/tmp/bfubin/ksh $rootprefix/boot/solaris/bin/update_grub \
		    -R $root
	elif [ $is_pcfs_boot = no ]; then
		get_rootdev_list | while read rootdev
		do 
			print "Install grub on $rootdev"
			PATH=/tmp/bfubin /tmp/bfubin/installgrub \
				$STAGE1 $STAGE2 $rootdev
		done
	else
		# copy /boot grub & solaris to /stubboot
		cp -r $rootprefix/boot/grub $rootprefix/stubboot/grub
		cp -r $rootprefix/boot/solaris $rootprefix/stubboot/solaris

		# Adjust grub paths relative to pcfs filesystem
		rm -rf $rootprefix/stubboot/boot
		mkdir -p $rootprefix/stubboot/boot
		mv $rootprefix/stubboot/grub $rootprefix/stubboot/boot
		mv $rootprefix/stubboot/solaris $rootprefix/stubboot/boot

		#
		# Run installgrub after copying stubboot to avoid overwriting
		# /stubboot/boot/grub/stage2, which must stay untouched.
		#
		bootdev=`grep -v "^#" $rootprefix/etc/vfstab | grep pcfs | \
			grep "[ 	]/stubboot[ 	]" | nawk '{print $1}'`
		rbootdev=`echo "$bootdev" | sed -e "s/dev\/dsk/dev\/rdsk/"`
		if [ "$rbootdev" != "" ]; then
			print "Install grub on $rbootdev"
			PATH=/tmp/bfubin /tmp/bfubin/installgrub $STAGE1 $STAGE2 $rbootdev
		fi
	fi
}

#
# We check for several possibilites of a bootenv.rc line:
#
# 1. setprop name 'value'
# 2. setprop name "value"
# 3. setprop name value
#
parse_bootenv_line()
{
	line=$1
	value=`echo $line | grep "'" | cut -d\' -f2`
	if [ -z "$value" ]; then
		value=`echo $line | grep "\"" | cut -d\" -f2`
		if [ -z "$value" ]; then
			value=`echo $line | cut -d' ' -f3-`
		fi
	fi
	echo $value
}

update_bootenv()
{
	bootenvrc=$rootprefix/boot/solaris/bootenv.rc
	bootenvrc_updated=0

	# Note: the big space below is actually a space and tab
	boot_file=`grep '^setprop[ 	]\{1,\}boot-file\>' $bootenvrc`
	if [ -n "$boot_file" ]; then
		file=`parse_bootenv_line "$boot_file"`
		if [ -n "$file" ]; then
			PATH=/tmp/bfubin /tmp/bfubin/bootadm set-menu kernel="$file"
			bootenvrc_updated=1
		fi
	fi

	console=`grep '^setprop[ 	]\{1,\}console\>' $bootenvrc`
	if [ -z "$console" ]; then
		console=`grep '^setprop[ 	]\{1,\}input-device\>' \
		    $bootenvrc`
	fi
	if [ -n "$console" ]; then
		cons=`parse_bootenv_line "$console"`
	fi
	boot_args=`grep '^setprop[ 	]\{1,\}boot-args\>' $bootenvrc`
	if [ -n "boot_args" ]; then
		args=`parse_bootenv_line "$boot_args"`
	fi
	if [ -n "$cons" ] && [ -n "$args" ]; then
		# If args starts with a -B, remove it and add a comma instead
		if echo $args | grep '^-B ' >/dev/null; then
			new_args=`echo $args | sed 's/^-B //'`
			args_line="-B console=$cons,$new_args"
		else
			args_line="-B console=$cons $args"
		fi
	elif [ -n "$cons" ]; then
		args_line="-B console=$cons"
	elif [ -n "$args" ]; then
		args_line="$args"
	else
		args_line=""
	fi
	if [ -n "$args_line" ]; then
		PATH=/tmp/bfubin /tmp/bfubin/bootadm set-menu args="$args_line"
		bootenvrc_updated=1
	fi

	if [ $bootenvrc_updated = 1 ]; then
		egrep -v '^setprop[ 	]+(boot-file|boot-args)[ 	]' $bootenvrc > ${bootenvrc}.new
		[ -s ${bootenvrc}.new ] && mv ${bootenvrc}.new $bootenvrc
	fi
}

get_biosdisk()
{
	rootdev=$1
	rootphys=`ls -l $rootdev | nawk '{ print $NF }' | \
	    sed -e "s/\.\.\/\.\.\/devices//" -e "s/:[abcdefgh],raw//"`
	rbootdev=`echo "$rootdev" | sed -e "s/s[0-7]/p0/"`

	#
	# Use biosdev to get the bios disk number
	#
	biosdisk=`biosdev | grep $rootphys | \
		nawk '{print $1}' | sed -e "s/0x8//"`
}

#
# multiboot: set up initial grub menu
#
update_grub_menu()
{
	MENU=$rootprefix/boot/grub/menu.lst

	grubhd=$1

	if [ $archive_type = multiboot ]; then
		BOOT_PROG="kernel /platform/i86pc/multiboot"
		BOOT_ARCHIVE="module /platform/i86pc/boot_archive"
	else
		#
		# directboot archives
		#
		BOOT_PROG="kernel\$ /platform/i86pc/kernel/\$ISADIR/unix"
		BOOT_ARCHIVE="module\$ /platform/i86pc/\$ISADIR/boot_archive"
	fi

	#
	# The failsafe archives may be different than the boot archives
	#
	if [ -x /boot/platform/i86pc/kernel/unix ]; then
		BOOT_FAILSAFE_FILE="/boot/platform/i86pc/kernel/unix"
		BOOT_FAILSAFE_SUFFIX=""
	else
		BOOT_FAILSAFE_FILE="/boot/multiboot"
		BOOT_FAILSAFE_SUFFIX="kernel/unix"
	fi

	#
	# Append some useful entries to the existing menu
	#
	echo "Update GRUB menu $MENU with entries for $grubhd"

	grep ^default $MENU > /dev/null
	[ $? = 0 ] || echo "default=0" >> $MENU
	grep ^timeout $MENU > /dev/null
	[ $? = 0 ] || echo "timeout=10" >> $MENU

	echo "#serial --unit=0 --speed=9600" >> $MENU
	echo "#terminal serial" >> $MENU
	echo "#splashimage=$grubhd/boot/grub/splash.xpm.gz" >> $MENU
	echo "title Solaris" >> $MENU
	echo "	root $grubhd" >> $MENU
	echo "	${BOOT_PROG}" >> $MENU
	echo "	${BOOT_ARCHIVE}" >> $MENU

	echo "GRUB menu entry 'Solaris' boots to eeprom(1m) settings"

	if [ -f ${rootprefix}/$BOOT_FAILSAFE_FILE ] &&
	    [ -f ${rootprefix}/boot/x86.miniroot-safe ] ; then

		TTY=`grep "^setprop input-device" \
		    ${rootprefix}/boot/solaris/bootenv.rc | cut -f 2 -d \'`
		if [ -z "${TTY}" ] ; then
			TTY=`grep "^setprop console" \
			    ${rootprefix}/boot/solaris/bootenv.rc | \
			    cut -f 2 -d \'`
		fi

		if [ "${TTY}" = "ttya" ] || [ "${TTY}" = "ttyb" ] ; then
			FS_CONSOLE="-B console=${TTY}"
		fi

cat >>$MENU <<EOF
title Solaris failsafe
  root $grubhd
  kernel $BOOT_FAILSAFE_FILE $BOOT_FAILSAFE_SUFFIX $FS_CONSOLE -s
  module /boot/x86.miniroot-safe
EOF
	fi
}

bootadm_f_flag=""

install_failsafe()
{
	if [ "$root" != "/" ] || \
	    [ -f /boot/x86.miniroot-safe ] || \
	    [ ! -x ${GATE}/public/bin/update_failsafe ]; then
		#
		# Either we're not bfu'ing /, or the failsafe archives were
		# already installed, or update_failsafe is not available.
		# If the old failsafe archives were multiboot, clear out the
		# directboot kernel.
		# 
		if [ $failsafe_type = multiboot ]; then
			rm -f $rootprefix/boot/platform/i86pc/kernel/unix
		elif [ $failsafe_type = directboot ]; then
			cp /tmp/bfubin/unix \
			    $rootprefix/boot/platform/i86pc/kernel/unix
		fi
	else
		echo "Updating failsafe archives"
		${GATE}/public/bin/update_failsafe

		# Force bootadm to update the failsafe entry
		bootadm_f_flag="-f"
	fi
}

#
# setup_grub_menu is only called when upgrading from a system
# with a dca boot.  This cannot happen on systems with zfs root,
# so this function need not take care of the case where the root
# file system type is zfs
#
setup_grub_menu()
{
	MENU=$rootprefix/boot/grub/menu.lst

	get_rootdev_list | while read rootdev
	do
		rootphys=`ls -l $rootdev | nawk '{print $NF}' | \
		    sed -e "s/\.\.\/\.\.\/devices//"`
		gslice=`echo "$rootphys" | cut -f 2 -d : | sed s/,raw//`
		rootphys=`echo "$rootphys" | sed -e "s/:[abcdefgh],raw//"`
		rbootdev=`echo "$rootdev" | sed -e "s/s[0-7]/p0/"`

		#
		# Wallow through fdisk to get the active partition number
		# Partition numbering is zero-based
		#
		part=0
		fdisk -W - $rbootdev | grep -v '^*' | grep -v '^$' | \
		while read id act bhead bcyl ehead ecyl rsect numsect
		do
			# Find solaris partition, either older 130 or 191
			if [ $id -eq "191" -o $id -eq "130" ] ; then
				break
			fi
			part=`expr "$part" + 1`
		done

		get_biosdisk $rootdev
		grubhd="(hd${biosdisk},${part},${gslice})"

		#
		# update the grub menu if it doesn't exist or
		# doesn't have usable boot entries
		#
		if [ -f $MENU ]; then
			grep -v "^#" $MENU | grep $grubhd >/dev/null 2>&1
			if [ $? -eq 1 ]; then
				update_grub_menu $grubhd
			fi
		else
			update_grub_menu $grubhd
		fi
	done
}

#
# Build the multiboot boot archive
#
build_boot_archive()
{
	#
	# We should be able to run bootadm here but that's a
	# little more complicated than one would think
	#bootadm_args=${rootprefix:+-R $rootprefix}
	#PATH=/tmp/bfubin /tmp/bfubin/bootadm update $bootadm_args

	cr_args=${rootprefix:+ -R $rootprefix}
	LD_LIBRARY_PATH=/tmp/bfulib PATH=/tmp/bfubin \
	    /tmp/bfubin/ksh $rootprefix/boot/solaris/bin/create_ramdisk $cr_args

	#
	# Disable the boot-archive service on the first boot
	# to silence complaints about new files
	# svccfg -s system/boot-archive setprop start/exec = true

	mkdir -p $rootprefix/bfu.conflicts/lib/svc/method
	cp $rootprefix/lib/svc/method/boot-archive \
	    $rootprefix/bfu.conflicts/lib/svc/method/boot-archive
	cat >$rootprefix/lib/svc/method/boot-archive <<"EOF"
#!/sbin/sh
exit 0
EOF

	cat >$rootprefix/etc/rc2.d/S99postbfu <<EOF
#!/bin/sh
#
case "\$1" in
'start')
	cp /bfu.conflicts/lib/svc/method/boot-archive /lib/svc/method/boot-archive
	chmod +x /lib/svc/method/boot-archive
        rm -f /etc/rc2.d/S99postbfu
        ;;
*)
        echo "usage: \$0 start"
        exit 1
        ;;
esac
exit 0
EOF

	chmod +x $rootprefix/etc/rc2.d/S99postbfu
	chmod +x $rootprefix/lib/svc/method/boot-archive
	chmod +x $rootprefix/bfu.conflicts/lib/svc/method/boot-archive
}

#
# Install failsafe archive on a sparc machine if not present.
# Use a well-known server for the archive if we need it.
#
install_sparc_failsafe()
{
	# check if failsafe already installed
        if [ -f $rootprefix/platform/$karch/failsafe ]; then
                 return
        fi
        if [ -z "$FAILSAFE_SERVER" ]; then
                FAILSAFE_SERVER="netinstall.sfbay"
        fi
        if [ -z "$FAILSAFE_IMAGE" ]; then
                FAILSAFE_IMAGE="export/nv/s/latest"
        fi
        fs_wos_image="/net/${FAILSAFE_SERVER}/${FAILSAFE_IMAGE}"
        fs_archive="${fs_wos_image}/boot/sparc.miniroot"
        if [ ! -d $fs_wos_image ] || [ ! -f $fs_archive ]; then
		# XXX Remove this fallback to a known good archive once real
                # XXX images with boot archives become available.
		fs_wos_image="/net/netinstall.sfbay/export/setje/nbs-latest"
                fs_archive="${fs_wos_image}/boot/sparc.miniroot"
        fi
        if [ -d $fs_wos_image ] || [ ! -f $fs_archive ]; then
                echo "Installing failsafe archive from $fs_wos_image"
                cp $fs_archive $rootprefix/platform/$karch/failsafe
        fi
}

disable_boot_service()
{
	svccfg -s system/boot-archive setprop start/exec = true
	cat >$rootprefix/lib/svc/method/boot-archive <<EOF
#!/sbin/sh
. /lib/svc/share/smf_include.sh
. /lib/svc/share/fs_include.sh
exit 0
EOF
}

dir_is_inherited() {
	dir=$1
	set -- `zonecfg -z $zone info inherit-pkg-dir dir=/$dir`
	[ "$3" = "/$dir" ] && return 0 || return 1
}

check_boot_env()
{
	if [ $multi_or_direct = yes ]; then
		if [ $archive_type != $system_type ]; then
			install_failsafe
			[ $system_type = dca ] && setup_grub_menu

			if [ $have_new_bootadm = yes ] ||
			    ( [ -x /tmp/bfubin/symdef ] &&
			    [ -x /tmp/bfubin/bootadm ] &&
			    /tmp/bfubin/symdef /tmp/bfubin/bootadm \
			    dboot_or_multiboot ); then
				if [[ -z $rootprefix ]]; then
					PATH=/tmp/bfubin /tmp/bfubin/bootadm \
					    -m upgrade $bootadm_f_flag
				else
					PATH=/tmp/bfubin /tmp/bfubin/bootadm \
					    -m upgrade -R $rootprefix \
					    $bootadm_f_flag
				fi
				install_grub
				[ $archive_type = directboot ] && update_bootenv
			else
				install_grub
				cat >&2 <<EOF

WARNING: Cannot find new bootadm.  If bfu'ing across the multiboot/directboot
boundary, you will need to manually change menu.lst.  See
http://www.sun.com/msg/SUNOS-8000-CF for details.

EOF
			fi

			#
			# If we're going backwards, we need to remove the
			# symdef binary.
			#
			if [ -f $rootprefix/boot/solaris/bin/symdef ] && \
			    [ $archive_type = multiboot ]
			then
				rm -f $rootprefix/boot/solaris/bin/symdef \
				    $rootprefix/boot/solaris/bin/update_grub
			fi
		elif [ $failsafe_type = multiboot ]; then
			rm -f $rootprefix/boot/platform/i86pc/kernel/unix
		elif [ $failsafe_type = directboot ]; then
			cp /tmp/bfubin/unix \
			    $rootprefix/boot/platform/i86pc/kernel/unix
		fi
		build_boot_archive
	else
		disable_boot_service
	fi
}

mondo_loop() {
	typeset pkgroot
	typeset pkg
	root=$1
	zone=$2
	if [ $zone != global ]; then
		usrroot=$root
	fi

	# If the archives being installed contain i86pc.boot, 
	# check to see if it contains strap.com, one of the
	# four possibly-required booters.  If i86pc.boot does,
	# try to upgrade the realmode booters from the current 
	# archive set.
	#
	# Don't bother doing the upgrade for diskless bfu, as the boot
	# will be done with floppy or PXE, which must match the build
	# anyway (floppy must match or add_install_client must be 
	# rerun), and in any event we can't touch the boot bits
	# for diskless boot from here.  Also don't do this for
	# any zone but 'global'.

	cd $root || fail "Cannot cd $root"
	rootprefix=${root%/}
	pkgroot=${rootprefix:+-R $rootprefix}

	if [ "$karch" = "i86pc" -a "$diskless" = "no" -a "$zone" = "global" ]
	then
		remove_properties
		check_system_type
		if boot_is_upgradeable $root && \
		    [ $archive_type = dca ]; then
			check_multi_to_dca_boot
			print "\nUpdating realmode boot loaders\n"
			update_realmode_booters $root
			setup_pboot
		fi
		if [ $multi_or_direct = yes ]; then
			check_dca_to_multiboot
			if [ $is_pcfs_boot = yes ]; then
				setup_stubboot
			fi
		fi
	fi

	# before we save away driver_aliases, remove any obsolete entries
	if [ $target_isa = i386 ]; then
		# need to remove old pci5853,1 entry for xpv. The correct
		# entry going forward is pci5853,1.1 which is now in
		# uts/intel/os/driver_aliases
		grep '\"pci5853,1\"' $root/etc/driver_aliases > /dev/null 2>&1
		if [ "$?" -eq 0 ]; then
			/tmp/bfubin/update_drv -b $root -d -i '"pci5853,1"' xpv > /dev/null 2>&1
		fi
	fi

	SECONDS=0		# time each iteration

	print "\nSaving configuration files in $rootprefix/bfu.child ... \c"
	cd $root
	rm -rf bfu.default bfu.restore	# historical
	rm -rf bfu.child bfu.conflicts
	mkdir bfu.child bfu.conflicts
	filelist $zone | cpio -pdmu bfu.child || \
	    fail 'failed to save config files'
	test -f etc/motd && mv etc/motd etc/motd.old

	#
	# If the var/sadm/system/admin/INST_RELEASE file still exists,
	# this system has never been bfu'd before.  Therefore, the
	# information in var/sadm/install/contents is still valid and
	# can be used to determine whether files have been modified
	# since installation (the bfu.ancestors directory serves this
	# purpose for systems that have already been bfu'd.)
	#
	if [ -f var/sadm/system/admin/INST_RELEASE ] ; then
		firstbfu=yes
	else
		firstbfu=no
	fi

	#
	# bfu'ed systems are not upgradeable; prevent suninstall from
	# even *presenting* the upgrade option by removing INST_RELEASE.
	#
	rm -f var/sadm/system/admin/INST_RELEASE

	#
	# Hacks to work around minor annoyances and make life more pleasant.
	# Part 1 of 2: pre-archive-extraction stuff
	#

	#
	# Do not remove remove_initd_links, since this makes sure things
	# work properly when init scripts are shuffled around.
	#
	remove_initd_links

	#
	# Remove rc.d scripts and things made superfluous by smf.
	# Backwards BFUs will resurrect them from the archives.
	#
	smf_cleanup

	#
	# New, enabled-by-default services need to be checked for, such
	# that their enabled status is not flipped by BFU after their
	# initial arrival.
	#
	smf_handle_new_services

	#
	# Handle unbundled TX conversion if needed
	#
	tx_check_update

      	# Reflect SUNWcsr's pre-install change, ensures
	# the i.hosts action script works during 'acr'	
	if [[ -f $rootprefix/etc/inet/ipnodes && \
			! -h $rootprefix/etc/inet/ipnodes ]]; then
		rm -f $rootprefix/etc/inet/ipnodes.hostsmerge
		cp -p $rootprefix/etc/inet/ipnodes \
			$rootprefix/etc/inet/ipnodes.hostsmerge
	fi

	#
	# Remove obsolete disassembler module
	#
	if [ $target_isa = sparc ]; then 
		rm -rf $usr/lib/mdb/disasm/*
		rm -f $root/kernel/kmdb/sparcv9/sparc
	fi

	#
	# Remove obsolete Sun-Fire-880 (daktari) FMA Fault Tree directory
	# and file.  Backwards BFUs will resurrect them from the archives.
	#
	if [ $target_isa = sparc ]; then
		rm -rf $usr/platform/SUNW,Sun-Fire-880/lib/fm
	fi

	#
	# Remove old ndpd header (moved to /usr/include per 6509782)
	#
	rm -f $usr/include/protocols/ndpd.h

	#
	# Remove old FMA dictionary files
	#
	rm -f $usr/lib/fm/FMD.dict
	rm -f $usr/lib/fm/SUN4U.dict
	rm -f $usr/lib/fm/SUNOS.dict

	# Remove unused SMF dictionary
	rm -f $root/usr/lib/fm/dict/SMF.dict
	rm -f $root/usr/lib/locale/C/LC_MESSAGES/SMF.mo

	#
	# Remove old FMA .eft files and directories
	#
	rm -f $usr/platform/sun4u/lib/fm/eft/pci-sun4u.eft
	rm -rf $usr/platform/SUNW,Serverblade1/lib/fm
	rm -rf $usr/platform/SUNW,Sun-Fire/lib/fm
	rm -rf $usr/platform/SUNW,Sun-Fire-15000/lib/fm

	#
	# Remove old FMA LDOMS files
	#
	rm -f $usr/platform/sun4v/lib/fm/fmd/libldom.so.1
	rm -f $usr/platform/sun4v/lib/fm/fmd/libldom.so
	rm -f $usr/platform/sun4v/lib/fm/fmd/llib-lldom
	rm -f $usr/platform/sun4v/lib/fm/fmd/llib-lldom.ln
	rm -f $usr/platform/sun4v/lib/fm/fmd/sparcv9/libldom.so.1
	rm -f $usr/platform/sun4v/lib/fm/fmd/sparcv9/libldom.so
	rm -f $usr/platform/sun4v/lib/fm/fmd/sparcv9/llib-lldom.ln

	#
	# Remove old topology data
	#
	rm -rf $usr/lib/fm/topo
	rm -f $usr/platform/*/lib/fm/topo/hc-topology.xml

	#
	# Remove old prtopo and obsoleted include file.
	#
	rm -f $usr/include/fm/libtopo_enum.h
	rm -f $usr/lib/fm/prtopo

	#
	# Remove fm driver
	#
	rm -f $root/kernel/drv/fm
	rm -f $root/kernel/drv/fm.conf
	rm -f $root/kernel/drv/amd64/fm
	rm -f $root/kernel/drv/sparcv9/fm

	#
	# Remove old AMD cpu module, to be replaced by extended cpu.generic
	# with AMD-specific support layered on top as a model-specific module.
	# Also remove the corresponding mdb and kmdb support.  Backwards BFU
	# will reintroduce these files.
	rm -f $root/platform/i86pc/kernel/cpu/cpu.AuthenticAMD.15
	rm -f $root/platform/i86pc/kernel/cpu/amd64/cpu.AuthenticAMD.15
	rm -f $root/usr/platform/i86pc/lib/mdb/kvm/cpu.AuthenticAMD.15.so
	rm -f $root/usr/platform/i86pc/lib/mdb/kvm/amd64/cpu.AuthenticAMD.15.so
	rm -f $root/usr/platform/i86pc/lib/mdb/kvm/cpu.generic.so
	rm -f $root/usr/platform/i86pc/lib/mdb/kvm/amd64/cpu.generic.so
	rm -f $root/usr/platform/i86pc/lib/mdb/kvm/cpu_ms.AuthenticAMD.15.so
	rm -f $root/usr/platform/i86pc/lib/mdb/kvm/amd64/cpu_ms.AuthenticAMD.15.so
	rm -f $root/usr/lib/mdb/kvm/cpu.generic.so
	rm -f $root/usr/lib/mdb/kvm/amd64/cpu.generic.so
	rm -f $root/usr/lib/mdb/kvm/cpu_ms.AuthenticAMD.15.so
	rm -f $root/usr/lib/mdb/kvm/amd64/cpu_ms.AuthenticAMD.15.so

	# Remove cpu.generic from i86xpv platform
	rm -f $root/platform/i86xpv/kernel/cpu/cpu.generic
	rm -f $root/platform/i86xpv/kernel/cpu/amd64/cpu.generic

	#
	# Remove obsolete buildmnttab script.  Backwards BFUs will
	# resurrect it by extracting it from the archives.
	#
	rm -f $root/etc/init.d/buildmnttab
	rm -f $root/etc/rcS.d/S70buildmnttab.sh

	#
	# Break-up of inetsvc, inetinit & network -- remove both the old
	# and new init scripts.  The correct ones will be extracted from
	# the archives whether bfu'ing backwards or forwards.
	#
	# old: need to remove going forwards:
	#
	rm -f $root/etc/rc0.d/K42inetsvc
	rm -f $root/etc/rc1.d/K42inetsvc
	rm -f $root/etc/rcS.d/K42inetsvc
	rm -f $root/etc/rcS.d/S29network.sh
	#
	# new: need to remove going backwards:
	#
	rm -f $root/etc/init.d/domainname
	rm -f $root/etc/init.d/inetd
	rm -f $root/etc/init.d/named
	rm -f $root/etc/init.d/nodename
	rm -f $root/etc/rc0.d/K40inetd
	rm -f $root/etc/rc0.d/K42named
	rm -f $root/etc/rc1.d/K40inetd
	rm -f $root/etc/rc1.d/K42named
	rm -f $root/etc/rc2.d/S69domainname
	rm -f $root/etc/rc2.d/S72named
	rm -f $root/etc/rc2.d/S77inetd
	rm -f $root/etc/rcS.d/K40inetd
	rm -f $root/etc/rcS.d/K42named
	rm -f $root/etc/rcS.d/S28network.sh
	rm -f $root/etc/rcS.d/S29nodename.sh

	#
	# Remove Zones init scripts: they will be extracted properly
	# going forwards; after going backwards, they will be gone,
	# thus preventing scary warnings on subsequent bfu's.
	#
	rm -f $root/etc/init.d/zones
	rm -f $root/etc/rc0.d/K01zones
	rm -f $root/etc/rc1.d/K01zones
	rm -f $root/etc/rc2.d/K01zones
	rm -f $root/etc/rc3.d/S99zones
	rm -f $root/etc/rcS.d/K01zones

	#
	# Remove <inet>6 STREAMS modules; these no longer exist (and
	# should never have existed in the first place).
	#
	rm -f $root/kernel/strmod/icmp6		\
	    $root/kernel/strmod/ip6		\
	    $root/kernel/strmod/tcp6		\
	    $root/kernel/strmod/udp6

	rm -f $root/kernel/strmod/sparcv9/icmp6 \
	    $root/kernel/strmod/sparcv9/ip6	\
	    $root/kernel/strmod/sparcv9/tcp6	\
	    $root/kernel/strmod/sparcv9/udp6

	#
	# Remove old ZFS binaries (back when it was three modules)
	#
	find $root/kernel/drv -name zpool 2> /dev/null | xargs rm -f
	rm -f $root/kernel/drv/zpool.conf
	rm -f $root/kernel/drv/zpool.cache

	find $root/kernel/drv -name zvol 2> /dev/null | xargs rm -f
	rm -f $root/kernel/drv/zvol.conf

	#
	# Remove /usr/lib/old_libthread since support for it has
	# been removed from the kernel in Solaris 10.  If this is
	# a backwards BFU, it will all be extracted again by cpio.
	rm -rf $usr/lib/old_libthread

	# Remove libconfig 
	rm -f $usr/lib/drv/config_md.so.1
	rm -f $usr/include/config_md.h
	# remove libssd
	rm -f $usr/lib/libssd.a
	rm -f $usr/lib/libssd.so
	rm -f $usr/lib/libssd.so.1
	# remove libap
	rm -f $usr/lib/libap_dmd.a
	rm -f $usr/lib/libap_dmd.so.1
	# remove libintpos
	rm -f $usr/lib/libintpos.a
	rm -f $usr/lib/libintpos.so.1

	# Remove obsolete abi subdirectories
	if [ -d $usr/platform/*/lib/abi ]; then
		rm -rf $usr/platform/*/lib/abi
	fi
	rm -rf $usr/lib/gss/abi
	rm -rf $usr/lib/krb5/abi
	rm -rf $usr/xpg4/lib/abi
	rm -rf $usr/ucblib/abi

	#
	# Remove old stuff related to libthread now that libthread has
	# been folded into libc and libthread_db has been renamed libc_db.
	# In addition, all the apptrace's tracing libraries (i.e., abi_*.so*),
	# spec2map and spec2trace are no longer needed, should be removed.
	rm -f	\
	    $usr/lib/mdb/proc/libthread.so		\
	    $usr/lib/mdb/proc/sparcv9/libthread.so	\
	    $usr/lib/abi/spec2map			\
	    $usr/lib/abi/spec2trace			\
	    $usr/lib/abi/abi_*.so*			\
	    $usr/lib/abi/sparcv9/abi_*.so*

	#
	# Remove the old symlink /lib => usr/lib, if necessary.
	# /lib is now a real directory in the root filesystem.
	# Remove all of the old static libraries and commands now
	# that we no longer build them.  If this is a backwards
	# BFU, all this will all be extracted again by cpio.
	rm $root/lib 2>/dev/null
	rm -rf $usr/lib/pics
	rm -rf $usr/sbin/static
	rm -f	\
	    $usr/ccs/lib/libcurses.a			\
	    $usr/ccs/lib/libform.a			\
	    $usr/ccs/lib/libgen.a			\
	    $usr/ccs/lib/libl.a				\
	    $usr/ccs/lib/libmalloc.a			\
	    $usr/ccs/lib/libmenu.a			\
	    $usr/ccs/lib/libpanel.a			\
	    $usr/ccs/lib/libtermcap.a			\
	    $usr/ccs/lib/libtermlib.a			\
	    $usr/ccs/lib/liby.a				\
	    $usr/lib/lib300.a				\
	    $usr/lib/lib300s.a				\
	    $usr/lib/lib4014.a				\
	    $usr/lib/lib450.a				\
	    $usr/lib/libTL.a				\
	    $usr/lib/libadm.a				\
	    $usr/lib/libadt_jni.a			\
	    $usr/lib/libbsdmalloc.a			\
	    $usr/lib/libbsm.a				\
	    $usr/lib/libc.a				\
	    $usr/lib/libc2.a				\
	    $usr/lib/libc2stubs.a			\
	    $usr/lib/libcmd.a				\
	    $usr/lib/libcrypt.a				\
	    $usr/lib/libcrypt_d.a			\
	    $usr/lib/libcrypt_i.a			\
	    $usr/lib/libcurses.a			\
	    $usr/lib/libdevid.a				\
	    $usr/lib/libdevinfo.a			\
	    $usr/lib/libdhcpagent.a			\
	    $usr/lib/libdhcputil.a			\
	    $usr/lib/libdl_stubs.a			\
	    $usr/lib/libefi.a				\
	    $usr/lib/libelf.a				\
	    $usr/lib/libform.a				\
	    $usr/lib/libgen.a				\
	    $usr/lib/libgenIO.a				\
	    $usr/lib/libike.a				\
	    $usr/lib/libinetcfg.a			\
	    $usr/lib/libinetutil.a			\
	    $usr/lib/libintl.a				\
	    $usr/lib/libkstat.a				\
	    $usr/lib/libl.a				\
	    $usr/lib/libldfeature.a			\
	    $usr/lib/libmail.a				\
	    $usr/lib/libmalloc.a			\
	    $usr/lib/libmapmalloc.a			\
	    $usr/lib/libmenu.a				\
	    $usr/lib/libmeta.a				\
	    $usr/lib/libmp.a				\
	    $usr/lib/libnisdb.a				\
	    $usr/lib/libnls.a				\
	    $usr/lib/libnsl.a				\
	    $usr/lib/libnss_compat.a			\
	    $usr/lib/libnss_dns.a			\
	    $usr/lib/libnss_files.a			\
	    $usr/lib/libnss_nis.a			\
	    $usr/lib/libnss_nisplus.a			\
	    $usr/lib/libp/libc.a			\
	    $usr/lib/libpam.a				\
	    $usr/lib/libpanel.a				\
	    $usr/lib/libplot.a				\
	    $usr/lib/librac.a				\
	    $usr/lib/libresolv.a			\
	    $usr/lib/librpcsvc.a			\
	    $usr/lib/libsec.a				\
	    $usr/lib/libsendfile.a			\
	    $usr/lib/libsocket.a			\
	    $usr/lib/libstraddr.a			\
	    $usr/lib/libtermcap.a			\
	    $usr/lib/libtermlib.a			\
	    $usr/lib/libuuid.a				\
	    $usr/lib/libvolmgt.a			\
	    $usr/lib/libvt0.a				\
	    $usr/lib/libw.a				\
	    $usr/lib/liby.a				\
	    $usr/lib/null.a				\
	    $usr/lib/sparcv9/libadt_jni.a		\
	    $usr/lib/sparcv9/libinetutil.a		\
	    $usr/lib/sparcv9/libldfeature.a		\
	    $usr/lib/sparcv9/libsendfile.a		\
	    $usr/platform/sun4u/lib/libwrsmconf.a	\
	    $usr/ucblib/libcurses.a			\
	    $usr/ucblib/libdbm.a			\
	    $usr/ucblib/libtermcap.a			\
	    $usr/ucblib/libucb.a

	#
	# Remove other obsolete files, too
	rm -f	\
	    $usr/include/table.h			\
	    $usr/include/libgenIO.h			\
	    $usr/include/sys/kd.h			\
	    $usr/lib/llib-lTL				\
	    $usr/lib/llib-lTL.ln

	#
	# libc_psr.so.1 and libmd5_psr.so.1 have been moved
	# from /usr/platform/*/lib to /platform/*/lib.
	# Remove the old files and their containing directories
	rm -f $usr/platform/*/lib/libc_psr.so.1
	rm -f $usr/platform/*/lib/sparcv9/libc_psr.so.1
	rm -f $usr/platform/*/lib/libmd5_psr.so.1
	rm -f $usr/platform/*/lib/sparcv9/libmd5_psr.so.1
	rmdir $usr/platform/*/lib/sparcv9 2>/dev/null
	rmdir $usr/platform/*/lib 2>/dev/null

	#
	# libmd5_psr.so.1 and symlinks to it have been replaced 
	# by libmd_psr.so.1 and thus need to be removed
	rm -f $root/platform/*/lib/libmd5_psr.so.1
	rm -f $root/platform/*/lib/sparcv9/libmd5_psr.so.1

	#
	# Remove obsolete profile libc symlinks
	rm -f $usr/lib/libp/libc.so
	rm -f $usr/lib/libp/sparcv9/libc.so

	#
	# Remove Legacy DR files, now obsolete due to NGDR Phase II putback
	#
	STARFIRE_PLAT=platform/SUNW,Ultra-Enterprise-10000 
		rm -f \
		$root/$STARFIRE_PLAT/kernel/drv/dr		\
		$root/$STARFIRE_PLAT/kernel/drv/dr.conf		\
		$root/$STARFIRE_PLAT/kernel/misc/drmach		\
		$root/$STARFIRE_PLAT/kernel/drv/sparcv9/dr	\
		$root/$STARFIRE_PLAT/kernel/misc/sparcv9/drmach	\
		$root/$STARFIRE_PLAT/lib/dr_daemon		\
		$usr/platform/sun4u/include/sys/dr.h	\
		$usr/platform/sun4u/include/sys/sfdr.h

	# Remove obsolete OPL platform links.
		rm -f $root/platform/FJSV,SPARC-Enterprise
		rm -f $root/platform/SUNW,OPL-Enterprise
		rm -f $usr/platform/FJSV,SPARC-Enterprise
		rm -f $usr/platform/SUNW,OPL-Enterprise

	# Solstice Enterprise Agent(SEA) : mib-II subagent mibiisa
	# needs to be disabled during startup. SMA(System Management Agent)
	# has the capability to support mib-II requests.
	# The correct ones will be extracted from
	# the archives whether bfu'ing backwards or forwards.
	#
	# old: need to remove going forwards:
	rm -f $root/etc/snmp/conf/mibiisa.rsrc
	#
	# new: need to remove going backwards:
	rm -f $root/etc/snmp/conf/mibiisa.rsrc-

	# remove old terminal emulator module:
	# (renamed from 'terminal-emulator' to 'tem')
	#
	# old: need to remove going forwards:
	rm -f $root/kernel/misc/terminal-emulator
	rm -f $root/kernel/misc/amd64/terminal-emulator
	#
	# new: need to remove going backwards:
	rm -f $root/kernel/misc/tem
	rm -f $root/kernel/misc/amd64/tem
	rm -f $root/kernel/misc/sparcv9/tem

	#
	# Remove /dev/mc symlink and /platform/sun4u/kernel/drv/mc-us3.conf
	# if any.
	#
	if [ -h $root/dev/mc ]; then
		rm -f $root/dev/mc
	fi

	if [ -f $root/platform/sun4u/kernel/drv/mc-us3.conf ]; then
		rm -f $root/platform/sun4u/kernel/drv/mc-us3.conf
	fi

	#
	# Remove the snowbird sbin and include symlinks
	#

	if [[ -h $usr/platform/SUNW,Netra-CP2300/sbin ]] ; then
		rm -f $usr/platform/SUNW,Netra-CP2300/sbin
	fi

	if [[ -h $usr/platform/SUNW,Netra-CP2300/include ]] ; then
		rm -f $usr/platform/SUNW,Netra-CP2300/include
	fi

	# If we still have the old lp(7D) driver, remove it and its symlinks
	# and header file. (If driver already gone, don't trample new symlinks.)
	#
	if [ -f $root/platform/i86pc/kernel/drv/lp -a \
	    -h $root/dev/lp[012] ]; then
		rm -f $root/dev/lp[012]
	fi
	rm -f $root/platform/i86pc/kernel/drv/lp.conf
	rm -f $root/platform/i86pc/kernel/drv/lp
	rm -f $root/usr/include/sys/lp.h

	#
	# Remove V880 CPU DR files, program cancelled
	#
	DAKTARI_PLAT=platform/SUNW,Sun-Fire-880
		rm -f \
		$root/$DAKTARI_PLAT/kernel/drv/gptwo.conf	\
		$root/$DAKTARI_PLAT/kernel/drv/sparcv9/bbc	\
		$root/$DAKTARI_PLAT/kernel/drv/sparcv9/gptwo	\
		$root/$DAKTARI_PLAT/kernel/misc/sparcv9/sbdp	\
		$usr/platform/sun4u/include/sys/sbdp.h

	#
	# Remove crash(1M), now obsoleted by mdb(1).  If this is a backwards
	# BFU, it will be extracted again by cpio.
	#
	rm -f $root/etc/crash $usr/sbin/crash $usr/sbin/i86/crash \
	    $usr/sbin/sparcv7/crash $usr/sbin/sparcv9/crash

	#
	# Remove kadb(1M), now obsoleted by kmdb(1M)
	#
	rm -f $root/platform/*/kadb

	#
	# Remove old platform dmod symlinks
	#
	for dir in $usr/platform/*/lib/mdb ; do
		[[ -h $dir ]] && rm -f $dir
	done

	#
	# Remove ADB macros
	#
	rm -fr $usr/lib/adb

	for dir in $usr/platform/*/lib/adb ; do
		rm -fr $dir
	done

	#
	# Remove the SGENV driver from the Sun-Fire directory structure.
	# If this is a backwards BFU, it will be extracted again by cpio.
	#
	SERENGETI_PLAT=platform/SUNW,Sun-Fire
	rm -f $root/$SERENGETI_PLAT/kernel/drv/sgenv.conf \
	    $root/$SERENGETI_PLAT/kernel/drv/sparcv9/sgenv

	#
	# Remove sun4m
	#
	rm -rf $root/platform/sun4m
	rm -rf $usr/platform/sun4m
	if [ $target_isa = sparc ]; then
		rm -f $root/kernel/genunix
	fi
	rm -f $root/kernel/drv/xbox
	rm -f $usr/include/sys/comvec.h
	rm -f $usr/include/sys/openprom.h
	rm -f $usr/include/sys/cg14io.h
	rm -f $usr/include/sys/cg14reg.h
	rm -f $usr/include/sys/cg8reg.h
	rm -f $usr/include/sys/cg8var.h

	#
	# Remove perl 5.005_03.  If this is a backwards bfu,
	# it will be extracted again by cpio.
	#
	if [[ -d $usr/perl5/5.00503 ]]; then
		remove_perl_500503
	fi

	#
	# Remove perl 5.8.3, but only if the generic.usr archive contains 5.8.4.
	# If this is a backwards bfu, 5.8.3 will be extracted again by cpio.
	#
	if [[ -d $usr/perl5/5.8.3 ]] && $ZCAT $cpiodir/generic.usr$ZFIX | \
	    cpio -it 2>/dev/null |  egrep -s '^usr/perl5/5.8.4/'; then
		remove_perl_583
	fi

	#
	# Clean up legacy versions of the FMA CPU/Mem DE which may be still
	# be laying around.  This check may be removed when a sufficient time
	# has lapsed between the FMA putback as to ensure that no test machines
	# still have development FMA bits.
	#
	for platdir in $usr/platform/SUNW,* ; do
		[[ -h $platdir ]] && continue

		rm -f $platdir/lib/fm/fmd/plugins/cpumem-diagnosis.so
		rm -f $platdir/lib/fm/fmd/plugins/cpumem-diagnosis.conf 
	done

	#
	# Clean up legacy versions of x4500 FMA modules which may be still
	# be laying around.  This check may be removed when a sufficient time
	# has lapsed between the FMA putback as to ensure that no test machines
	# still have development FMA bits.
	#
	rm -f $usr/platform/i86pc/lib/fm/topo/plugins/sata.so
	rm -f $usr/platform/i86pc/lib/fm/topo/maps/storage-hc-topology.xml
	rm -f $usr/platform/i86pc/lib/fm/fmd/plugins/sfx4500-disk.so
	rm -f $usr/platform/i86pc/lib/fm/fmd/plugins/sfx4500-disk.conf

	# Remove pam_unix
	#
	rm -f $usr/lib/security/pam_unix.so.1
	rm -f $usr/lib/security/pam_unix.so
	rm -f $usr/lib/security/sparcv9/pam_unix.so.1
	rm -f $usr/lib/security/sparcv9/pam_unix.so

	#
	# Remove pam_projects
	rm -f $usr/lib/security/pam_projects.so.1
	rm -f $usr/lib/security/pam_projects.so
	rm -f $usr/lib/security/64/pam_projects.so.1
	rm -f $usr/lib/security/64/pam_projects.so

	#
	# Remove libldap.so.3
	#
	rm -f $usr/lib/libldap.so.3
	rm -f $usr/lib/sparcv9/libldap.so.3

	#
	# Remove nss XFN support no longer used by printing
	#
	sed -e '/printers:/s/xfn[  ]*//' \
		$rootprefix/bfu.child/etc/nsswitch.conf > /tmp/nssw.$$
	cp /tmp/nssw.$$ $rootprefix/bfu.child/etc/nsswitch.conf
	rm -f /tmp/nssw.$$
	rm -f $usr/lib/nss_xfn.so.1
	rm -f $usr/lib/sparcv9/nss_xfn.so.1

	#
	# Remove FNS/XFN.
	#
	if [ -d $rootprefix/etc/fn -o \
	     -d $usr/include/xfn -o \
	     -d $usr/lib/fn -o \
	     -d $rootprefix/var/fn ]; then
		remove_eof_fns
	fi

	#
	# Remove AT&T FACE
	#
	if [ -d $usr/oasys -o -d $usr/vmsys ]; then
		remove_eof_face
	fi

	#
	# Remove DMI
	#
	if [ -d $usr/lib/dmi -o \
	     -d $rootprefix/etc/dmi -o \
	     -d $rootprefix/var/dmi ]; then
	        remove_eof_dmi
	fi

	#
	# Remove Wildcat
	#
	if [ -f $rootprefix/platform/SUNW,Sun-Fire-15000/kernel/misc/sparcv9/gptwo_wci -o \
	     -f $usr/platform/SUNW,Sun-Fire/lib/rsmlib/wrsm.so.1 -o \
	     -f $rootprefix/platform/sun4u/kernel/drv/wrsmd.conf -o \
	     -d $rootprefix/etc/wrsm -o \
	     -f $usr/platform/sun4u/sbin/wrsmstat ]; then
		remove_eof_wildcat
	fi

	#
	# Remove ASET
	#
	if [ -d $usr/aset ]; then
		remove_eof_aset
	fi

	#
	# Remove BIND 8, but only if the generic.usr archive doesn't contains
	# BIND 8 named server/tools. If this is a backwards bfu, BIND 8 will
	# be extracted again by cpio.
	#
	if [[ -f $usr/sbin/dnskeygen ]] && ! $ZCAT $cpiodir/generic.usr$ZFIX \
	    | cpio -it 2>/dev/null |  egrep -s '^usr/sbin/ndc' ; then
		remove_eof_bind8
	fi

	#
	# Remove any sendmailvars: line from /etc/nsswitch.conf
	#
	sed -e '/^sendmailvars:/d' $rootprefix/bfu.child/etc/nsswitch.conf > \
		/tmp/nssw.$$
	cp /tmp/nssw.$$ $rootprefix/bfu.child/etc/nsswitch.conf
	rm -f /tmp/nssw.$$

	#
	# Remove vold
	#
	if [ -f $rootprefix/etc/vold.conf -o -d $usr/lib/vold ]; then
		remove_eof_vold
	fi

	#
	# Remove obsolete Mobile IP software
	#
	if [[ -f $rootprefix/etc/init.d/mipagent || \
	    -f $rootprefix/usr/lib/inet/mipagent ]]; then
		remove_eof_mobileip
	fi

	#
	# Remove SUNWcoff package
	#
	pkg=SUNWcoff
	if [ $target_isa = i386 ]; then
		if pkginfo $pkgroot -q $pkg; then
			pkgrm $pkgroot -n $pkg >/dev/null 2>&1
		fi

		# In case that did not work, do it manually.
		if [ -d $rootprefix/var/sadm/pkg/$pkg ]; then
			rm -rf $rootprefix/var/sadm/pkg/$pkg
			rm $rootprefix/kernel/exec/coffexec
		fi
	fi

	#
	# Remove GMT* zoneinfo files
	#
	rm -f $usr/share/lib/zoneinfo/GMT-12
	rm -f $usr/share/lib/zoneinfo/GMT-11
	rm -f $usr/share/lib/zoneinfo/GMT-10
	rm -f $usr/share/lib/zoneinfo/GMT-9
	rm -f $usr/share/lib/zoneinfo/GMT-8
	rm -f $usr/share/lib/zoneinfo/GMT-7
	rm -f $usr/share/lib/zoneinfo/GMT-6
	rm -f $usr/share/lib/zoneinfo/GMT-5
	rm -f $usr/share/lib/zoneinfo/GMT-4
	rm -f $usr/share/lib/zoneinfo/GMT-3
	rm -f $usr/share/lib/zoneinfo/GMT-2
	rm -f $usr/share/lib/zoneinfo/GMT-1
	rm -f $usr/share/lib/zoneinfo/GMT+1
	rm -f $usr/share/lib/zoneinfo/GMT+2
	rm -f $usr/share/lib/zoneinfo/GMT+3
	rm -f $usr/share/lib/zoneinfo/GMT+4
	rm -f $usr/share/lib/zoneinfo/GMT+5
	rm -f $usr/share/lib/zoneinfo/GMT+6
	rm -f $usr/share/lib/zoneinfo/GMT+7
	rm -f $usr/share/lib/zoneinfo/GMT+8
	rm -f $usr/share/lib/zoneinfo/GMT+9
	rm -f $usr/share/lib/zoneinfo/GMT+10
	rm -f $usr/share/lib/zoneinfo/GMT+11
	rm -f $usr/share/lib/zoneinfo/GMT+12
	rm -f $usr/share/lib/zoneinfo/GMT+13

	# Remove stc(7d)-related files
	rm -f $usr/include/sys/stcio.h
	rm -f $usr/include/sys/stcvar.h
	rm -f $usr/include/sys/stcreg.h
	rm -f $usr/include/sys/stcconf.h
	SUN4U_DRV=platform/sun4u/kernel/drv
	rm -f $rootprefix/$SUN4U_DRV/stc.conf
	rm -f $rootprefix/$SUN4U_DRV/stc
	rm -f $rootprefix/$SUN4U_DRV/sparcv9/stc

	# Remove old CPC adb macros.
	rm -f $usr/lib/adb/cpc_ctx
	rm -f $usr/lib/adb/cpc_event
	if [ $target_isa = sparc ]; then
	    rm -f $usr/lib/adb/sparcv9/cpc_ctx
	    rm -f $usr/lib/adb/sparcv9/cpc_event
	fi;

	# Remove obsolete DTrace demos
	rm -f $usr/demo/dtrace/cputick.d

	# Remove flashprom-related files.
	if [ $target_isa = sparc ]; then
	    for x in $FLASHPROMLIST
	    do
		rm -f $root/$x;
	    done
	fi;

	# Remove pt_chmod - obsoleted by new /dev filesystem
	if [ $zone = global ]; then
	   rm -f $usr/lib/pt_chmod
	fi

	if [ $RM_32BIT_KERNEL -eq 1 -a $zone = global ];
	then
	    print "Removing 32-bit commands and kernel binaries ... \c";
	    rm -rf \
		$usr/bin/sparcv7/amt \
		$usr/bin/sparcv7/cputrack \
		$usr/bin/sparcv7/newtask \
		$usr/bin/sparcv7/nohup \
		$usr/bin/sparcv7/pargs \
		$usr/bin/sparcv7/pcred \
		$usr/bin/sparcv7/pfiles \
		$usr/bin/sparcv7/pflags \
		$usr/bin/sparcv7/pldd \
		$usr/bin/sparcv7/plimit \
		$usr/bin/sparcv7/pmap \
		$usr/bin/sparcv7/ppgsz \
		$usr/bin/sparcv7/ppriv \
		$usr/bin/sparcv7/prctl \
		$usr/bin/sparcv7/preap \
		$usr/bin/sparcv7/prex \
		$usr/bin/sparcv7/prstat \
		$usr/bin/sparcv7/prun \
		$usr/bin/sparcv7/ps \
		$usr/bin/sparcv7/psig \
		$usr/bin/sparcv7/pstack \
		$usr/bin/sparcv7/pstop \
		$usr/bin/sparcv7/ptime \
		$usr/bin/sparcv7/ptree \
		$usr/bin/sparcv7/pwait \
		$usr/bin/sparcv7/pwdx \
		$usr/bin/sparcv7/setuname \
		$usr/bin/sparcv7/sort \
		$usr/bin/sparcv7/tnfxtract \
		$usr/bin/sparcv7/uptime \
		$usr/bin/sparcv7/w \
		$usr/sbin/sparcv7/intrstat \
		$usr/sbin/sparcv7/lockstat \
		$usr/sbin/sparcv7/prtconf \
		$usr/sbin/sparcv7/swap \
		$usr/sbin/sparcv7/sysdef \
		$usr/sbin/sparcv7/whodo \
		$root/kernel/dacf/consconfig_dacf \
		$root/kernel/drv/arp \
		$root/kernel/drv/audiocs \
		$root/kernel/drv/audioens \
		$root/kernel/drv/bofi \
		$root/kernel/drv/bpp \
		$root/kernel/drv/clone \
		$root/kernel/drv/cn \
		$root/kernel/drv/conskbd \
		$root/kernel/drv/consms \
		$root/kernel/drv/dad \
		$root/kernel/drv/devinfo \
		$root/kernel/drv/ecpp \
		$root/kernel/drv/ehci \
		$root/kernel/drv/esp \
		$root/kernel/drv/fas \
		$root/kernel/drv/fcip \
		$root/kernel/drv/fcp \
		$root/kernel/drv/fp \
		$root/kernel/drv/glm \
		$root/kernel/drv/hid \
		$root/kernel/drv/hme \
		$root/kernel/drv/hubd \
		$root/kernel/drv/icmp \
		$root/kernel/drv/icmp6 \
		$root/kernel/drv/ifp \
		$root/kernel/drv/ip \
		$root/kernel/drv/ip6 \
		$root/kernel/drv/ippctl \
		$root/kernel/drv/ipsecah \
		$root/kernel/drv/ipsecesp \
		$root/kernel/drv/isp \
		$root/kernel/drv/iwscn \
		$root/kernel/drv/keysock \
		$root/kernel/drv/le \
		$root/kernel/drv/lebuffer \
		$root/kernel/drv/llc1 \
		$root/kernel/drv/lofi \
		$root/kernel/drv/log \
		$root/kernel/drv/md \
		$root/kernel/drv/mm \
		$root/kernel/drv/mpt \
		$root/kernel/drv/nca \
		$root/kernel/drv/ohci \
		$root/kernel/drv/openeepr \
		$root/kernel/drv/options \
		$root/kernel/drv/pcata \
		$root/kernel/drv/pcelx \
		$root/kernel/drv/pcic \
		$root/kernel/drv/pcmem \
		$root/kernel/drv/pcram \
		$root/kernel/drv/pcs \
		$root/kernel/drv/pcser \
		$root/kernel/drv/pem \
		$root/kernel/drv/pln \
		$root/kernel/drv/poll \
		$root/kernel/drv/pseudo \
		$root/kernel/drv/ptc \
		$root/kernel/drv/ptsl \
		$root/kernel/drv/qlc \
		$root/kernel/drv/random \
		$root/kernel/drv/rts \
		$root/kernel/drv/sad \
		$root/kernel/drv/scsa2usb \
		$root/kernel/drv/scsi_vhci \
		$root/kernel/drv/sd \
		$root/kernel/drv/se \
		$root/kernel/drv/ses \
		$root/kernel/drv/sgen \
		$root/kernel/drv/soc \
		$root/kernel/drv/socal \
		$root/kernel/drv/spdsock \
		$root/kernel/drv/ssd \
		$root/kernel/drv/st \
		$root/kernel/drv/stp4020 \
		$root/kernel/drv/sy \
		$root/kernel/drv/sysmsg \
		$root/kernel/drv/tcp \
		$root/kernel/drv/tcp6 \
		$root/kernel/drv/tl \
		$root/kernel/drv/uata \
		$root/kernel/drv/udp \
		$root/kernel/drv/udp6 \
		$root/kernel/drv/ugen \
		$root/kernel/drv/usb_ac \
		$root/kernel/drv/usb_as \
		$root/kernel/drv/usb_mid \
		$root/kernel/drv/usbprn \
		$root/kernel/drv/usbser_edge \
		$root/kernel/drv/usoc \
		$root/kernel/drv/wc \
		$root/kernel/exec/aoutexec \
		$root/kernel/exec/elfexec \
		$root/kernel/exec/intpexec \
		$root/kernel/fs/autofs \
		$root/kernel/fs/cachefs \
		$root/kernel/fs/devfs \
		$root/kernel/fs/fifofs \
		$root/kernel/fs/hsfs \
		$root/kernel/fs/lofs \
		$root/kernel/fs/mntfs \
		$root/kernel/fs/nfs \
		$root/kernel/fs/procfs \
		$root/kernel/fs/sockfs \
		$root/kernel/fs/specfs \
		$root/kernel/fs/tmpfs \
		$root/kernel/fs/udfs \
		$root/kernel/fs/ufs \
		$root/kernel/ipp/dlcosmk \
		$root/kernel/ipp/dscpmk \
		$root/kernel/ipp/flowacct \
		$root/kernel/ipp/ipgpc \
		$root/kernel/ipp/tokenmt \
		$root/kernel/ipp/tswtclmt \
		$root/kernel/misc/amsrc1 \
		$root/kernel/misc/audiosup \
		$root/kernel/misc/busra \
		$root/kernel/misc/consconfig \
		$root/kernel/misc/dada \
		$root/kernel/misc/des \
		$root/kernel/misc/diaudio \
		$root/kernel/misc/fctl \
		$root/kernel/misc/fssnap_if \
		$root/kernel/misc/gld \
		$root/kernel/misc/hidparser \
		$root/kernel/misc/hpcsvc \
		$root/kernel/misc/ipc \
		$root/kernel/misc/kbtrans \
		$root/kernel/misc/kgss/do_kmech_krb5 \
		$root/kernel/misc/kgss/gl_kmech_krb5 \
		$root/kernel/misc/kgssapi \
		$root/kernel/misc/klmmod \
		$root/kernel/misc/klmops \
		$root/kernel/misc/krtld \
		$root/kernel/misc/md5 \
		$root/kernel/misc/md_hotspares \
		$root/kernel/misc/md_mirror \
		$root/kernel/misc/md_notify \
		$root/kernel/misc/md_raid \
		$root/kernel/misc/md_sp \
		$root/kernel/misc/md_stripe \
		$root/kernel/misc/md_trans \
		$root/kernel/misc/mixer \
		$root/kernel/misc/mpxio \
		$root/kernel/misc/nfs_dlboot \
		$root/kernel/misc/nfssrv \
		$root/kernel/misc/pcicfg \
		$root/kernel/misc/pcihp \
		$root/kernel/misc/phx \
		$root/kernel/misc/rpcsec \
		$root/kernel/misc/rpcsec_gss \
		$root/kernel/misc/rsmops \
		$root/kernel/misc/scsi \
		$root/kernel/misc/seg_drv \
		$root/kernel/misc/seg_mapdev \
		$root/kernel/misc/sha1 \
		$root/kernel/misc/strplumb \
		$root/kernel/misc/swapgeneric \
		$root/kernel/misc/tlimod \
		$root/kernel/misc/ufs_log \
		$root/kernel/misc/usba \
		$root/kernel/misc/usbser \
		$root/kernel/sched/TS \
		$root/kernel/sched/TS_DPTBL \
		$root/kernel/strmod/6to4tun \
		$root/kernel/strmod/arp \
		$root/kernel/strmod/atun \
		$root/kernel/strmod/authmd5h \
		$root/kernel/strmod/authsha1 \
		$root/kernel/strmod/bufmod \
		$root/kernel/strmod/connld \
		$root/kernel/strmod/dedump \
		$root/kernel/strmod/drcompat \
		$root/kernel/strmod/encr3des \
		$root/kernel/strmod/encraes \
		$root/kernel/strmod/encrbfsh \
		$root/kernel/strmod/encrdes \
		$root/kernel/strmod/icmp \
		$root/kernel/strmod/ip \
		$root/kernel/strmod/ipsecah \
		$root/kernel/strmod/ipsecesp \
		$root/kernel/strmod/keysock \
		$root/kernel/strmod/ldterm \
		$root/kernel/strmod/ms \
		$root/kernel/strmod/nca \
		$root/kernel/strmod/pckt \
		$root/kernel/strmod/pfmod \
		$root/kernel/strmod/pipemod \
		$root/kernel/strmod/ptem \
		$root/kernel/strmod/redirmod \
		$root/kernel/strmod/rpcmod \
		$root/kernel/strmod/rts \
		$root/kernel/strmod/tcp \
		$root/kernel/strmod/timod \
		$root/kernel/strmod/tirdwr \
		$root/kernel/strmod/ttcompat \
		$root/kernel/strmod/tun \
		$root/kernel/strmod/udp \
		$root/kernel/strmod/usb_ah \
		$root/kernel/strmod/usbkbm \
		$root/kernel/strmod/usbms \
		$root/kernel/sys/c2audit \
		$root/kernel/sys/doorfs \
		$root/kernel/sys/inst_sync \
		$root/kernel/sys/kaio \
		$root/kernel/sys/msgsys \
		$root/kernel/sys/nfs \
		$root/kernel/sys/pipe \
		$root/kernel/sys/pset \
		$root/kernel/sys/rpcmod \
		$root/kernel/sys/semsys \
		$root/kernel/sys/shmsys \
		$root/platform/SUNW,Ultra-250/kernel/drv/envctrltwo \
		$root/platform/SUNW,Ultra-250/kernel/misc/platmod \
		$root/platform/SUNW,Ultra-4/kernel/drv/envctrl \
		$root/platform/SUNW,Ultra-4/kernel/misc/platmod \
		$root/platform/SUNW,Ultra-5_10/kernel/misc/platmod \
		$root/platform/SUNW,Ultra-80/kernel/misc/platmod \
		$root/platform/SUNW,Ultra-Enterprise-10000/kernel/cpu/SUNW,UltraSPARC \
		$root/platform/SUNW,Ultra-Enterprise-10000/kernel/cpu/SUNW,UltraSPARC-II \
		$root/platform/SUNW,Ultra-Enterprise-10000/kernel/drv/cvc \
		$root/platform/SUNW,Ultra-Enterprise-10000/kernel/drv/cvcredir \
		$root/platform/SUNW,Ultra-Enterprise-10000/kernel/drv/idn \
		$root/platform/SUNW,Ultra-Enterprise-10000/kernel/drv/ngdr \
		$root/platform/SUNW,Ultra-Enterprise-10000/kernel/drv/pcipsy \
		$root/platform/SUNW,Ultra-Enterprise-10000/kernel/drv/rootnex \
		$root/platform/SUNW,Ultra-Enterprise-10000/kernel/drv/sbus \
		$root/platform/SUNW,Ultra-Enterprise-10000/kernel/misc/ngdrmach \
		$root/platform/SUNW,Ultra-Enterprise-10000/kernel/misc/platmod \
		$root/platform/SUNW,Ultra-Enterprise-10000/kernel/unix \
		$root/platform/SUNW,Ultra-Enterprise/kernel/drv/ac \
		$root/platform/SUNW,Ultra-Enterprise/kernel/drv/central \
		$root/platform/SUNW,Ultra-Enterprise/kernel/drv/environ \
		$root/platform/SUNW,Ultra-Enterprise/kernel/drv/fhc \
		$root/platform/SUNW,Ultra-Enterprise/kernel/drv/simmstat \
		$root/platform/SUNW,Ultra-Enterprise/kernel/drv/sram \
		$root/platform/SUNW,Ultra-Enterprise/kernel/drv/sysctrl \
		$root/platform/SUNW,Ultra-Enterprise/kernel/misc/platmod \
		$root/platform/sun4u/boot.conf \
		$root/platform/sun4u/kernel/cpu/SUNW,UltraSPARC \
		$root/platform/sun4u/kernel/cpu/SUNW,UltraSPARC-II \
		$root/platform/sun4u/kernel/cpu/SUNW,UltraSPARC-III \
		$root/platform/sun4u/kernel/cpu/SUNW,UltraSPARC-III+ \
		$root/platform/sun4u/kernel/cpu/SUNW,UltraSPARC-IIIi \
		$root/platform/sun4u/kernel/cpu/SUNW,UltraSPARC-IIe \
		$root/platform/sun4u/kernel/cpu/SUNW,UltraSPARC-IIi \
		$root/platform/sun4u/kernel/cpu/SUNW,UltraSPARC-IV \
		$root/platform/sun4u/kernel/drv/bwtwo \
		$root/platform/sun4u/kernel/drv/cgsix \
		$root/platform/sun4u/kernel/drv/cgthree \
		$root/platform/sun4u/kernel/drv/cpc \
		$root/platform/sun4u/kernel/drv/db21554 \
		$root/platform/sun4u/kernel/drv/dma \
		$root/platform/sun4u/kernel/drv/ebus \
		$root/platform/sun4u/kernel/drv/fd \
		$root/platform/sun4u/kernel/drv/ledma \
		$root/platform/sun4u/kernel/drv/memtest \
		$root/platform/sun4u/kernel/drv/pci_pci \
		$root/platform/sun4u/kernel/drv/pcipsy \
		$root/platform/sun4u/kernel/drv/power \
		$root/platform/sun4u/kernel/drv/rootnex \
		$root/platform/sun4u/kernel/drv/sbbc \
		$root/platform/sun4u/kernel/drv/sbus \
		$root/platform/sun4u/kernel/drv/sbusmem \
		$root/platform/sun4u/kernel/drv/sf \
		$root/platform/sun4u/kernel/drv/simba \
		$root/platform/sun4u/kernel/drv/su \
		$root/platform/sun4u/kernel/drv/tod \
		$root/platform/sun4u/kernel/drv/trapstat \
		$root/platform/sun4u/kernel/drv/zs \
		$root/platform/sun4u/kernel/drv/zsh \
		$root/platform/sun4u/kernel/genunix \
		$root/platform/sun4u/kernel/misc/bootdev \
		$root/platform/sun4u/kernel/misc/cpr \
		$root/platform/sun4u/kernel/misc/forthdebug \
		$root/platform/sun4u/kernel/misc/kgss/do_kmech_krb5 \
		$root/platform/sun4u/kernel/misc/kgss/gl_kmech_krb5 \
		$root/platform/sun4u/kernel/misc/md5 \
		$root/platform/sun4u/kernel/misc/obpsym \
		$root/platform/sun4u/kernel/misc/pcmcia \
		$root/platform/sun4u/kernel/misc/platmod \
		$root/platform/sun4u/kernel/misc/vis \
		$root/platform/sun4u/kernel/strmod/kb \
		$root/platform/sun4u/kernel/sys/cpc \
		$root/platform/sun4u/kernel/tod/todmostek \
		$root/platform/sun4u/kernel/tod/todstarfire \
		$usr/include/v7/sys/mon_clock.h \
		$usr/kernel/drv/dump \
		$usr/kernel/drv/fssnap \
		$usr/kernel/drv/gen_drv \
		$usr/kernel/drv/kstat \
		$usr/kernel/drv/ksyms \
		$usr/kernel/drv/llc2 \
		$usr/kernel/drv/lo \
		$usr/kernel/drv/lockstat \
		$usr/kernel/drv/logindmux \
		$usr/kernel/drv/pm \
		$usr/kernel/drv/pshot \
		$usr/kernel/drv/ptm \
		$usr/kernel/drv/pts \
		$usr/kernel/drv/rsm \
		$usr/kernel/drv/sppp \
		$usr/kernel/drv/sppptun \
		$usr/kernel/drv/sysevent \
		$usr/kernel/drv/tidg \
		$usr/kernel/drv/tivc \
		$usr/kernel/drv/tmux \
		$usr/kernel/drv/tnf \
		$usr/kernel/drv/vol \
		$usr/kernel/drv/winlock \
		$usr/kernel/exec/javaexec \
		$usr/kernel/fs/fdfs \
		$usr/kernel/fs/namefs \
		$usr/kernel/fs/pcfs \
		$usr/kernel/sched/FSS \
		$usr/kernel/sched/FX \
		$usr/kernel/sched/FX_DPTBL \
		$usr/kernel/sched/IA \
		$usr/kernel/sched/RT \
		$usr/kernel/sched/RT_DPTBL \
		$usr/kernel/strmod/cryptmod \
		$usr/kernel/strmod/lmodb \
		$usr/kernel/strmod/lmode \
		$usr/kernel/strmod/lmodr \
		$usr/kernel/strmod/lmodt \
		$usr/kernel/strmod/rlmod \
		$usr/kernel/strmod/spppasyn \
		$usr/kernel/strmod/spppcomp \
		$usr/kernel/strmod/sppptun \
		$usr/kernel/strmod/telmod \
		$usr/kernel/sys/acctctl \
		$usr/kernel/sys/exacctsys \
		$usr/kernel/sys/sysacct \
		$usr/lib/gss/mech_spnego.so \
		$usr/lib/gss/mech_spnego.so.1 \
		$usr/lib/mdb/kvm/cpc.so \
		$usr/lib/mdb/kvm/genunix.so \
		$usr/lib/mdb/kvm/ip.so \
		$usr/lib/mdb/kvm/ipc.so \
		$usr/lib/mdb/kvm/ipp.so \
		$usr/lib/mdb/kvm/isp.so \
		$usr/lib/mdb/kvm/krtld.so \
		$usr/lib/mdb/kvm/lofs.so \
		$usr/lib/mdb/kvm/logindmux.so \
		$usr/lib/mdb/kvm/mdb_ks.so \
		$usr/lib/mdb/kvm/nca.so \
		$usr/lib/mdb/kvm/nfs.so \
		$usr/lib/mdb/kvm/ptm.so \
		$usr/lib/mdb/kvm/random.so \
		$usr/lib/mdb/kvm/sd.so \
		$usr/lib/mdb/kvm/sppp.so \
		$usr/lib/mdb/kvm/ssd.so \
		$usr/lib/mdb/kvm/ufs_log.so \
		$usr/lib/mdb/kvm/usba.so \
		$usr/lib/sparcv9/gss/mech_spnego.so \
		$usr/lib/sparcv9/gss/mech_spnego.so.1 \
		$usr/platform/SUNW,Ultra-1 \
		$usr/platform/SUNW,Ultra-250/doc \
		$usr/platform/SUNW,Ultra-250/lib/flash-update.sh \
		$usr/platform/SUNW,Ultra-250/lib/prom \
		$usr/platform/SUNW,Ultra-Enterprise-10000/doc \
		$usr/platform/SUNW,Ultra-Enterprise-10000/lib/flash-update.sh \
		$usr/platform/SUNW,Ultra-Enterprise-10000/lib/prom \
		$usr/platform/sun4u/lib/mdb/kvm/unix.so \
		$usr/platform/sun4u/lib/prom/SUNW,Ultra-1 > /dev/null 2>&1;
		print "done.";
	fi;

        # Remove pre dboot krtld as well as obsolete boot blocks
        #
        if [ $zone = global ]; then
                rm -rf \
                    $root/kernel/misc/sparcv9/krtld \
                    $root/platform/*/ufsboot \
                    $root/platform/*/lib/fs/*/bootblk \
                    $usr/platform/*/lib/fs/*/bootblk
        fi

	#
	# Remove kmdbmod from /kernel
	#
	rm -f $root/kernel/misc/sparcv9/kmdbmod

	#
	# Remove obsolete drivers/header files as a result of sun4v source
	# code reorg
	#
	rm -f $root/platform/sun4u/kernel/drv/sparcv9/pci_pci
	rm -f $root/platform/sun4u/kernel/misc/sparcv9/pcmcia
	rm -f $usr/include/v9/sys/traptrace.h
	rm -f $usr/platform/sun4u/include/sys/spitasi.h
	rm -f $usr/kernel/pcbe/sparcv9/pcbe.SUNW,UltraSPARC-T1

	#
        # Remove the IPsec encryption and authentication modules.
        # IPsec now uses the Kernel Crypto Framework for crypto.
        #
        rm -f $rootprefix/kernel/strmod/encr3des
        rm -f $rootprefix/kernel/strmod/encrdes
        rm -f $rootprefix/kernel/strmod/encrbfsh
        rm -f $rootprefix/kernel/strmod/encraes
        rm -f $rootprefix/kernel/strmod/authmd5h
        rm -f $rootprefix/kernel/strmod/authsha1
        rm -f $rootprefix/kernel/strmod/sparcv9/encr3des
        rm -f $rootprefix/kernel/strmod/sparcv9/encrdes
        rm -f $rootprefix/kernel/strmod/sparcv9/encrbfsh
        rm -f $rootprefix/kernel/strmod/sparcv9/encraes
        rm -f $rootprefix/kernel/strmod/sparcv9/authmd5h
        rm -f $rootprefix/kernel/strmod/sparcv9/authsha1

	#
	# Remove the now-obsolete "nattymod" STREAMS module.
	#
	rm -f $rootprefix/kernel/strmod/nattymod
	rm -f $rootprefix/kernel/strmod/amd64/nattymod
	rm -f $rootprefix/kernel/strmod/sparcv9/nattymod

        #
        # Remove obsolete SSA utility, firmware and fcode.
        # usr/lib/firmware/ssa contains ssafirmware 
        #
        rm -rf $usr/lib/firmware/ssa
        rm -f $usr/lib/firmware/fc_s/fc_s_fcode
        rm -f $usr/sbin/ssaadm

	#
	# Remove seg_drv, seg_mapdev driver
	#
	rm -f $root/kernel/misc/seg_drv
	rm -f $root/kernel/misc/sparcv9/seg_drv
	rm -f $usr/include/sys/seg_drv.h
	rm -f $root/kernel/misc/seg_mapdev
	rm -f $root/kernel/misc/sparcv9/seg_mapdev

	#
	# Remove mpxio module
	#
	rm -f $root/kernel/misc/sparcv9/mpxio

	#
	# Remove mpxio/vhci adb macros.
	#
	if [ $target_isa = sparc -a $zone = global ]; then
		rm -f $usr/lib/adb/mdi_client
		rm -f $usr/lib/adb/sparcv9/mdi_client
		rm -f $usr/lib/adb/mdi_pathinfo
		rm -f $usr/lib/adb/sparcv9/mdi_pathinfo
		rm -f $usr/lib/adb/mdi_phci
		rm -f $usr/lib/adb/sparcv9/mdi_phci
		rm -f $usr/lib/adb/mdi_vhci
		rm -f $usr/lib/adb/sparcv9/mdi_vhci
		rm -f $usr/lib/adb/scsi_vhci_pkt
		rm -f $usr/lib/adb/sparcv9/scsi_vhci_pkt
		rm -f $usr/lib/adb/scsi_vhci_softstate
		rm -f $usr/lib/adb/sparcv9/scsi_vhci_softstate
	fi

	#
	# Remove platform specific dmfe driver ... its common now
	if [ $target_isa = sparc ]; then
		rm -f $root/platform/sun4u/kernel/drv/sparcv9/dmfe
		rm -f $root/platform/sun4u/kernel/drv/dmfe.conf
	fi

	#
	# Remove EOF sbpro driver and supporting header file
	# (Note that .conf file may also appear in /platform)
	#
	if [ $target_isa = i386 ]; then
		rm -f $root/kernel/drv/sbpro
		rm -f $root/kernel/drv/sbpro.conf
		rm -f $root/platform/i86pc/kernel/drv/sbpro.conf
		rm -f $usr/include/sys/sbpro.h
	fi

	#
	# Diskless clients have already extracted /usr so don't delete this
	# Non-global zones never extracts /usr so don't delete these
	#
	if [ $diskless = no -a $zone = global ]; then
		rm -f $usr/sbin/stmsboot

		rm -f $usr/lib/mdb/kvm/mpxio.so
		rm -f $usr/lib/mdb/kvm/sparcv9/mpxio.so
		rm -f $usr/lib/mdb/kvm/amd64/mpxio.so
		rm -f $usr/lib/mdb/kvm/scsi_vhci.so
		rm -f $usr/lib/mdb/kvm/sparcv9/scsi_vhci.so
		rm -f $usr/lib/mdb/kvm/amd64/scsi_vhci.so
	fi
	rm -f $root/lib/mpxio/mpxio
	rm -f $root/lib/mpxio/stmsboot_util

	rm -f $root/kernel/kmdb/mpxio
	rm -f $root/kernel/kmdb/sparcv9/mpxio
	rm -f $root/kernel/kmdb/amd64/mpxio
	rm -f $root/kernel/kmdb/scsi_vhci
	rm -f $root/kernel/kmdb/sparcv9/scsi_vhci
	rm -f $root/kernel/kmdb/amd64/scsi_vhci

	#
	# Remove rpcib misc module (converted to driver)
	#
	rm -f $root/kernel/misc/sparcv9/rpcib
	rm -f $root/kernel/drv/sparcv9/rpcib

	#
	# Remove old smartcard header files
	#

	rm -f \
		$usr/include/smartcard.h \
		$usr/include/smartcard/ocf_authenticate.h \
		$usr/include/smartcard/ocf_core.h \
		$usr/include/smartcard/ocf_core_cardservices.h

	#
	# Remove smartcard libraries that should not have been shipped.
	#
	rm -rf  $usr/lib/smartcard/sparcv9/ \
		$usr/share/lib/smartcard/scmtester.jar

	#
	# Remove external smartcard reader driver
	#
	rm -f $usr/share/lib/smartcard/scmrsr3.jar

	#
	# Remove old internal smartcard reader driver
	#
	rm -f $usr/share/lib/smartcard/scmiscr.jar
	rm -f $usr/lib/smartcard/libSCMI2CNative.so
	rm -f $usr/lib/smartcard/libSCMI2CNative.so.1

	#
	# Remove Smart OS
	#
	rm -f $usr/share/lib/smartcard/smartos.jar

	#
	# Remove drivers & header files for EOL of soc & pln drivers
	# as per PSARC/2003/233
	#
	rm -f $root/kernel/drv/pln.conf
	rm -f $root/kernel/drv/sparcv9/pln
	rm -f $root/kernel/drv/sparcv9/soc
	rm -f $usr/include/sys/socvar.h
	rm -f $usr/include/sys/socmap.h
	rm -f $usr/include/sys/soc_cq_defs.h
	rm -f $usr/include/sys/socreg.h
	rm -f $usr/include/sys/scsi/adapters/plndef.h
	rm -f $usr/include/sys/scsi/adapters/plnvar.h
	rm -f $usr/include/sys/scsi/adapters/ssaisp.h
	rm -f $usr/include/sys/scsi/targets/pln_ctlr.h
	rm -f $usr/include/sys/scsi/targets/osesio.h

	#
	# PSARC/2003/629 Common Solaris Target Disk Driver
	# remove adb macro "scsi_disk" for the x86 platform
	#
	if [ $target_isa = i386 ]; then
		rm -f $usr/lib/adb/scsi_disk
	fi

	# Remove CPCv1 API header per PSARC/2004/648
	rm -f $usr/include/sys/cpc_event.h

	# Remove headers per PSARC/2005/561
	rm -f $usr/include/sys/nexusintr.h
	rm -f $usr/platform/sun4u/include/sys/nexusintr_impl.h
	rm -f $usr/platform/sun4v/include/sys/nexusintr_impl.h

	# Remove usr/lib/mail which has moved to etc/mail/cf, but first,
	# attempt to migrate any user-added files, which primarily live
	# under usr/lib/mail/cf .  Blow away the seven files which we
	# ship under that directory, then move any that remain to the
	# new location, which we will `mkdir -p` just to be safe.
	# If the zone in question is non-global, then skip all this.
	#
	if [ $zone = "global" ]; then
		# -d follow sym-links: make sure it's not a link.
		if [ -d $usr/lib/mail -a ! -h $usr/lib/mail ]; then
			# Only do this if usr/lib/mail is still a directory;
			# bfu'ing backwards does not merit such migration.
			rm -f $usr/lib/mail/cf/Makefile
			rm -f $usr/lib/mail/cf/main.cf
			rm -f $usr/lib/mail/cf/main.mc
			rm -f $usr/lib/mail/cf/submit.cf
			rm -f $usr/lib/mail/cf/submit.mc
			rm -f $usr/lib/mail/cf/subsidiary.cf
			rm -f $usr/lib/mail/cf/subsidiary.mc
			mkdir -p -m 0755 $root/etc/mail/cf/cf
			mv $usr/lib/mail/cf/* $root/etc/mail/cf/cf >/dev/null 2>&1
		fi
		rm -rf $usr/lib/mail
	fi

	# local.cf no longer needed with the advent of sendmail -bl
	rm -f $root/etc/mail/cf/cf/local.cf
	rm -f $root/etc/mail/cf/cf/local.mc
	rm -f $root/etc/mail/local.cf

	#
	# Remove drivers and header files for EOF of Lance Ethernet
	# driver(le) as per PSARC/2003/335.
	#
	rm -f $root/kernel/drv/le
	rm -f $root/kernel/drv/sparcv9/le
	rm -f $root/kernel/drv/lebuffer
	rm -f $root/kernel/drv/sparcv9/lebuffer
	rm -f $root/platform/sun4u/kernel/drv/ledma
	rm -f $root/platform/sun4u/kernel/drv/sparcv9/ledma
	rm -f $usr/include/sys/le.h
	rm -f $usr/include/sys/lance.h
	rm -f $usr/lib/adb/le
	rm -f $usr/lib/adb/lestr

	#
	# Remove drivers and header files for EOF of ieef driver as
	# per PSARC/2003/009
	#
	rm -f $root/kernel/drv/ieef
	rm -f $root/kernel/drv/ieef.conf
	rm -f $usr/include/sys/ieef.h
	rm -f $root/boot/solaris/drivers/notisa.010/ieef.bef

	#
	# Remove drivers and header files for EOF of elx driver as
	# per PSARC/2003/770
	#
	rm -f $root/platform/i86pc/kernel/drv/elx
	rm -f $root/platform/i86pc/kernel/drv/elx.conf
	rm -f $usr/include/sys/elx.h
	rm -f $root/boot/solaris/drivers/isa.175/elx.bef

	#
	# Remove drivers for EOF of pe driver as per PSARC/2004/051
	#
	rm -f $root/kernel/drv/pe
	rm -f $root/kernel/drv/pe.conf
	rm -f $root/boot/solaris/drivers/isa.125/pe3.bef

	#
	# Remove drivers for EOF of Compaq NCR, Compaq SMART2, AMI Mega
	# card and /usr/bin/smart2cfg as per PSARC/2003/701 and
	# PSARC/2004/207
	#
	rm -f $root/kernel/drv/cpqncr
	rm -f $root/kernel/drv/cpqncr.conf
	rm -f $root/boot/solaris/drivers/notisa.020/cpqncr.bef
	rm -f $root/platform/i86pc/kernel/drv/smartii
	rm -f $root/platform/i86pc/kernel/drv/smartii.conf
	rm -f $usr/bin/smart2cfg
	rm -f $root/kernel/drv/mega
	rm -f $root/kernel/drv/mega.conf
	rm -f $root/boot/solaris/drivers/notisa.010/mega.bef
	rm -f $root/kernel/mach/compaq
	rm -f $root/kernel/mach/corollary

	#
	# Remove eisa nexus driver and header files for EOF of EISA
	# support as per PSARC/2003/650
	#
	rm -f $root/platform/i86pc/kernel/drv/eisa
	rm -f $usr/platform/i86pc/include/sys/eisarom.h
	rm -f $usr/platform/i86pc/include/sys/nvm.h

	#
	# Remove xmem headers (they moved back to usr/include/sys/fs)
	#
	rm -f $usr/include/ia32/sys/fs/xmem.h
	rm -f $usr/include/ia32/sys/fs/seg_xmem.h
	rm -rf $usr/include/ia32/sys/fs

	#
	# Remove junk headers
	#
	rm -f $usr/platform/i86pc/include/sys/mcdma.h
	rm -f $usr/platform/i86pc/include/sys/xque.h

	#
	# Remove obsolete x86 hat layer and associated adb scripts
	#
	rm -f $root/platform/i86pc/kernel/mmu/mmu32
	rm -f $root/platform/i86pc/kernel/mmu/mmu36
	rm -rf $root/platform/i86pc/kernel/mmu
	rm -f $usr/lib/adb/hwpp
	rm -f $usr/lib/adb/hatppp
	rm -f $usr/lib/adb/hat.nxt
	rm -f $usr/lib/adb/hwpp.nxt
	
	#
	# Remove drivers for EOF of chs as per PSARC/2005/581
	#
	rm -f $root/kernel/drv/chs
	rm -f $root/kernel/drv/chs.conf
	rm -f $root/boot/solaris/drivers/notisa.020/chs.bef

	#
	# Remove drivers & header files for EOF of dbri as per PSARC 2005/582
	#
	rm -f $root/kernel/drv/sparcv9/dbri
	rm -f $root/usr/include/sys/dbriio.h
	rm -f $root/usr/include/sys/mmcodecreg.h

	#
	# Remove drivers for EOF of pcscsi as per PSARC/2005/003
	#
	rm -f $root/kernel/drv/pcscsi
	rm -f $root/kernel/drv/pcscsi.conf
	rm -f $root/boot/solaris/drivers/notisa.010/pcscsi.bef
	
	#
	# Remove drivers for EOF of dpt as per PSARC/2003/701
	#
	rm -f $root/boot/solaris/drivers/isa.125/dpt.bef
	rm -f $root/platform/i86pc/kernel/drv/dpt
	rm -f $root/platform/i86pc/kernel/drv/dpt.conf
	rm -rf $usr/include/sys/dktp/dpt

	#
	# Remove drivers for EOF of mlx driver as per PSARC/2003/701
	#
	rm -f $root/boot/solaris/drivers/notisa.010/mlx.bef
	rm -f $root/platform/i86pc/kernel/drv/mlx
	rm -f $root/platform/i86pc/kernel/drv/mlx.conf
	rm -rf $usr/include/sys/dktp/mlx

	#
	# Remove snlb
	#
	rm -f $root/kernel/misc/snlb
	rm -f $root/kernel/misc/amd64/snlb
	rm -f $root/usr/include/sys/dktp/dklb.h
	rm -f $root/usr/include/sys/dktp/snlb.h

	#
	# Remove objmgr
	#
	rm -f $root/kernel/drv/objmgr.conf
	rm -f $root/kernel/drv/objmgr
	rm -f $root/kernel/drv/amd64/objmgr
	rm -f $root/usr/include/sys/dktp/objmgr.h

	#
	# Remove other unused headers
	#
	rm -f $root/usr/include/sys/scsi/impl/pkt_wrapper.h
	rm -f $root/usr/include/sys/dktp/hba.h
	rm -f $root/usr/include/sys/dktp/cdtypes.h
	rm -f $root/usr/include/sys/dktp/scdk.h
	rm -f $root/usr/include/sys/dktp/scdkwatch.h
	rm -f $root/usr/include/sys/dktp/sctarget.h
	rm -f $root/usr/include/sys/dktp/tgcd.h
	rm -f $root/usr/include/sys/dktp/tgpassthru.h
	rm -f $root/usr/include/sys/dmfe.h
	rm -f $root/usr/include/sys/dmfe_impl.h
 
	#
	# Remove Floating Point Emulator for EOF as per PSARC/2003/651
	#
	rm -f $root/platform/i86pc/kernel/misc/emul_80387

	#
	# Remove 64-bit adp, cadp and cpqhpc
	#
	rm -f $root/kernel/drv/amd64/adp
	rm -f $root/kernel/drv/amd64/cadp
	rm -f $root/kernel/drv/amd64/cpqhpc

	#
	# Remove 64-bit i2o_bs, i2o_msg, i2o_scsi, pci_to_i2o, mscsi, ncrs,
	# msm, spwr, bscv, bscbus
	#
	rm -f $root/kernel/drv/amd64/i2o_bs
	rm -f $root/kernel/misc/amd64/i2o_msg
	rm -f $root/kernel/drv/amd64/i2o_scsi
	rm -f $root/kernel/drv/amd64/pci_to_i2o
	rm -f $root/platform/i86pc/kernel/drv/amd64/mscsi
	rm -f $root/kernel/drv/amd64/ncrs
	rm -f $root/platform/i86pc/kernel/drv/amd64/msm
	rm -f $root/kernel/drv/amd64/spwr
	rm -f $root/platform/i86pc/kernel/drv/amd64/bscv
	rm -f $root/platform/i86pc/kernel/drv/amd64/bscbus

	# Remove obsolete pfil modules, binaries, and configuration files
	rm -f $root/kernel/drv/pfil
	rm -f $root/kernel/drv/pfil.conf
	rm -f $root/kernel/drv/sparcv9/pfil
	rm -f $root/kernel/drv/amd64/pfil
	rm -f $root/kernel/strmod/pfil
	rm -f $root/kernel/strmod/sparcv9/pfil
	rm -f $root/kernel/strmod/amd64/pfil
	rm -f $root/usr/sbin/pfild

	# Remove obsolete atomic_prim.h file.
	rm -f $usr/include/v9/sys/atomic_prim.h

	#
	# Remove sc_nct binary and the corresponding symlink to sc_nct from the
	# Montecarlo platform specific directories (Reference: PSARC 2003/606). 
	# To be specific, the following binary will be removed.
	# /platform/SUNW,UltraSPARC-IIe-NetraCT-40/kernel/drv/sparcv9/sc_nct 
	# Also, the following symlink will be removed.
	# /platform/SUNW,UltraSPARC-IIe-NetraCT-60/kernel/drv/sparcv9/sc_nct
	#
	if [ -f $root/platform/SUNW,UltraSPARC-IIe-NetraCT-40/kernel/drv/sparcv9/sc_nct ]; then
		rm -f $root/platform/SUNW,UltraSPARC-IIe-NetraCT-40/kernel/drv/sparcv9/sc_nct
		rm -f $root/platform/SUNW,UltraSPARC-IIe-NetraCT-60/kernel/drv/sparcv9/sc_nct
	fi

	#
	# In case of bfu to an older release, remove traces of "new"
	# Kerberos mechanisms.  Kerberos libraries and paths are corrected
	# after extraction is complete.
	#
	rm -f $root/kernel/misc/kgss/kmech_krb5
	rm -f $root/kernel/misc/kgss/sparcv9/kmech_krb5
	rm -f $root/platform/$karch/kernel/misc/kgss/sparcv9/kmech_krb5
	#
	# Diskless clients have already extracted /usr so don't delete these
	# Non-global zones never extracts /usr so don't delete these
	#
	if [ $diskless = no -a $zone = global ]; then
		rm -f $usr/lib/gss/mech_krb5.so
		rm -f $usr/lib/gss/mech_krb5.so.1
		rm -f $usr/lib/sparcv9/gss/mech_krb5.so
		rm -f $usr/lib/sparcv9/gss/mech_krb5.so.1
	fi

	# Remove old OpenSSL stuff from SUNWwbint
	rm -rf $usr/include/openssl
	rm -rf $usr/lib/openssl

	#Remove ufs logging module - now merged into ufs module
	rm -f $rootprefix/kernel/misc/ufs_log
	rm -f $rootprefix/kernel/misc/sparcv9/ufs_log

	#Remove ufs_log mdb/kmdb modules - now merged in to ufs module
	rm -f $rootprefix/kernel/kmdb/ufs_log
	rm -f $rootprefix/kernel/kmdb/sparcv9/ufs_log
	rm -f $rootprefix/kernel/kmdb/amd64/ufs_log
	rm -f $rootprefix/usr/lib/mdb/kvm/ufs_log.so
	rm -f $rootprefix/usr/lib/mdb/kvm/sparcv9/ufs_log.so
	rm -f $rootprefix/usr/lib/mdb/kvm/amd64/ufs_log.so

	#Remove diskmgtd. If backward BFU, will get re-installed from
	#archive.
	rm -f $usr/lib/diskmgtd

	#
	# Remove old ia64 cruft
	#
	if [ $target_isa = i386 ]; then
		rm -f $usr/include/sys/ia64_archext.h
		rm -f $usr/include/sys/sysia64.h
		rm -rf $usr/include/ia64
	fi

	#
	# Remove machpage-related stuff
	#
	rm -f $usr/platform/*/include/vm/mach_page.h
	rm -f $usr/lib/adb/machpp

	#
	# Remove old cacheos
	#
	rm -f $root/etc/init.d/cacheos
	rm -f $root/etc/init.d/cacheos.finish
	rm -f $root/etc/init.d/cachefs.root
	rm -f $root/etc/rcS.d/S35cacheos.sh
	rm -f $root/etc/rc2.d/S93cacheos.finish
	rm -f $root/etc/rcS.d/S41cachefs.root

	#
	# Remove unneeded nfsmapid entries
	#
	nfsmapid_cfg

	#
	# Nuke the nfsauth headers when we're working with the 'global'
	# or a fully populated nonglobal zone. The cpio archive will lay the
	# right one to match mountd(1m)'s comm method w/the kernel (via
	# kRPC or Doors/XDR).
	#
	dir_is_inherited usr 2>/dev/null;
	if [ $? = 1 -o $zone = global ]; then
		rm -f ${rootprefix}/usr/include/rpcsvc/nfsauth_prot.x
		rm -f ${rootprefix}/usr/include/rpcsvc/nfsauth_prot.h
		rm -f ${rootprefix}/usr/include/nfs/auth.h
	fi

	#
	# Move the original manifests aside; later we will restore
	# unchanged originals to avoid superfluous re-import on reboot.
	# (First blow away the old dir path just to be safe.)
	#
	rm -rf $root/$old_mfst_dir
	[ -d $root/$new_mfst_dir ] && mv $root/$new_mfst_dir $root/$old_mfst_dir

	#
	# Remove obsolete sum.h
	#
	rm -f $usr/include/sum.h

	#
	# Remove obsolete std.h
	#
	rm -f $usr/include/std.h

	#
	# Remove obsolete rpc/trace.h
	#
	rm -f $usr/include/rpc/trace.h

	#
	# Remove acpi_intp module
	#
	if [ $target_isa = i386 ]; then
		rm -f $root/kernel/misc/acpi_intp
		rm -f $root/kernel/misc/amd64/acpi_intp
	fi

	#
	# Remove nxge module (moved to a generic location to support xVM)
	#
	if [ $target_isa = i386 ]; then
		rm -f $root/platform/i86pc/kernel/drv/nxge
		rm -f $root/platform/i86pc/kernel/drv/amd64/nxge
		# We're doing a backward bfu.
		rm -f $root/kernel/drv/nxge
		rm -f $root/kernel/drv/amd64/nxge
	fi

	#
	# Remove obsolete librac
	#
	rm -f $usr/include/rpc/rac.h
	rm -f $usr/lib/llib-lrac
	rm -f $usr/lib/llib-lrac.ln
	rm -f $usr/lib/amd64/llib-lrac.ln
	rm -f $usr/lib/sparcv9/llib-lrac.ln
	rm -f $usr/lib/librac.so
	rm -f $usr/lib/librac.so.1
	rm -f $usr/lib/amd64/librac.so
	rm -f $usr/lib/amd64/librac.so.1
	rm -f $usr/lib/sparcv9/librac.so
	rm -f $usr/lib/sparcv9/librac.so.1

	#
	# Remove /kernel/mac.  This directory was introduced by
	# PSARC/2006/248, and along with this came a syntax change to the
	# /etc/aggregation.conf file.  After archives have been extracted,
	# we check for the existance of the /kernel/mac directory to see if
	# we're doing a backward bfu and need to convert the syntax of the
	# /etc/aggregation.conf file to its old format.
	#
	if [ -d $root/kernel/mac ]; then
		from_new_aggrconf=1
		rm -rf $root/kernel/mac
	else
		from_new_aggrconf=0
	fi

	# Remove libcmd from $root/lib.  It has moved back to $usr/lib.
	rm -f $root/lib/libcmd.so
	rm -f $root/lib/libcmd.so.1
	rm -f $root/lib/amd64/libcmd.so
	rm -f $root/lib/amd64/libcmd.so.1
	rm -f $root/lib/sparcv9/libcmd.so
	rm -f $root/lib/sparcv9/libcmd.so.1
	rm -f $root/lib/llib-lcmd
	rm -f $root/lib/llib-lcmd.ln
	rm -f $root/lib/amd64/llib-lcmd.ln
	rm -f $root/lib/sparcv9/llib-lcmd.ln

	# Remove audit_record_attr. Moved to /usr/lib/security
	rm -f $root/etc/security/audit_record_attr

	#
	# Remove xmemfs altogether.
	#
	rm -f $usr/include/sys/fs/xmem.h
	rm -f $usr/include/sys/fs/seg_xmem.h
	rm -f $usr/kernel/fs/xmemfs
	rm -f $usr/kernel/fs/amd64/xmemfs
	rm -rf $usr/lib/fs/xmemfs

	#
	# Remove obsolete libmacadm, liblaadm and libwladm. If this is
	# a backwards BFU, they will be extracted by cpio.
	#
	rm -f $root/lib/libmacadm.so.1
	rm -f $root/lib/liblaadm.so.1
	rm -f $root/lib/libwladm.so.1

	#
	# Remove PCI hotplug devlinks.  Their format has changed,
	# and the old devlinks will interfere with the new ones.
	#
	rm -f $root/dev/cfg/*pci*

	#
	# remove the architecture-specific sn1_brand module since it's being
	# replaced with platform-specific modules.
	#
	rm -f $root/kernel/brand/sparcv9/sn1_brand

	#
	# Remove I2O.
	#
	rm -f $root/kernel/drv/i2o_bs
	rm -f $root/kernel/drv/i2o_bs.conf
	rm -f $root/kernel/drv/i2o_scsi
	rm -f $root/kernel/drv/i2o_scsi.conf
	rm -f $root/kernel/drv/pci_to_i2o
	rm -f $root/kernel/drv/pci_to_i2o.conf
	rm -f $root/kernel/misc/i2o_msg
	rm -f $root/usr/include/sys/i2o/*
	rmdir $root/usr/include/sys/i2o/ 2>/dev/null

	#
	# Remove /usr/ccs/bin dependency files that now live in
	# /usr/share/lib/ccs
	#
	rm -f $usr/ccs/bin/gprof.callg.blurb
	rm -f $usr/ccs/bin/gprof.flat.blurb
	rm -f $usr/ccs/bin/nceucform
	rm -f $usr/ccs/bin/ncform
	rm -f $usr/ccs/bin/nrform
	rm -f $usr/ccs/bin/yaccpar

	#
	# Remove us driver header.
	#
	rm -f $usr/platform/sun4u/include/sys/us_drv.h

	#
	# Remove device private and legacy sun headers we don't need
	#
	rm -f $usr/include/sys/aflt.h
	rm -f $usr/include/sys/bmac.h
	rm -f $usr/include/sys/bw2reg.h
	rm -f $usr/include/sys/bw2var.h
	rm -f $usr/include/sys/cursor_impl.h
	rm -f $usr/include/sys/eri.h
	rm -f $usr/include/sys/eri_common.h
	rm -f $usr/include/sys/eri_mac.h
	rm -f $usr/include/sys/eri_msg.h
	rm -f $usr/include/sys/eri_phy.h
	rm -f $usr/include/sys/i82586.h
	rm -f $usr/include/sys/isdnio.h
	rm -f $usr/include/sys/mace.h
	rm -f $usr/include/sys/memfb.h
	rm -f $usr/include/sys/memreg.h

	#
	# Remove new files in order to go backward.
	#
	rm -f $root/usr/lib/rcm/modules/SUNW_vlan_rcm.so
	rm -f $root/usr/lib/rcm/modules/SUNW_aggr_rcm.so
	rm -f $root/kernel/drv/softmac
	rm -f $root/kernel/drv/sparcv9/softmac
	rm -f $root/kernel/drv/amd64/softmac

	#
	# Remove libtopo platform XML files that have been replaced by propmap
	# files.
	#
	rm -f $root/usr/platform/i86pc/lib/fm/topo/maps/Sun-Fire-*-topology.xml

	# Migrate hostid
	#
	migrate_hostid

	# End of pre-archive extraction hacks.

	if [ $diskless = no -a $zone = global ]; then
		# extract both /platform and /usr/platform bootblks
		# for compatibility with older bootblk delivery
		print "Extracting platform $rootfstype modules for boot " \
		    "block ... \c" | tee -a $EXTRACT_LOG
		do_extraction $cpiodir/$karch.root$ZFIX \
			'platform/'$karch'/lib/fs/'$rootfstype'/*' | \
			tee -a $EXTRACT_LOG
		print "Extracting usr/platform $rootfstype modules for boot " \
		    "block ... \c" | tee -a $EXTRACT_LOG
		do_extraction $cpiodir/$karch.usr$ZFIX \
			'usr/platform/'$karch'/lib/fs/'$rootfstype'/*' | \
			tee -a $EXTRACT_LOG
		case $target_isa in
		    sparc)
			if [[ "$rootfstype" = zfs ]]; then
				print "Extracting usr/sbin/installboot for " \
				    "zfs boot block installation ... \c" |
				    tee -a $EXTRACT_LOG
				do_extraction $cpiodir/generic.usr$ZFIX \
				    'usr/sbin/installboot' | \
				    tee -a $EXTRACT_LOG
				cd $usr/platform/$karch/lib/fs/zfs
				get_rootdev_list | while read physlice
				do
					print "Installing bootblk on $physlice."
                                        $usr/sbin/installboot -F zfs ./bootblk \
					    $physlice
                                done
			elif [[ "$rootslice" = /dev/rdsk/* ]]; then
				print "Installing boot block on $rootslice."
				cd $usr/platform/$karch/lib/fs/ufs
				installboot ./bootblk $rootslice
                         elif [[ "$rootslice" = /dev/md/rdsk/* ]]; then
                                print "Detected SVM root."
                                cd $usr/platform/$karch/lib/fs/ufs
                                get_rootdev_list | while read physlice
                                do 
					print "Installing bootblk on $physlice."
                                        installboot ./bootblk $physlice
                                done
			fi
			;;
		    i386)
			print "Extracting grub for boot " \
			    "block ... \c" | tee -a $EXTRACT_LOG
			do_extraction $cpiodir/$karch.boot$ZFIX  | \
				tee -a $EXTRACT_LOG
			$rootprefix/boot/solaris/bin/update_grub -R $root
			;;
		    *)
			;;	# unknown ISA
		esac
	fi

	if [ $diskless = yes ]; then
		node=${root##*/}
		archlist=""
		for arch in $allarchs
		do
			egrep -s '/export/exec/.*'$arch'/usr/kvm' \
				$root/etc/vfstab ||
				test -d $root/platform/$arch &&
				archlist="$archlist $arch"
		done
		if [ -z "$old_style_archives" ]; then
			extract_archives lib generic
			extract_archives sbin generic
			extract_archives kernel generic
		fi
		extract_archives root generic $archlist
		if [ $target_isa = i386 ]; then
			extract_boot_archives boot $archlist
                elif [ $newboot_sparc = yes ]; then
                        extract_boot_archives boot generic
		fi
	else
		export PATH=/tmp/bfubin
		node=`uname -n`
		if [ $zone = global ]; then
			extract_archives usr generic $usrarchs
			if [ -z "$old_style_archives" ]; then
				extract_archives lib generic
				extract_archives sbin generic
				extract_archives kernel generic
			fi
			extract_archives root generic $rootarchs
			if [ $target_isa = i386 ]; then
		        	#
		        	#  The assumption here is that if boot
				#  archives exist at all, they only exist
				#  for architectures where we also have
				#  .root archives.
				#
				extract_boot_archives boot $rootarchs
			elif [ $newboot_sparc = yes ]; then
				extract_boot_archives boot generic
			fi
		else
			dir_is_inherited usr ||
			    extract_archives usr generic $usrarchs
			dir_is_inherited lib ||
			    extract_archives lib generic
			dir_is_inherited sbin ||
			    extract_archives sbin generic
			dir_is_inherited platform &&
			    extract_archives root generic ||
			    extract_archives root generic $rootarchs
		fi
	fi

	touch reconfigure

	#
	# UltraSparc III platforms have aes module in platform directory
	#
	if [ ! -f $root/platform/$plat/kernel/crypto/sparcv9/aes ]; then
		rm -f $root/platform/sun4u-us3/kernel/crypto/sparcv9/aes
		rm -f $root/platform/sun4u-us3/kernel/crypto/sparcv9/aes256
	fi

	#
	# remove platform specific rsa module obsoleted by the bignum module
	#

	rm -f $root/platform/sun4u/kernel/crypto/sparcv9/rsa

	if [ $zone = global ]; then
		print "\nRemoving duplicate kernel binaries ..."
		#
		# First, find all regular files underneath the */kernel
		# directories we extracted, and mark them as older or newer
		# than our reference file -- if newer, they were extracted
		# during the bfu.
		#
		# We then split out the pre-/kernel part from the post-/kernel
		# part, sort by post-/kernel part and age (new first), and
		# delete old files which have new counterparts.
		#
		dirs="$rootprefix/kernel $usr/kernel"
		for plat in $archlist $rootarchs $usrarchs; do
			dir=$rootprefix/platform/$plat/kernel
			[[ -d $dir ]] && dirs="$dirs $dir"
		done

		age=new
		ls -ct $time_ref `find $dirs -type f 2>/dev/null` | uniq |
		    while read f; do
			if [[ $f = $time_ref ]] then
				age=old
			else
				echo $age $f
			fi
		done |
		    sed 's@\(.*/kernel\)/@\1 @' | sort -k 3 -k 1 | nawk '
			/^new/ { lastname = $3 }
			/^old/ { if (lastname == $3) { print $2 "/" $3 } }
		    ' | while read x; do
			echo "rm $x"
			rm $x
		done
	fi

	echo

	#
	# Change permissions of public IKE certificates and CRLs
	# that may have been incorrectly created as private
	# PKCS#11 hints files must be left root-only readable.
	# Make sure this files starts with "30 82"
	#
	for file in `ls $rootprefix/etc/inet/ike/crls/* \
	    $rootprefix/etc/inet/ike/publickeys/* 2>/dev/null`; do
		if /bin/od -tx1 -N3 < $file | grep '30 82' >/dev/null 2>&1
		then
			chmod 644 $file
		fi
	done

	#
	# Remove EOF SUNWcry/SUNWcryr
	remove_eof_SUNWcry

	# Add uCF's metaslot feature
	if [ -f $rootprefix/etc/crypto/pkcs11.conf ] ; then
		enable_crypto_metaslot
	fi

	# Cleanup old Kerberos mechanisms
	cleanup_kerberos_mechanisms

	# Cleanup old RBAC profiles
	rbac_cleanup

	# Obsolete GLDv3 /etc/datalink.conf file".
	if [[ $zone = global && -f $rootprefix/etc/datalink.conf ]]; then
		rm -f $rootprefix/etc/datalink.conf
	fi

	#
	# Force xVM privilege fixups to occur on next boot.
	#
	rm -f $rootprefix/var/lib/xend/.xvmuser
	
	print "\nRestoring configuration files.\n"

	cd $root
	rm -rf bfu.ancestor
	test -d bfu.parent && mv bfu.parent bfu.ancestor
	mkdir bfu.parent
	print "Restoring configuration files ... \c" >> $EXTRACT_LOG
	filelist $zone | cpio -pdmu bfu.parent 2>>$EXTRACT_LOG || \
	    extraction_error "restoring configuration files"
	if [ $multi_or_direct = no ]; then
		if [ $have_realmode = yes ]; then
			if [ -d bfu.realmode ]; then
				( cd bfu.realmode ; realmode_filelist | \
				    cpio -pdmu ../bfu.ancestor 2>/dev/null )
				rm -rf bfu.realmode
			fi
			mkdir bfu.realmode
			( cd bfu.parent ; realmode_filelist | \
				cpio -pdmu ../bfu.realmode 2>/dev/null )
		else
			for file in $realmode_files
			do
				rm -rf bfu.parent/$file
			done
		fi
	fi

	cd bfu.child
	for file in `filelist $zone`
	do
		# parent: freshly-BFUed version
		# child: pre-BFU version
		# ancestor: installed from archives the last time you BFUed
		# actual: in the root filesystem at this moment (same as parent)

		parent=$rootprefix/bfu.parent/$file
		child=$rootprefix/bfu.child/$file
		ancestor=$rootprefix/bfu.ancestor/$file
		conflicts=$rootprefix/bfu.conflicts/$file
		actual=$rootprefix/$file

		# if a superfluous-to-local-zones file was blown away, skip it
		[ -f $actual ] || continue

		# if there's been no change by the BFU, skip it
		cmp -s $child $actual && continue

		# if the file was not installed by the BFU, skip it
		[  -f $parent ] || continue

		# if this is a file which should never be updated by BFU,
		# preserve the original (child) version
		if (echo $preserve_files | grep $file >/dev/null 2>&1)
		then
			print "    preserve: $file"
			cp -p $child $actual
			continue
		fi

		# if the file was accepted from the parent on the last BFU,
		# then accept it again this time without argument.  Or, if
		# this is the first bfu after an standard Solaris install
		# or upgrade, compare the file to one installed from packages.
		# If it hasn't been modified since installation, accept
		# the file from the parent.
		if [ -f $ancestor ] ; then
			if cmp -s $child $ancestor; then
				print "      update: $file"
				continue
			fi
		elif [ "$firstbfu" = "yes" ] ; then
			installedsum=$(grep "^/$file " \
			    $rootprefix/var/sadm/install/contents |
			    awk '{ print $8 }')
			if [ -n "$installedsum" ] ; then
				actualsum=`sum $child | sed 's/ .*//'`
				if [ "$installedsum" -eq "$actualsum" ] ; then
					print "      update: $file"
					continue
				fi
			fi
		fi

		# if the BFU'ed file is the same as the beginning of the
		# pre-BFUed file, assume the user has added lines to the
		# end, and restore the pre-BFUed version
		if (cmp $child $parent 2>&1) | egrep -s 'EOF on '$parent; then
			print "     restore: $file"
			cp -p $child $actual
			continue
		fi

		# if the new version is the same as it was the last time
		# BFU was run, but still different than the pre-BFU version,
		# this is an "old" conflict; otherwise, it's a "NEW"
		# conflict.  Old conflicts can usually be safely ignored.
		if cmp -s $parent $ancestor; then
			print "old \c"
		else
			print "NEW \c"
			print $file >>$rootprefix/bfu.conflicts/NEW
		fi

		print "conflict: $file"
		(cd $root; print $file | cpio -pdmu bfu.conflicts 2>/dev/null)

		# for all conflicts, restore the pre-BFU version and let
		# the user decide what to do.
		cp -p $child $actual
	done

	#
	# Add build_class_script_files to NEW
	# Don't add the file to bfu.conflict since the private script from
	# the pkg takes care of the update.
	#
	for bldscript in $build_class_script_files; do
		print "NEW \c"
		print $bldscript >>$rootprefix/bfu.conflicts/NEW
		print "conflict: $bldscript"
	done

	if [ $zone = global ]; then
		#
		# correct permissions using /etc/minor_perm from the parent and
		# child, prefer parent.
		#
		mperm=$rootprefix/etc/minor_perm
		pmperm=$rootprefix/bfu.parent/etc/minor_perm
		if [ -f $pmperm ]
		then
			mperm="$pmperm $mperm"
		fi

		#
		# Devices with changed permissions should be added here much
		# like in i.minorperm.  The "ssm" devices are special in that
		# they have no /dev links associated with them.
		#
		while read minor dev
		do (
			set -- `fgrep -h "$minor" $mperm` "";
			if [ ! -z "$2" ]
			then
				chmod $2 $rootprefix/dev/$dev 2>/dev/null
				chown $3:$4 $rootprefix/dev/$dev 2>/dev/null
			fi
		) done <<-EOF
			ssm:*			../devices/ssm*:*
			cpc:shared		../devices/pseudo/cpc*
			icmp:icmp		icmp
			icmp6:icmp6		icmp6
			ip:ip			ip
			ip6:ip6			ip6
			rts:rts			rts
			keysock:keysock		keysock
			ipsecah:ipsecah		ipsecah
			ipsecesp:ipsecesp	ipsecesp
			spdsock:spdsock		spdsock
			sad:admin		sad/admin
			fssnap:ctl		fssnapctl
			fssnap:*		fssnap/*
			clone:ce		ce
			clone:eri		eri
			clone:ge		ge
			clone:hme		hme
			clone:qfe		qfe
			clone:bge		bge
			bge:*			bge*
			clone:dmfe		dmfe
			dmfe:*			dmfe*
			clone:pcelx		pcelx
			pcelx:*			pcelx*
			clone:dnet		dnet
			dnet:*			dnet*
			clone:elxl		elxl
			elxl:*			elxl*
			clone:iprb		iprb
			iprb:*			iprb*
			clone:spwr		spwr
			spwr:*			spwr*
			clone:afe		afe
			afe:*			afe*
			clone:mxfe		mxfe
			mxfe:*			mxfe*
			clone:rtls		rtls
			rtls:*			rtls*
			nsmb:*			nsmb*
		EOF

		if [ $target_isa = i386 ] && [[ $rootfstype = zfs || \
		    $rootslice = /dev/rdsk/* || \
		    $rootslice = /dev/md/rdsk/* ]]; then
			check_boot_env
		fi

		#
		# update boot archives for new boot sparc
                #
                if [ $newboot_sparc = yes ] && \
		    [[ $rootfstype = zfs || $rootslice = /dev/rdsk/* ||
			$rootslice = /dev/md/rdsk/* ]]; then
				build_boot_archive
                                install_sparc_failsafe
		fi

		# Check for damage due to CR 6379341.  This was actually fixed
		# back in snv_24, but users BFUing from an S10 build up to
		# Nevada can still encounter it.
		rzi=$root/etc/zones/index
		if [ -f $rzi ]; then
			# Look for duplicated UUIDs.  If there are any, then
			# just wipe them out.
			if nawk -F: '
				/^\#/ || NF != 4 { print $0; next; }
				{
					if (flags[$4])
						sub(/:[-0-9a-z]*$/,":");
					print $0;
					flags[$4]=1;
				}
			' < $rzi > ${rzi}.bfu.$$; then
				if cmp -s $rzi ${rzi}.bfu.$$; then
					rm -f ${rzi}.bfu.$$
				else
					chown root:sys ${rzi}.bfu.$$
					chmod 644 ${rzi}.bfu.$$
					mv ${rzi}.bfu.$$ $rzi
				fi
			else
				rm -f ${rzi}.bfu.$$
			fi
		fi

		if [[ $dlmgmtd_status = new ]]; then
			# Upgrade existing /etc/aggregation.conf (or
			# /etc/dladm/aggregation.conf) and linkprop.conf
			upgrade_aggr_and_linkprop
		else
			# Move existing /etc/aggregation.conf entries to
			# /etc/dladm/aggregation.conf; or, if bfu'ing
			# backwards, move aggregation.conf back to /etc
			aggr_old=$rootprefix/etc/aggregation.conf
			aggr_new=$rootprefix/etc/dladm/aggregation.conf
			if [[ $new_dladm = yes ]]; then
				if [[ -f $aggr_old ]]; then
					# use cat instead of cp/mv to keep
					# owner+group of dest
					cat $aggr_old > $aggr_new
					rm -f $aggr_old
				fi
			elif [[ -f $aggr_new ]]; then
				cp $aggr_new $aggr_old
				chgrp sys $aggr_old
				rm -rf $rootprefix/etc/dladm
			fi
		fi

		# The global zone needs to have its /dev/dld symlink created
		# during install so that processes can access it early in boot
		# before devfsadm is run.
		if [ ! -L $rootprefix/dev/dld ]; then
			ln -s ../devices/pseudo/dld@0:ctl $rootprefix/dev/dld
		fi
	fi

	# Fix up audit permissions
	fix_up_audit

	print "\nFor each file in conflict, your version has been restored."
	print "The new versions are under $rootprefix/bfu.conflicts."
	print "\nMAKE SURE YOU RESOLVE ALL CONFLICTS BEFORE REBOOTING.\n"
	if [ $multi_or_direct = yes ]; then
		print "To install resolved changes required for reboot in the boot"
		print "archive, invoke 'bootadm update-archive${cr_args}'\n"
	fi

	if [ $zone != global ]; then
		print "Resolve conflicts in the global zone first.  Many of"
		print "the conflicts in non-global zones can be resolved by"
		print "copying the corresponding file from the global zone.\n"
	else
		fixup_mpxio

		#
		# If we're bfuing backward across PSARC/2006/248, then
		# revert the /etc/aggregation.conf to its old format.
		#
		if [ -f $rootprefix/etc/aggregation.conf -a \
		    ! -d $rootprefix/kernel/mac -a \
		    $from_new_aggrconf = 1 ]; then
			revert_aggregation_conf
		fi
	fi

	cd $root

	smf_apply_conf

	update_policy_conf

	tx_check_bkbfu

	update_aac_conf

	if [ $target_isa = i386 ]; then
	    update_mptconf_i386

	    update_etc_mach_i386
	fi

	if [ $target_isa = i386 ]; then
	    update_drvclass_i386
	fi

	if [ $zone != global ]; then
		rm -rf $global_zone_only_files $superfluous_nonglobal_zone_files
	fi

	print "bfu'ed from $cpiodir on `date +%Y-%m-%d`" >>etc/motd
	tail +`nawk '/bfu.ed from/ { x=NR }; END { print x+1 }' \
		etc/motd.old` etc/motd.old >> etc/motd

	#
	# Hacks to work around minor annoyances and make life more pleasant.
	# Part 2 of 2: post-archive-extraction stuff
	#

	rm -f var/statmon/state		# to prevent lockd/statd hangs
	for f in etc/auto_*		# to make autofs happy
	do
		file $f | grep executable >/dev/null || chmod -x $f
	done

	epilogue=$rootprefix/bfu.epilogue
	if [ -f $epilogue ]; then
		print "Executing $epilogue"
		$epilogue || print "WARNING: $epilogue failed with code $?"
	fi

	((seconds = SECONDS))
	((min = seconds / 60))
	((sec = seconds % 60))

	if [ $zone = global ]; then
		target=$node
	else
		target=$zone
	fi
	printf "Upgrade of $target took ${min}:%02d.\n" $sec

	#
	# Do logging in the background so that if the automounter is gone,
	# bfu doesn't wedge at this point.
	#
	log=$GATE/public/bfu.log
	(test -w $log && printf \
		"`date +%Y'%'m%d` $node `uname -rv` $karch $cpiodir ${min}:%02d\n" \
		$sec >>$log) &
}

#
# make sure the time reference is older than anything extracted
#
test $time_ref_seconds -eq $SECONDS && sleep 1

test $diskless = yes && extract_archives usr generic $allarchs

for root in $rootlist
do
	mondo_loop $root global
	lastroot=$root
done

if [ -s "$bfu_zone_list" ]; then
	cat "$bfu_zone_list" | while read zone zonepath; do
		print "\nNow for zone $zone..."
		mondo_loop $zonepath/root $zone
	done

	#
	# Normally we would clean up $bfu_zone_list but instead we leave it
	# behind for ACR to locate and use inside the BFU alternate reality.
	#
fi

print "Turning off delayed i/o and syncing filesystems ..."
sync
fastfs -s $rootlist $usr
fastfs $rootlist $usr
sync
lockfs -f $rootlist $usr

egrep -s "^error " $EXTRACT_LOG
if [ $? -eq 0 ]; then
	print "\nWARNING: archive extraction errors occurred.\n"
	print "See $EXTRACT_LOG for details.\n"
fi

lastrootprefix=${lastroot%/}

if [ -t 0 -a -t 1 -a -t 2 ]; then
	print "\nEntering post-bfu protected environment (shell: ksh)."
	print "Edit configuration files as necessary, then reboot.\n"
	cd $lastrootprefix/bfu.conflicts
	PS1='bfu# ' ksh -ip
fi

print "Exiting post-bfu protected environment.  To reenter, type:"
print LD_NOAUXFLTR=1 LD_LIBRARY_PATH=/tmp/bfulib $ldlib64 PATH=/tmp/bfubin \
    /tmp/bfubin/ksh

exit 0
