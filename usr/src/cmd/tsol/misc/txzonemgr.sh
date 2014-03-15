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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2014 Garrett D'Amore
#
#

# This script provides a simple GUI for managing labeled zones.
# It provides contextual menus which provide appropriate choices.
# It must be run in the global zone as root.

# These arguments are accepted, and will result in non-interactive
# (text-only) mode:
#
#	txzonemgr [-c | -d[f]]
#
#	-c	create default zones
#	-d	destroy all zones; prompts for confirmation unless
#		the -f flag is also specified
#	-f	force
#

# DISP - use GUI (otherwise use non-interactive mode)
DISP=1
# CREATEDEF - make default zones (non-interactive)
CREATEDEF=0
# DESTROYZONES - tear down all zones (non-interactive)
DESTROYZONES=0
# FORCE - force
FORCE=0

NSCD_PER_LABEL=0
NSCD_INDICATOR=/var/tsol/doors/nscd_per_label
if [ -f $NSCD_INDICATOR ] ; then
	NSCD_PER_LABEL=1
fi

myname=$(basename $0)

TXTMP=/tmp/txzonemgr
TNRHTP=/etc/security/tsol/tnrhtp
TNRHDB=/etc/security/tsol/tnrhdb
TNZONECFG=/etc/security/tsol/tnzonecfg
PUBZONE=public
INTZONE=internal

PATH=/usr/bin:/usr/sbin:/usr/lib export PATH
title="Labeled Zone Manager 2.1"

msg_defzones=$(gettext "Create default zones using default settings?")
msg_confirmkill=$(gettext "OK to destroy all zones?")
msg_continue=$(gettext "(exit to resume $(basename $0) when ready)")
msg_getlabel=$(gettext "Select a label for the")
msg_getremote=$(gettext "Select a remote host or network from the list below:")
msg_getnet=$(gettext "Select a network configuration for the")
msg_getzone=$(gettext "Select a zone from the list below:
(select global for zone creation and shared settings)")
msg_getcmd=$(gettext "Select a command from the list below:")
msg_inuse=$(gettext "That label is already assigned\nto the")
msg_getmin=$(gettext "Select the minimum network label for the")
msg_getmax=$(gettext "Select the maximum network label for the")
msg_badip=$(gettext " is not a valid IP address")


process_options()
{
	typeset opt optlist

	optlist='cdf'

	while getopts ":$optlist" opt
	do
		case $opt in
		c)	CREATEDEF=1
			DISP=0
			;;
		d)	DESTROYZONES=1
			DISP=0
			;;
		f)	FORCE=1
			;;
		*)	gettext "invalid option -$OPTARG\n"
			usage
			return 2
			;;
		esac
	done

	if [ $CREATEDEF -eq 1 -a $DESTROYZONES -eq 1 ] ; then
		gettext "cannot combine options -c and -d\n"
		usage
		return 2
	fi
	if [ $CREATEDEF -eq 1 -a $FORCE -eq 1 ] ; then
		gettext "option -f not allowed with -c\n"
		usage
		return 2
	fi
	if [ $FORCE -eq 1 -a $CREATEDEF -eq 0 -a $DESTROYZONES -eq 0 ] ; then
		gettext "option -f specified without any other options\n"
		usage
		return 2
	fi

	shift $((OPTIND - 1))
	if [ "x$1" != "x" ] ; then
		usage
		return 2
	fi

	return 0
}

usage() {
	gettext "usage: $myname [-c | -d[f]]\n"
}

consoleCheck() {
	if [ $zonename != global ] ; then
		zconsole=$(pgrep -f "zlogin -C $zonename")
		if [ $? != 0 ] ; then
			console="Zone Console...\n"
		fi
	fi
}

labelCheck() {
	hexlabel=$(grep "^$zonename:" $TNZONECFG|cut -d : -f2);
	if [[ $hexlabel ]] ; then
		label=
		if [ $zonename = global ] ; then
			template="admin_low"
			addcipsohost="Add Multilevel Access to Remote Host...\n"
			removecipsohost="Remove Multilevel Access to Remote Host...\n"
			setmlps="Configure Multilevel Ports...\n"
		else
			template=${zonename}_unlab
			addcipsohost=
			removecipsohost=
			setmlps=

			net=$(zonecfg -z $zonename info net)
			if [[ -n $net ]] ; then
				setmlps="Configure Multilevel Ports...\n"
			elif [ $zonestate = configured ] ; then
				addnet="Configure Network Interfaces...\n"
			fi
		fi
		addremotehost="Add Single-level Access to Remote Host...\n"
		remotes=$(grep -v "^#" $TNRHDB|grep $template)
		if [ $? = 0 ] ; then
			removeremotehost="Remove Single-level Access to Remote Host...\n"
		else
			removeremotehost=
		fi
	else
		label="Select Label...\n"
		addremotehost=
		removeremotehost=
		addcipsohost=
		removecipsohost=
		setmlps=
	fi
}

cloneCheck() {
	set -A zonelist
	integer clone_cnt=0
	for p in $(zoneadm list -ip) ; do
		z=$(echo "$p"|cut -d : -f2)
		s=$(echo "$p"|cut -d : -f3)
		if [ $z = $zonename ] ; then
			continue
		elif [ $s = "installed" ] ; then
			zonelist[clone_cnt]=$z
			clone_cnt+=1
		fi
	done
	if [ $clone_cnt -gt 0 ] ; then
		clone="Clone...\n"; \
	fi
}

relabelCheck() {
	macstate=$(zonecfg -z $zonename info|grep win_mac_write)
	if [[ -n $macstate ]] ; then
		permitrelabel="Deny Relabeling\n"
	else
		permitrelabel="Permit Relabeling\n"
	fi
}

autobootCheck() {
	bootmode=$(zonecfg -z $zonename info autoboot)
	if [[ $bootmode == 'autoboot: true' ]] ; then
		autoboot="Set Manual Booting\n"
	else
		autoboot="Set Automatic Booting\n"
	fi
}

newZone() { 
		if [[ ! -n $zonename ]] ; then
			zonename=$(zenity --entry \
			    --title="$title" \
			    --width=330 \
			    --entry-text="" \
			    --text="Enter Zone Name: ")

			if [[ ! -n $zonename ]] ; then
				zonename=global
				return
			fi
		fi
		zonecfg -z $zonename "create -t SUNWtsoldef;\
		     set zonepath=/zone/$zonename"
}

removeZoneBEs() {
	delopt=$*

	zfs list -H $ZDSET/$zonename 1>/dev/null 2>&1
	if [ $? = 0 ] ; then
		for zbe in $(zfs list -rHo name $ZDSET/$zonename|grep ROOT/zbe) ; do
			zfs destroy $delopt $zbe
		done
	fi
}

updateTemplate () {
	if [ $hostType = cipso ] ; then
		template=${zonename}_cipso
		deflabel=
	else
		template=${zonename}_unlab
		deflabel="def_label=${hexlabel};"
	fi

	tnzone=$(grep "^${template}:" $TNRHTP 2>/dev/null)
	if [ $? -eq 0 ] ; then
		sed -e "/^${template}/d" $TNRHTP > $TXTMP/tnrhtp.$$ 2>/dev/null
		mv $TXTMP/tnrhtp.$$ $TNRHTP
	fi
	print "${template}:host_type=${hostType};doi=1;min_sl=${minlabel};max_sl=${maxlabel};$deflabel" >> $TNRHTP
	tnctl -t $template
}
		
setTNdata () {
	tnzline="$zonename:${hexlabel}:0::"
	grep "^$tnzline" $TNZONECFG 1>/dev/null 2>&1
	if [ $? -eq 1 ] ; then
		print "$tnzline" >> $TNZONECFG
	fi

	#
	# Add matching entries in tnrhtp if necessary
	#
	minlabel=admin_low
	maxlabel=admin_high
	hostType=cipso
	updateTemplate

	hostType=unlabeled
	updateTemplate
}

selectLabel() {
	hexlabel=$(tgnome-selectlabel \
		--title="$title" \
		--text="$msg_getlabel $zonename zone:" \
		--min="${DEFAULTLABEL}"  \
		--default="${DEFAULTLABEL}"  \
		--max=$(chk_encodings -X) \
		--accredcheck=yes \
		--mode=sensitivity \
		--format=internal)
	if [ $? = 0 ] ; then
		x=$(grep -i :{$hexlabel}: $TNZONECFG)
		if [ $? = 0 ] ; then
			z=$(print $x|cut -d : -f1)
			x=$(zenity --error \
			    --title="$title" \
			    --text="$msg_inuse $z zone.")
		else
			setTNdata
		fi
	fi	
}

getLabelRange() {
	deflabel=$(hextoalabel $hexlabel)
	minlabel=$(tgnome-selectlabel \
		--title="$title" \
		--text="$msg_getmin $zonename zone:" \
		--min="${DEFAULTLABEL}"  \
		--max="$deflabel" \
		--default="$hexlabel" \
		--accredcheck=no \
		--mode=sensitivity \
		--format=internal)
	[ $? != 0 ] && return
	
	maxlabel=$(tgnome-selectlabel \
		--title="$title" \
		--text="$msg_getmax $zonename zone:" \
		--min="$deflabel"  \
		--max=$(chk_encodings -X) \
		--default="$hexlabel" \
		--accredcheck=no \
		--mode=sensitivity \
		--format=internal)
	[ $? != 0 ] && return

	hostType=cipso
	updateTemplate
}


encryptionValues() {
	echo $(zfs get 2>&1 | grep encryption | sed -e s/^.*YES// -e s/\|//g)
}

getPassphrase() {
	pass1=$(zenity --entry --title="$title" --text="Enter passphrase:" \
	    --width=330 --hide-text)
	pass2=$(zenity --entry --title="$title" --text="Re-enter passphrase:" \
	    --width=330 --hide-text)
	if [[ "$pass1" != "$pass2" ]]; then
		zenity --error --title="$title" \
			--text="Passphrases do not match"
		return ""
	fi
	file=$(mktemp)
	echo "$pass1" > $file
	echo "$file"
}

createZDSET() {
	options=$1
	pool=${2%%/*}

	# First check if ZFS encrytption support is available
	pversion=$(zpool list -H -o version $pool)
	cversion=$(zpool upgrade -v | grep Crypto | awk '{ print $1 }')
	if (( cversion == 0 || pversion < cversion )); then
		zfs create $options $ZDSET
		return
	fi

	encryption=$(zenity --list --title="$title" --height=320 \
		--text="Select cipher for encryption of all labels:" \
		--column="encryption" $(encryptionValues))

	if [[ $? != 0 || $encryption == "off" ]]; then
		zfs create $options $ZDSET
		return
	fi

	format=$(zenity --list --title="$title" \
		--text "Select encryption key source:" \
		--column="Key format and location" \
		"Passphrase" "Generate Key in file")
	[ $? != 0 ] && exit 

	if [[ $format == "Passphrase" ]]; then
		file=$(getPassphrase)
		if [[ $file == "" ]]; then
			exit
		fi
		keysource="passphrase,file://$file"
		removefile=1;
	elif [[ $format == "Generate Key in file" ]]; then
		file=$(zenity --file-selection \
			--title="$title: Location of key file" \
			--save --confirm-overwrite)
		[ $? != 0 ] && exit 
		if [[ $encryption == "on" ]]; then
			keylen=128
		else
			t=${encryption#aes-} && keylen=${t%%-*}
		fi
		pktool genkey keystore=file keytype=aes \
		    keylen=$keylen outkey=$file
		keysource="raw,file:///$file"
	fi

	options="$options -o encryption=$encryption -o keysource=$keysource"
	zfs create $options $ZDSET
	if (( removefile == 1 )); then
		zfs set keysource=passphrase,prompt $ZDSET
		rm $file
	fi
}


initialize() {
	zonepath=$(zoneadm -z $zonename list -p|cut -d : -f4)
	ZONE_ETC_DIR=$zonepath/root/etc
	SYSIDCFG=${ZONE_ETC_DIR}/sysidcfg

	if [ -f /var/ldap/ldap_client_file ] ; then
		ldapaddress=$(ldapclient list | \
		    grep "^NS_LDAP_SERVERS" | cut -d " " -f2)
		print "name_service=LDAP {" > ${SYSIDCFG}
		domain=$(domainname)
		print "domain_name=$domain" >> ${SYSIDCFG}
		profName=$(ldapclient list | \
		    grep "^NS_LDAP_PROFILE" | cut -d " " -f2)
		proxyPwd=$(ldapclient list | \
		    grep "^NS_LDAP_BINDPASSWD" | cut -d " " -f2)
		proxyDN=$(ldapclient list | \
		    grep "^NS_LDAP_BINDDN" | cut -d " " -f 2)
		if [ "$proxyDN" ] ; then
			print "proxy_dn=\"$proxyDN\"" >> ${SYSIDCFG}
			print "proxy_password=\"$proxyPwd\"" >> ${SYSIDCFG}
		fi
		print "profile=$profName" >> ${SYSIDCFG}
		print "profile_server=$ldapaddress }" >> ${SYSIDCFG}
		cp /etc/nsswitch.conf $ZONE_ETC_DIR/nsswitch.ldap
	else
		print "name_service=NONE" > ${SYSIDCFG}
		fi
	print "security_policy=NONE" >> ${SYSIDCFG}
	locale=$(locale|grep LANG | cut -d "=" -f2)
	if [[ -z $locale ]] ; then
		locale="C"
	fi
	print "system_locale=$locale" >> ${SYSIDCFG}
	timezone=$(grep "^TZ" /etc/default/init|cut -d "=" -f2)
	print "timezone=$timezone" >> ${SYSIDCFG}
	print "terminal=vt100" >> ${SYSIDCFG}
	rootpwd=$(grep "^root:" /etc/shadow|cut -d : -f2)
 
#	There are two problems with setting the root password:
#		The zone's shadow file may be read-only
#		The password contains unparsable characters
#	so the following line is commented out until this is resolved.

	#print "root_password=$rootpwd" >> ${SYSIDCFG}
	print "nfs4_domain=dynamic" >> ${SYSIDCFG}
	print "network_interface=PRIMARY {" >> ${SYSIDCFG}

	net=$(zonecfg -z $zonename info net)
	ipType=$(zonecfg -z $zonename info ip-type|cut -d" " -f2)
	if [ $ipType = exclusive ] ; then
		hostname=$(zenity --entry \
		    --title="$title" \
		    --width=330 \
		    --text="${zonename}0: Enter Hostname or dhcp: ")
		[ $? != 0 ] && return

		if [ $hostname = dhcp ] ; then
			print "dhcp" >> ${SYSIDCFG}
		else
			print "hostname=$hostname" >> ${SYSIDCFG}
			ipaddr=$(getent hosts $hostname|cut -f1)
			if [ $? != 0 ] ; then
				ipaddr=$(zenity --entry \
				    --title="$title" \
				    --text="$nic: Enter IP address: " \
				    --entry-text a.b.c.d)
				[ $? != 0 ] && return
				
				validateIPaddr
				if [[ -z $ipaddr ]] ; then
					return
				fi
			fi
			print "ip_address=$ipaddr" >> ${SYSIDCFG}
			getNetmask
			print "netmask=$nm" >> ${SYSIDCFG}
			print "default_route=none" >> ${SYSIDCFG}
			template=${zonename}_cipso
			cidr=32
			updateTnrhdb
		fi
	elif [[ -n $net ]] ; then
		hostname=$(hostname)
		hostname=$(zenity --entry \
		    --title="$title" \
		    --width=330 \
		    --text="Enter Hostname: " \
		    --entry-text $hostname)
		[ $? != 0 ] && return
		
		print "hostname=$hostname" >> ${SYSIDCFG}
		ipaddr=$(getent hosts $hostname|cut -f1)
		if [ $? = 0 ] ; then
			print "ip_address=$ipaddr" >> ${SYSIDCFG}
		fi
	else
		getAllZoneNICs
		for i in ${aznics[*]} ; do
			ipaddr=$(ifconfig $i|grep inet|cut -d " " -f2)
		done
		print "hostname=$(hostname)" >> ${SYSIDCFG}
		print "ip_address=$ipaddr" >> ${SYSIDCFG}
	fi
		
	print "protocol_ipv6=no }" >> ${SYSIDCFG}
	cp /etc/default/nfs ${ZONE_ETC_DIR}/default/nfs
	touch ${ZONE_ETC_DIR}/.NFS4inst_state.domain
}

clone() {
	image=$1
	if [[ -z $image ]] ; then
		msg_clone=$(gettext "Clone the $zonename zone using a
snapshot of one of the following halted zones:")
		image=$(zenity --list \
		    --title="$title" \
		    --text="$msg_clone" \
		    --height=300 \
		    --width=330 \
		    --column="Installed Zones" ${zonelist[*]})
	fi

	if [[ -n $image ]] ; then
		removeZoneBEs
		zoneadm -z $zonename clone $image

		if [ $NSCD_PER_LABEL = 0 ] ; then
			sharePasswd $zonename
		else
			unsharePasswd $zonename
		fi

		ipType=$(zonecfg -z $zonename info ip-type|cut -d" " -f2)
		if [ $ipType = exclusive ] ; then
			zoneadm -z $zonename ready
			zonepath=$(zoneadm -z $zonename list -p|cut -d : -f4)
			sys-unconfig -R $zonepath/root 2>/dev/null
			initialize
			zoneadm -z $zonename halt
		fi
	fi
}

install() {
	removeZoneBEs
	if [ $DISP -eq 0 ] ; then
		gettext "installing zone $zonename ...\n"
		zoneadm -z $zonename install
	else
		# sleep is needed here to avoid occasional timing
		# problem with gnome-terminal display...
		sleep 2
		gnome-terminal \
		    --title="$title: Installing $zonename zone" \
		    --command "zoneadm -z $zonename install" \
		    --disable-factory \
		    --hide-menubar
	fi

	zonestate=$(zoneadm -z $zonename list -p | cut -d : -f 3)
	if [ $zonestate != installed ] ; then
		gettext "error installing zone $zonename.\n"
		return 1
	fi

	if [ $NSCD_PER_LABEL = 0 ] ; then
		sharePasswd $zonename
	else
		unsharePasswd $zonename
	fi

	zoneadm -z $zonename ready
	zonestate=$(zoneadm -z $zonename list -p | cut -d : -f 3)
	if [ $zonestate != ready ] ; then
		gettext "error making zone $zonename ready.\n"
		return 1
	fi

	initialize
	zoneadm -z $zonename halt
}

delete() {
	delopt=$*

	# if there is an entry for this zone in tnzonecfg, remove it
	# before deleting the zone.

	tnzone=$(grep "^$zonename:" $TNZONECFG 2>/dev/null)
	if [ -n "${tnzone}" ] ; then
		sed -e "/^$zonename:/d" $TNZONECFG > \
		    $TXTMP/tnzonefg.$$ 2>/dev/null
		mv $TXTMP/tnzonefg.$$ $TNZONECFG
	fi

	for tnzone in $(grep ":${zonename}_unlab" $TNRHDB 2>/dev/null) ; do
		tnctl -dh "$tnzone"
		sed -e "/:${zonename}_unlab/d" $TNRHDB > \
		    $TXTMP/tnrhdb.$$ 2>/dev/null
		mv $TXTMP/tnrhdb.$$ $TNRHDB
	done

	for tnzone in $(grep "^${zonename}_unlab:" $TNRHTP 2>/dev/null) ; do
		tnctl -dt ${zonename}_unlab
		sed -e "/^${zonename}_unlab:/d" $TNRHTP > \
		    $TXTMP/tnrhtp.$$ 2>/dev/null
		mv $TXTMP/tnrhtp.$$ $TNRHTP
	done

	for tnzone in $(grep ":${zonename}_cipso" $TNRHDB 2>/dev/null) ; do
		tnctl -dh "$tnzone"
		sed -e "/:${zonename}_cipso/d" $TNRHDB > \
		    $TXTMP/tnrhdb.$$ 2>/dev/null
		mv $TXTMP/tnrhdb.$$ $TNRHDB
	done

	for tnzone in $(grep "^${zonename}_cipso:" $TNRHTP 2>/dev/null) ; do
		tnctl -dt ${zonename}_cipso
		sed -e "/^${zonename}_cipso:/d" $TNRHTP > \
		    $TXTMP/tnrhtp.$$ 2>/dev/null
		mv $TXTMP/tnrhtp.$$ $TNRHTP
	done

	zonecfg -z $zonename delete -F

	removeZoneBEs $delopt
	for snap in $(zfs list -Ho name -t snapshot|grep "\@${zonename}_snap") ; do
		zfs destroy -R $snap
	done
}

validateIPaddr () {
	OLDIFS=$IFS
	IFS=.
	integer octet_cnt=0
	integer dummy
	set -A octets $ipaddr
	IFS=$OLDIFS
	if [ ${#octets[*]} == 4 ] ; then
		while (( octet_cnt < ${#octets[*]} )); do
			dummy=${octets[octet_cnt]}
			if [ $dummy = ${octets[octet_cnt]} ] ; then
				if (( dummy >= 0 && \
				    dummy < 256 )) ; then
					octet_cnt+=1
					continue
				fi
			else
			x=$(zenity --error \
			    --title="$title" \
			    --text="$ipaddr $msg_badip")
			ipaddr=
			return
			fi
		done
	else
		x=$(zenity --error \
		    --title="$title" \
		    --text="$ipaddr $msg_badip")
		ipaddr=
	fi
}

getAllZoneNICs(){
	integer count=0
	for i in $(ifconfig -a4|grep  "^[a-z].*:")
	do
		print "$i" |grep "^[a-z].*:" >/dev/null 2>&1
		[ $? -eq 1 ] && continue
		
		i=${i%:} # Remove colon after interface name
		for j in $(ifconfig $i)
		do
			case $j in
				all-zones)
					aznics[count]=$i
					count+=1
					;;
			esac
		done
        done
}

getNetmask() {
	cidr=
	nm=$(zenity --entry \
	    --title="$title" \
	    --width=330 \
	    --text="$ipaddr: Enter netmask: " \
	    --entry-text 255.255.255.0)
	[ $? != 0 ] && return;

	cidr=$(perl -e 'use Socket; print unpack("%32b*",inet_aton($ARGV[0])), "\n";' $nm)
}

addNet() {
	getIPaddr
	if [[ -z $ipaddr ]] ; then
		return;
	fi
	getNetmask
	if [[ -z $cidr ]] ; then
		return;
	fi
	zonecfg -z $zonename "add net; \
	    set address=${ipaddr}/${cidr}; \
	    set physical=$nic; \
	    end"
	template=${zonename}_cipso
	cidr=32
	updateTnrhdb
}

getAttrs() {
	zone=global
	type=ignore
	for j in $(ifconfig $nic)
	do
		case $j in
			inet) type=$j;;
			zone) type=$j;;
			all-zones) zone=all-zones;;
			flags*) flags=$j;;
			*) case $type in
				inet) ipaddr=$j ;;
				zone) zone=$j ;;
				*) continue ;;
			   esac;
			   type=ignore;;
		esac
	done
	if [[ $flags == ~(E).UP, ]] ; then
		updown=Up
	else
		updown=Down
	fi
	if [[ $nic == ~(E).: ]] ; then
		linktype=logical
	else
		vnic=$(dladm show-vnic -po link $nic 2>/dev/null)
		if [[ -n $vnic ]] ; then
			linktype=virtual
		else
			linktype=physical
		fi
	fi
	if [ $ipaddr != 0.0.0.0 ] ; then
		x=$(grep "^${ipaddr}[^0-9]" $TNRHDB)
		if [ $? = 1 ] ; then
			template=cipso
			cidr=32
			updateTnrhdb
		else
			template=$(print "$x"|cut -d : -f2)
		fi
	else
		template="..."
		ipaddr="..."
	fi
}
deleteTnrhdbEntry() {
	remote=$(grep "^${ipaddr}[^0-9]" $TNRHDB)
	if [ $? = 0 ] ; then
		ip=$(print $remote|cut -d "/" -f1)
			if [[ $remote == ~(E)./ ]] ; then
				pr=$(print $remote|cut -d "/" -f2)
				remote="$ip\\/$pr"
			fi
		sed -e "/^${remote}/d" $TNRHDB > /tmp/tnrhdb.$$ 2>/dev/null
		mv /tmp/tnrhdb.$$ $TNRHDB
	fi
}

updateTnrhdb() {
	deleteTnrhdbEntry
	if [[ -n $cidr ]] ; then
		print "${ipaddr}/$cidr:$template" >> $TNRHDB
		tnctl -h ${ipaddr}/$cidr:$template
	else
		print "${ipaddr}:$template" >> $TNRHDB
		tnctl -h ${ipaddr}:$template
	fi
}

getIPaddr() {
        hostname=$(zenity --entry \
            --title="$title" \
	    --width=330 \
            --text="$nic: Enter Hostname: ")

        [ $? != 0 ] && return

	ipaddr=$(getent hosts $hostname|cut -f1)
        if [[ -z $ipaddr ]] ; then
		ipaddr=$(zenity --entry \
		    --title="$title" \
		    --text="$nic: Enter IP address: " \
		    --entry-text a.b.c.d)
		[ $? != 0 ] && return
		validateIPaddr
	fi

}

addHost() {
	# Update hosts
        if [[ -z $ipaddr ]] ; then
               return;
	fi
	grep "^${ipaddr}[^0-9]" /etc/inet/hosts >/dev/null
	if [ $? -eq 1 ] ; then
		print "$ipaddr\t$hostname" >> /etc/inet/hosts
	fi

	template=cipso
	cidr=32
	updateTnrhdb

	ifconfig $nic $ipaddr netmask + broadcast +
	#
	# TODO: better integration with nwam
	# TODO: get/set netmask for IP address
	#
	print $hostname > /etc/hostname.$nic
}

createInterface() {
	msg=$(ifconfig $nic addif 0.0.0.0)
	$(zenity --info \
	    --title="$title" \
	    --text="$msg" )
	nic=$(print "$msg"|cut -d" " -f5)

}
		    
createVNIC() {
	if [ $zonename != global ] ; then
		vnicname=${zonename}0
	else
		vnicname=$(zenity --entry \
		    --title="$title" \
		    --width=330 \
		    --entry-text="" \
		    --text="Enter VNIC Name: ")

		if [[ ! -n $vnicname ]] ; then
			return
		fi
	fi
	x=$(dladm show-vnic|grep "^$vnicname " )
	if [[ ! -n $x ]] ; then
		dladm create-vnic -l $nic $vnicname
	fi
	if [ $zonename = global ] ; then
		ifconfig $vnicname plumb
	else
		zonecfg -z $zonename "add net; \
		    set physical=$vnicname; \
		    end"
	fi
	nic=$vnicname
}

shareInterface() {
	#
	# TODO: better integration with nwam
	#
	ifconfig $nic all-zones;\
	if_file=/etc/hostname.$nic
	sed q | sed -e "s/$/ all-zones/" < $if_file >$TXTMP/txnetmgr.$$
	mv $TXTMP/txnetmgr.$$ $if_file
}

unshareInterface() {
	#
	# TODO: better integration with nwam
	#
	ifconfig $nic -zone;\
	if_file=/etc/hostname.$nic
	sed q | sed -e "s/all-zones/ /" < $if_file >$TXTMP/txnetmgr.$$
	mv $TXTMP/txnetmgr.$$ $if_file
}

addTnrhdb() {
	ipaddr=$(zenity --entry \
	    --title="$title" \
	    --width=330 \
	    --text="Zone:$zonename. Enter IP address of remote host or network: " \
	    --entry-text a.b.c.d)
	[ $? != 0 ] && return
	validateIPaddr
	if [[ -z $ipaddr ]] ; then
		return;
	fi
	if [ ${octets[3]} = 0 ] ; then
		nic="$ipaddr"
		getNetmask
		if [[ -z $cidr ]] ; then
			return;
		fi
	else
		cidr=32
	fi
	print "${ipaddr}/$cidr:$template" > $TXTMP/tnrhdb_new.$$
	x=$(tnchkdb -h $TXTMP/tnrhdb_new.$$ 2>$TXTMP/syntax_error.$$)
	if [ $? = 0 ] ; then
		updateTnrhdb
	else
		syntax=$(cat $TXTMP/syntax_error.$$)
		x=$(zenity --error \
		    --title="$title" \
		    --text="$syntax")
	fi
	rm $TXTMP/tnrhdb_new.$$
	rm $TXTMP/syntax_error.$$
}

removeTnrhdb() {
	while (( 1 )) do
		remotes=$(grep "^[^#][0-9.]" $TNRHDB|grep ":$template"|cut -d : -f1-2|tr : " ")
		if [ $template = cipso ] ; then
			templateHeading="from All Zones":
		else
			templateHeading="from this Zone":
		fi
		if [[ -n $remotes ]] ; then
			ipaddr=$(zenity --list \
			    --title="$title" \
			    --text="$msg_getremote" \
			    --height=250 \
			    --width=300 \
			    --column="Remove Access to:" \
			    --column="$templateHeading" \
			    $remotes)

			if [[ -n $ipaddr ]] ; then
				deleteTnrhdbEntry
				tnctl -dh ${ip}:$template
			else
				return
			fi
		else
			return
		fi
	done
}

setMLPs() {
	tnzone=$(grep "^$zonename:" $TNZONECFG 2>/dev/null)
	zoneMLPs=:$(print "$tnzone"|cut -d : -f4)
	sharedMLPs=:$(print "$tnzone"|cut -d : -f5)
	attrs="Private Interfaces$zoneMLPs\nShared Interfaces$sharedMLPs"
	ports=$(print "$attrs"|zenity --list \
	    --title="$title" \
	    --height=200 \
	    --width=450 \
	    --text="Zone: $zonename\nClick once to select, twice to edit.\nShift-click to select both rows." \
	    --column="Multilevel Ports (example: 80-81/tcp;111/udp;)" \
	    --editable \
	    --multiple
	    )

	if [[ -z $ports ]] ; then
		return
	fi

	# getopts needs another a blank and another dash
	ports=--$(print "$ports"|sed 's/ //g'|sed 's/|/ --/g'|sed 's/Interfaces:/ :/g')

	OPTIND=1
	while getopts "z:(Private)s:(Shared)" opt $ports ; do
		case $opt in
			z) zoneMLPs=$OPTARG ;;
			s) sharedMLPs=$OPTARG ;;
		esac
	done

	sed -e "/^$zonename:*/d" $TNZONECFG > $TXTMP/tnzonecfg.$$ 2>/dev/null
	tnzone=$(print "$tnzone"|cut -d : -f1-3)
	echo "${tnzone}${zoneMLPs}${sharedMLPs}" >> $TXTMP/tnzonecfg.$$

	x=$(tnchkdb -z $TXTMP/tnzonecfg.$$ 2>$TXTMP/syntax_error.$$)

	if [ $? = 0 ] ; then
		mv $TXTMP/tnzonecfg.$$ $TNZONECFG
		zenity --info \
		    --title="$title" \
		    --text="Multilevel ports for the $zonename zone\nwill be interpreted on next reboot."
		if [ $zonename != global ] ; then
			getLabelRange
		fi
	else
		syntax=$(cat $TXTMP/syntax_error.$$)
		x=$(zenity --error \
		    --title="$title" \
		    --text="$syntax")
		rm $TXTMP/tnzonecfg.$$
	fi
	rm $TXTMP/syntax_error.$$
}

enableAuthentication() {
	integer file_cnt=0

	zonepath=$(zoneadm -z $1 list -p|cut -d : -f4)
	ZONE_ETC_DIR=$zonepath/root/etc

	# If the zone's shadow file was previously read-only
	# there may be no root password entry for this zone.
	# If so, replace the root password entry with the global zone's.

	entry=$(grep ^root:: $ZONE_ETC_DIR/shadow)
	if [ $? -eq 0 ] ; then
		grep ^root: /etc/shadow > $TXTMP/shadow.$$
		sed -e "/^root::/d" $ZONE_ETC_DIR/shadow >> \
		    $TXTMP/shadow.$$ 2>/dev/null
		mv $TXTMP/shadow.$$ $ZONE_ETC_DIR/shadow
		chmod 400 $ZONE_ETC_DIR/shadow
	fi

	if [ $LOGNAME = "root" ]; then
		return
	fi

	file[0]="passwd"
	file[1]="shadow"
	file[2]="user_attr"
	#
	# Add the user who assumed the root role to each installed zone
	#
	while (( file_cnt < ${#file[*]} )); do
		exists=$(grep "^${LOGNAME}:" \
		    $ZONE_ETC_DIR/${file[file_cnt]} >/dev/null)
		if [ $? -ne 0 ] ; then
			entry=$(grep "^${LOGNAME}:" \
			    /etc/${file[file_cnt]})
			if [ $? -eq 0 ] ; then
				print "$entry" >> \
				    $ZONE_ETC_DIR/${file[file_cnt]}
			fi
		fi
		file_cnt+=1
	done
	chmod 400 $ZONE_ETC_DIR/shadow
}

unsharePasswd() {
	zonecfg -z $1 remove fs dir=/etc/passwd >/dev/null 2>&1 | grep -v such
	zonecfg -z $1 remove fs dir=/etc/shadow >/dev/null 2>&1 | grep -v such
	zoneadm -z $1 ready >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		enableAuthentication $1
		zoneadm -z $1 halt >/dev/null 2>&1
	else
		echo Skipping $1
	fi
}

sharePasswd() {
	passwd=$(zonecfg -z $1 info|grep /etc/passwd)
	if [ $? -eq 1 ] ; then
		zonecfg -z $1 "add fs; \
		    set special=/etc/passwd; \
		    set dir=/etc/passwd; \
		    set type=lofs; \
		    add options ro; \
		    end; \
		    add fs; \
		    set special=/etc/shadow; \
		    set dir=/etc/shadow; \
		    set type=lofs; \
		    add options ro; \
		    end"
	fi
	zoneadm -z $1 halt >/dev/null 2>&1
}

# This routine is a toggle -- if we find it configured for global nscd,
# change to nscd-per-label and vice-versa.
#
# The user was presented with only the choice to CHANGE the existing
# configuration.

manageNscd() {
	if [ $NSCD_PER_LABEL -eq 0 ] ; then
		# this MUST be a regular file for svc-nscd to detect
		touch $NSCD_INDICATOR
		NSCD_OPT="Unconfigure per-zone name service"
		NSCD_PER_LABEL=1
		for i in $(zoneadm list -i | grep -v global) ; do
			zoneadm -z $i halt >/dev/null 2>&1
			unsharePasswd $i
		done
	else
		rm -f $NSCD_INDICATOR
		NSCD_OPT="Configure per-zone name service"
		NSCD_PER_LABEL=0
		for i in $(zoneadm list -i | grep -v global) ; do
			zoneadm -z $i halt >/dev/null 2>&1
			sharePasswd $i
		done
	fi
}

manageZoneNets () {
	ncmds[0]="Only use all-zones interfaces"
	ncmds[1]="Add a logical interface"
	ncmds[2]="Add a virtual interface (VNIC)"

	stacks[0]="Shared Stack"
	stacks[1]="Exclusive Stack"

	getAllZoneNICs
	netOps[0]="1\n${ncmds[0]}\nShared Stack\n${aznics[*]}"

	integer nic_cnt=0
	integer netOp_cnt=2

	set -A nics $(dladm show-phys|grep -v LINK|cut -f1 -d " ")

	while (( nic_cnt < ${#nics[*]} )); do
		netOps[netOp_cnt - 1]="\n$netOp_cnt\n${ncmds[1]}\n${stacks[0]}\n${nics[nic_cnt]}"
		netOp_cnt+=1
		netOps[netOp_cnt - 1]="\n$netOp_cnt\n${ncmds[2]}\n${stacks[1]}\n${nics[nic_cnt]}"
		netOp_cnt+=1
		nic_cnt+=1
	done

	netOp=$(print "${netOps[*]}"|zenity --list \
	    --title="$title" \
	    --text="$msg_getnet $zonename zone:" \
	    --height=300 \
	    --width=500 \
	    --column="#" \
	    --column="Network Configuration " \
	    --column="IP Type" \
	    --column="Available Interfaces" \
	    --hide-column=1
	)
	
	# User picked cancel or no selection
	if [[ -z $netOp ]] ; then
		return
	fi

	# All-zones is the default, so just return
	if [ $netOp = 1 ] ; then
		return
	fi

	cmd=$(print "${netOps[$netOp - 1]}"|tr '\n' ';' |cut -d';' -f 3)
	nic=$(print "${netOps[$netOp - 1]}"|tr '\n' ';' |cut -d';' -f 5) 
	case $cmd in
	    ${ncmds[1]} )
		addNet;
		;;	
	    ${ncmds[2]} )
		zonecfg -z $zonename set ip-type=exclusive
		createVNIC
		;;
	esac
}

manageInterface () {
	while (( 1 )) do
		getAttrs

		# Clear list of commands

		share=
		setipaddr=
		newlogical=
		newvnic=
		unplumb=
		bringup=
		bringdown=

		if [ $updown = Down ] ; then
			bringup="Bring Up\n"
		else
			bringdown="Bring Down\n"
		fi

		case $linktype in
		physical )
			newlogical="Create Logical Interface...\n";
			newvnic="Create Virtual Interface (VNIC)...\n";
			;;
		logical )
			unplumb="Remove Logical Interface\n"
			;;
		virtual )
			newlogical="Create Logical Interface...\n";
			unplumb="Remove Virtual Interface\n" ;
			;;
		esac

		if [ $ipaddr = "..." ] ; then
			setipaddr="Set IP address...\n"
		elif [ $zone != all-zones ] ; then
			share="Share with Shared-IP Zones\n"
		else 
			share="Remove from Shared-IP Zones\n"
		fi

		command=$(print ""\
		    $share \
		    $setipaddr \
		    $newlogical \
		    $newvnic \
		    $unplumb \
		    $bringup \
		    $bringdown \
		    | zenity --list \
		    --title="$title" \
		    --text="Select a command from the list below:" \
		    --height=300 \
		    --column "Interface: $nic" )

		case $command in
		    " Create Logical Interface...")
			createInterface;;
		    " Create Virtual Interface (VNIC)...")
			createVNIC ;;	
		    " Set IP address...")
			getIPaddr
			addHost;;
		    " Share with Shared-IP Zones")
			shareInterface;;
		    " Remove from Shared-IP Zones")
			unshareInterface;;
		    " Remove Logical Interface")
			ifconfig $nic unplumb
			rm -f /etc/hostname.$nic
			return;;
		    " Remove Virtual Interface")
			ifconfig $nic unplumb
			dladm delete-vnic $nic
			rm -f /etc/hostname.$nic
			return;;
		    " Bring Up")
			ifconfig $nic up;;
		    " Bring Down")
			ifconfig $nic down;;
		    *) return;;
		esac
	done
}

sharePrimaryNic() {
	set -A ip $(getent hosts $(cat /etc/nodename))
	for i in $(ifconfig -au4|grep  "^[a-z].*:" |grep -v LOOPBACK)
	do
		print "$i" |grep "^[a-z].*:" >/dev/null 2>&1
		[ $? -eq 1 ] && continue
		
		nic=${i%:} # Remove colon after interface name
		getAttrs
		if [ ${ip[0]} = $ipaddr ]; then
			shareInterface
			break
		fi
	done
}

manageNets() {
	while (( 1 )) do
		attrs=
		for i in $(ifconfig -a4|grep  "^[a-z].*:" |grep -v LOOPBACK)
		do
			print "$i" |grep "^[a-z].*:" >/dev/null 2>&1
			[ $? -eq 1 ] && continue
			
			nic=${i%:} # Remove colon after interface name
			getAttrs
			attrs="$nic $linktype $zone $ipaddr $template $updown $attrs"
		done

		nic=$(zenity --list \
		    --title="$title" \
		    --text="Select an interface from the list below:" \
		    --height=300 \
		    --width=500 \
		    --column="Interface" \
		    --column="Type" \
		    --column="Zone Name" \
		    --column="IP Address" \
		    --column="Template" \
		    --column="State" \
		    $attrs)

		if [[ -z $nic ]] ; then
			return
		fi
		manageInterface
	done
}

createLDAPclient() {
	ldaptitle="$title: Create LDAP Client"
	ldapdomain=$(zenity --entry \
	    --width=400 \
	    --title="$ldaptitle" \
	    --text="Enter Domain Name: ")
	if [[ -n $ldapdomain ]] ; then
	ldapserver=$(zenity --entry \
	    --width=400 \
	    --title="$ldaptitle" \
	    --text="Enter Hostname of LDAP Server: ")
	else
		return
	fi
	if [[ -n $ldapserver ]] ; then
	ldapserveraddr=$(zenity --entry \
	    --width=400 \
	    --title="$ldaptitle" \
	    --text="Enter IP adddress of LDAP Server $ldapserver: ")
	else
		return
	fi
	ldappassword=""
	while [[ -z ${ldappassword} || "x$ldappassword" != "x$ldappasswordconfirm" ]] ; do
	    ldappassword=$(zenity --entry \
		--width=400 \
		--title="$ldaptitle" \
		--hide-text \
		--text="Enter LDAP Proxy Password:")
	    ldappasswordconfirm=$(zenity --entry \
		--width=400 \
		--title="$ldaptitle" \
		--hide-text \
		--text="Confirm LDAP Proxy Password:")
	done
	ldapprofile=$(zenity --entry \
	    --width=400 \
	    --title="$ldaptitle" \
	    --text="Enter LDAP Profile Name: ")
	whatnext=$(zenity --list \
	    --width=400 \
	    --height=250 \
	    --title="$ldaptitle" \
	    --text="Proceed to create LDAP Client?" \
	    --column=Parameter --column=Value \
	    "Domain Name" "$ldapdomain" \
	    "Hostname" "$ldapserver" \
	    "IP Address" "$ldapserveraddr" \
	    "Password" "$(print "$ldappassword" | sed 's/./*/g')" \
	    "Profile" "$ldapprofile")
	[ $? != 0 ] && return

	grep "^${ldapserveraddr}[^0-9]" /etc/hosts > /dev/null
	if [ $? -eq 1 ] ; then
		print "$ldapserveraddr $ldapserver" >> /etc/hosts
	fi

	grep "${ldapserver}:" $TNRHDB > /dev/null
	if [ $? -eq 1 ] ; then
		print "# ${ldapserver} - ldap server" \
		    >> $TNRHDB
		print "${ldapserveraddr}:cipso" \
		    >> $TNRHDB
		tnctl -h "${ldapserveraddr}:cipso"
	fi

	proxyDN=$(print $ldapdomain|awk -F"." \
	    "{ ORS = \"\" } { for (i = 1; i < NF; i++) print \"dc=\"\\\$i\",\" }{ print \"dc=\"\\\$NF }")

	zenity --info \
	    --title="$ldaptitle" \
	    --width=500 \
	    --text="global zone will be LDAP client of $ldapserver"

	ldapout=$TXTMP/ldapclient.$$

	ldapclient init -a profileName="$ldapprofile" \
	    -a domainName="$ldapdomain" \
	    -a proxyDN"=cn=proxyagent,ou=profile,$proxyDN" \
	    -a proxyPassword="$ldappassword" \
	    "$ldapserveraddr" >$ldapout 2>&1

	if [ $? -eq 0 ] ; then
	    ldapstatus=Success
	else
	    ldapstatus=Error
	fi

	zenity --text-info \
	    --width=700 \
	    --height=300 \
	    --title="$ldaptitle: $ldapstatus" \
	    --filename=$ldapout

	rm -f $ldapout


}

tearDownZones() {
	if [ $DISP -eq 0 ] ; then
		if [ $FORCE -eq 0 ] ; then
			gettext "OK to destroy all zones [y|N]? "
			read ans
			printf "%s\n" "$ans" \
			    | /usr/xpg4/bin/grep -Eq "$(locale yesexpr)"
			if [ $? -ne 0 ] ; then
				gettext "canceled.\n"
				return 1
			fi
		fi
		gettext "destroying all zones ...\n"
	else
		killall=$(zenity --question \
		    --title="$title" \
		    --width=330 \
		    --text="$msg_confirmkill")
		if [[ $? != 0 ]]; then
			return
		fi
	fi

	for p in $(zoneadm list -cp|grep -v global:) ; do
		zonename=$(echo "$p"|cut -d : -f2)
		if [ $DISP -eq 0 ] ; then
			gettext "destroying zone $zonename ...\n"
		fi
		zoneadm -z $zonename halt 1>/dev/null 2>&1
		zoneadm -z $zonename uninstall -F 1>/dev/null 2>&1
		delete -rRf
	done
	zonename=global
}

createDefaultZones() {
	# If GUI display is not used, skip the dialog
	if [ $DISP -eq 0 ] ; then
		createDefaultPublic
		if [ $? -ne 0 ] ; then
			return 1
		fi
		createDefaultInternal
		return
	fi

	msg_choose1=$(gettext "Choose one:")
	defpub=$(gettext "$PUBZONE zone only")
	defboth=$(gettext "$PUBZONE and $INTZONE zones")
	defskip=$(gettext "Main Menu...")
	command=$(echo ""\
	    "$defpub\n" \
	    "$defboth\n" \
	    "$defskip\n" \
	    | zenity --list \
	    --title="$title" \
	    --text="$msg_defzones" \
	    --column="$msg_choose1" \
	    --height=400 \
	    --width=330 )

	case $command in
	    " $defpub")
		createDefaultPublic ;;

	    " $defboth")
		createDefaultPublic
		if [ $? -ne 0 ] ; then
			return 1
		fi
		createDefaultInternal ;;

	    *)
		return;;
	esac
}

createDefaultPublic() {
	zonename=$PUBZONE
	if [ $DISP -eq 0 ] ; then
		gettext "creating default $zonename zone ...\n"
	fi
	newZone	
	zone_cnt+=1 
	hexlabel=$DEFAULTLABEL
	setTNdata
	sharePrimaryNic

	install
	if [ $? -ne 0 ] ; then
		return 1
	fi

	if [ $DISP -eq 0 ] ; then
		gettext "booting zone $zonename ...\n"
		zoneadm -z $zonename boot
	else
		zoneadm -z $zonename boot &
		gnome-terminal \
		    --disable-factory \
		    --title="Zone Console: $zonename $msg_continue" \
		    --command "zlogin -C $zonename"
	fi
}

createDefaultInternal() {
	zoneadm -z $PUBZONE halt

	zonename=snapshot
	newZone	
	zone_cnt+=1 
	zonecfg -z $zonename set autoboot=false

	clone $PUBZONE
	zoneadm -z $PUBZONE boot &

	zonename=$INTZONE
	if [ $DISP -eq 0 ] ; then
		gettext "creating default $zonename zone ...\n"
	fi
	newZone	
	zone_cnt+=1 

	hexlabel=$INTLABEL
	x=$(grep -i :{$hexlabel}: $TNZONECFG)
	if [ $? = 0 ] ; then
		z=$(print $x|cut -d : -f1)
		echo "$msg_inuse $z zone."
	else
		setTNdata
	fi

	clone snapshot
	if [ $DISP -eq 0 ] ; then
		gettext "booting zone $zonename ...\n"
	else
		gnome-terminal \
		    --title="Zone Console: $zonename" \
		    --command "zlogin -C $zonename" &
	fi
	zoneadm -z $zonename boot &
}

selectZone() {
	set -A zonelist "global\nrunning\nADMIN_HIGH"
	integer zone_cnt=1

	for p in $(zoneadm list -cp|grep -v global:) ; do
		zone_cnt+=1
	done
	if [ $zone_cnt == 1 ] ; then
		createDefaultZones
	fi
	if [ $zone_cnt == 1 ] ; then
		zonename=global
		singleZone
		return
	fi

	zone_cnt=1
	for p in $(zoneadm list -cp|grep -v global:) ; do
		zonename=$(echo "$p"|cut -d : -f2)
		state=$(echo "$p"|cut -d : -f3)
		hexlabel=$(grep "^$zonename:" $TNZONECFG|cut -d : -f2)
		if [[ $hexlabel ]] ; then
			curlabel=$(hextoalabel $hexlabel)
		else
			curlabel=...
		fi
		zonelist[zone_cnt]="\n$zonename\n$state\n$curlabel"
		zone_cnt+=1
	done
	zonename=$(print "${zonelist[*]}"|zenity --list \
	    --title="$title" \
	    --text="$msg_getzone" \
	    --height=300 \
	    --width=500 \
	    --column="Zone Name" \
	    --column="Status" \
	    --column="Sensitivity Label" \
	)

	# if the menu choice was a zonename, pop up zone menu
	if [[ -n $zonename ]] ; then
		singleZone
	else
		exit
	fi
}

# Loop for single-zone menu
singleZone() {

	while (( 1 )) do
		# Clear list of commands

		console=
		label=
		start=
		reboot=
		stop=
		clone=
		install=
		ready=
		uninstall=
		autoboot=
		delete=
		deletenet=
		permitrelabel=

		if [ $zone_cnt -gt 1 ] ; then
			killZones="Destroy all zones...\n"
			xit="Select another zone..."
		else
			killZones=
			xit="Exit"
		fi
		if [ $zonename = global ] ; then
			ldapClient="Create LDAP Client...\n"
			nscdOpt="$NSCD_OPT\n"
			createZone="Create a new zone...\n"
			addnet="Configure Network Interfaces...\n"
		else
			ldapClient=
			nscdOpt=
			createZone=
			addnet=
			killZones=
		fi

		zonestate=$(zoneadm -z $zonename list -p | cut -d : -f 3)

		consoleCheck;
		labelCheck;
		delay=0

		if [ $zonename != global ] ; then
			case $zonestate in
				running)
					ready="Ready\n"
					reboot="Reboot\n"
					stop="Halt\n"
					;;
				ready)
					start="Boot\n"
					stop="Halt\n"
					;;
				installed)
					if [[ -z $label ]] ; then
						ready="Ready\n"
						start="Boot\n"
					fi
					uninstall="Uninstall\n"
					relabelCheck
					autobootCheck
					;;
				configured) 
					install="Install...\n"
					cloneCheck
					delete="Delete\n"
					console=
					;;
				incomplete)
					uninstall="Uninstall\n"
					;;
				*)
				;;
			esac
		fi

		command=$(echo ""\
		    $createZone \
		    $console \
		    $label \
		    $start \
		    $reboot \
		    $stop \
		    $clone \
		    $install \
		    $ready \
		    $uninstall \
		    $delete \
		    $addnet \
		    $deletenet \
		    $addremotehost \
		    $addcipsohost \
		    $removeremotehost \
		    $removecipsohost \
		    $setmlps \
		    $permitrelabel \
		    $autoboot \
		    $ldapClient \
		    $nscdOpt \
		    $killZones \
		    $xit \
		    | zenity --list \
		    --title="$title" \
		    --text="$msg_getcmd" \
		    --height=400 \
		    --width=330 \
		    --column "Zone: $zonename   Status: $zonestate" )

		case $command in
		    " Create a new zone...")
			zonename=
			newZone ;;

		    " Zone Console...")
			delay=2
			gnome-terminal \
			    --title="Zone Console: $zonename" \
			    --command "zlogin -C $zonename" & ;;

		    " Select Label...")
			selectLabel;;

		    " Ready")
			zoneadm -z $zonename ready ;;

		    " Boot")
			zoneadm -z $zonename boot ;;

		    " Halt")
			zoneadm -z $zonename halt ;;

		    " Reboot")
			zoneadm -z $zonename reboot ;;

		    " Install...")
			install;;

		    " Clone...")
			clone ;;

		    " Uninstall")
			zoneadm -z $zonename uninstall -F;;

		    " Delete")
			delete
			return ;;

		    " Configure Network Interfaces...")
			if [ $zonename = global ] ; then
				manageNets
			else
				manageZoneNets
			fi;;	

		    " Add Single-level Access to Remote Host...")
			addTnrhdb ;;

		    " Add Multilevel Access to Remote Host...")
			template=cipso
			addTnrhdb ;;

		    " Remove Single-level Access to Remote Host...")
			removeTnrhdb ;;

		    " Remove Multilevel Access to Remote Host...")
			template=cipso
			removeTnrhdb ;;

		    " Configure Multilevel Ports...")
			setMLPs;;

		    " Permit Relabeling")
			zonecfg -z $zonename set limitpriv=default,\
win_mac_read,win_mac_write,win_selection,win_dac_read,win_dac_write,\
file_downgrade_sl,file_upgrade_sl,sys_trans_label ;;

		    " Deny Relabeling")
			zonecfg -z $zonename set limitpriv=default ;;

		    " Set Automatic Booting")
			zonecfg -z $zonename set autoboot=true ;;

		    " Set Manual Booting")
			zonecfg -z $zonename set autoboot=false ;;

		    " Create LDAP Client...")
			createLDAPclient ;;

		    " Configure per-zone name service")
			manageNscd ;;

		    " Unconfigure per-zone name service")
			manageNscd ;;

		    " Destroy all zones...")
			tearDownZones
			return ;;

		    *)
			if [ $zone_cnt == 1 ] ; then
				exit
			else
				return
			fi;;
		esac
		sleep $delay;
	done
}

# Main loop for top-level window
#

/usr/bin/plabel $$ 1>/dev/null 2>&1
if [ $? != 0 ] ; then
	gettext "$0 : Trusted Extensions must be enabled.\n"
	exit 1
fi

myzone=$(/sbin/zonename)
if [ $myzone != "global" ] ; then
	gettext "$0 : must be in global zone to run.\n"
	exit 1
fi


process_options "$@" || exit

mkdir $TXTMP 2>/dev/null
deflabel=$(chk_encodings -a|grep "Default User Sensitivity"|\
   sed 's/= /=/'|sed 's/"/'''/g|cut -d"=" -f2)
DEFAULTLABEL=$(atohexlabel ${deflabel})
intlabel=$(chk_encodings -a|grep "Default User Clearance"|\
   sed 's/= /=/'|sed 's/"/'''/g|cut -d"=" -f2)
INTLABEL=$(atohexlabel -c "${intlabel}")

# are there any zfs pools?
ZDSET=none
zpool iostat 1>/dev/null 2>&1
if [ $? = 0 ] ; then
	# is there a zfs pool named "zone"?
	zpool list -H zone 1>/dev/null 2>&1
	if [ $? = 0 ] ; then
		# yes
		ZDSET=zone
	else
		# no, but is there a root pool?
		rootfs=$(df -n / | awk '{print $3}')
		if [ $rootfs = "zfs" ] ; then
			# yes, use it
			ZDSET=$(zfs list -Ho name / | cut -d/ -f 1)/zones
			zfs list -H $ZDSET 1>/dev/null 2>&1
			if [ $? = 1 ] ; then
				createZDSET "-o mountpoint=/zone" $ZDSET
			fi
		fi
	fi
fi

if [ $DISP -eq 0 ] ; then
	gettext "non-interactive mode ...\n"

	if [ $DESTROYZONES -eq 1 ] ; then
		tearDownZones
	fi

	if [ $CREATEDEF -eq 1 ] ; then
		if [[ $(zoneadm list -c) == global ]] ; then
			createDefaultZones
		else
			gettext "cannot create default zones because there are existing zones.\n"
		fi
	fi

	exit
fi

if [ $NSCD_PER_LABEL -eq 0 ] ; then
	NSCD_OPT="Configure per-zone name service"
else
	NSCD_OPT="Unconfigure per-zone name service"
fi


while (( 1 )) do
	selectZone
done
