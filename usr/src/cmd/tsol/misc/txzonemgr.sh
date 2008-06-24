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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

# This script provides a simple GUI for managing labeled zones.
# It takes no arguments, but provides contextual menus which
# provide appropriate choices. It must be run in the global
# zone as root.

NSCD_PER_LABEL=0
NSCD_INDICATOR="/var/tsol/doors/nscd_per_label"
export NSCD_PER_LABEL
export NSCD_INDICATOR
if [ -f $NSCD_INDICATOR ] ; then
	NSCD_PER_LABEL=1
fi
PATH=/usr/bin:/usr/sbin:/usr/lib export PATH
title="Labeled Zone Manager"
maxlabel=`chk_encodings -X 2>/dev/null`
if [[ ! -n $maxlabel ]]; then
	maxlabel=0x000a-08-f8
fi
zonename=""
export zonename
config=/tmp/zfg.$$ ;

consoleCheck() {
	zconsole=`pgrep -f "zlogin -C $zonename"`
	if [ $? != 0 ]; then
		console="Zone Console...\n"
	fi
}

labelCheck() {
	hexlabel=`/bin/grep "^$zonename:" \
	    /etc/security/tsol/tnzonecfg|cut -d ":" -f2`;
	if [ $hexlabel ] ; then
		label=
		curlabel=`hextoalabel $hexlabel`
	else
		label="Select Label...\n"
		curlabel=...
	fi
}

snapshotCheck() {
	filesystem=`zfs list |grep $ZDSET/$zonename |cut -d " " -f1`
	if [[ -n $filesystem ]]; then
		snapshot="Create Snapshot\n"
	fi
}

copyCheck() {
	zonelist=""
	for p in `zoneadm list -ip`; do
		q=`echo $p|cut -d ":" -f2`
		if [ $q != $zonename ]; then
			zonelist="$zonelist $q"
		fi
	done
	if [[ -n $zonelist ]]; then
		copy="Copy...\n"; \
		clone="Clone\n"; \
	fi
}

relabelCheck() {
	macstate=`zonecfg -z $zonename info|grep win_mac_write`
	if [[ -n $macstate ]]; then
		permitrelabel="Deny Relabeling\n"
	else
		permitrelabel="Permit Relabeling\n"
	fi
}

selectLabel() {
	labelList=""
	for p in `lslabels -h $maxlabel`; do
		hexlabel=`/bin/grep :$p: /etc/security/tsol/tnzonecfg`
		if [ $? != 0 ]; then
			newlabel=`hextoalabel $p`
			labelList="$labelList $newlabel\n"
		fi
	done
	alabel=$(echo $labelList|zenity --list \
	    --title="$title" \
	    --height=300 \
	    --width=400 \
	    --column="Available Sensitivity Labels")

	if [[ -n $alabel ]]; then
		newlabel=`atohexlabel "$alabel" 2>/dev/null`
		if [[ -n $newlabel ]]; then
			echo $zonename:$newlabel:0:: >> /etc/security/tsol/tnzonecfg
		else
			x=$(zenity --error \
			    --title="$title" \
			    --text="$alabel is not valid")
		fi
	fi
}

resolveXdisplay() {
	export ZONE_PATH
	export ZONE_ETC_DIR
	export IPNODES
	export LIST
	ERRORLIST=""
	export ERRORLIST
	# if using nscd-per-label then we have to be sure the global zone's
	# hostname resolves because it is used for DISPLAY in X
	ghostname=`hostname`
	export ghostname

	if [[ -n "$1" ]] ; then
		LIST=`zoneadm list -ip | grep ":$1:"`
	else
		LIST=`zoneadm list -ip | grep -v "global"`
	fi

	gipaddress=`getent hosts $ghostname|cut -f1`
	for i in $LIST; do
		ZONE_PATH=`echo "$i" |cut -d ":" -f4`
		ZONE_ETC_DIR=$ZONE_PATH/root/etc
		IPNODES=${ZONE_ETC_DIR}/inet/ipnodes

		# Rather than toggle on and off with NSCD_PER_LABEL, put the
		# information in there and a sysadmin can remove it if necessary
		# $DISPLAY will not work in X without global hostname
		ENTRY=`grep $ghostname $IPNODES`
		case "$ENTRY" in
			127.0.0.1* )
				if [[ -z $ERRORLIST ]] ; then
					ERRORLIST="$ghostname address 127.0.0.1 found in:\n"
				fi
				ERRORLIST="$ERRORLIST $IPNODES\n"
				;;
			"")
				gipaddress=`getent hosts $ghostname|cut -f1`
				echo "$gipaddress\t$ghostname" >>  $IPNODES
				;;
			*)
				continue
				;;

		esac
	done
	if [[ -n "$ERRORLIST" ]] ; then
		x=$(zenity --error \
		    --title="$title" \
		    --text="WARNING:\n\n\n$ERRORLIST\n\n")
	fi
}

clone() {
	image=`zfs list |grep snapshot|cut -d " " -f1| \
	    zenity --list \
		--title="$title" \
	        --height=300 \
		--column="ZFS Zone Snapshots"`
	if [[ -n $image ]]; then
		dataset=`zfs list |grep $ZDSET/$zonename |cut -d " " -f1`
		if [[ -n $dataset ]]; then
			/usr/sbin/zfs destroy $ZDSET/$zonename
		fi
		/usr/sbin/zfs clone $image $ZDSET/$zonename
		/usr/sbin/zfs set mountpoint=/zone/$zonename  $ZDSET/$zonename

		/usr/sbin/zoneadm -z $zonename attach -F
		if [ ! -f /var/ldap/ldap_client_file ]; then
			if [ $NSCD_PER_LABEL = 0 ] ; then
				sharePasswd
			else
				unsharePasswd
				resolveXdisplay
			fi
		fi
	fi
}

copy() {

	image=`zenity --list \
	    --title="$title: Copy From" \
	    --height=300 \
	    --column="Installed Zones" $zonelist`

	/usr/bin/gnome-terminal \
	    --title="$title: Copying $image to $zonename zone" \
	    --command "zoneadm -z $zonename clone -m copy $image" \
	    --disable-factory \
	    --hide-menubar

	if [ ! -f /var/ldap/ldap_client_file ]; then
		if [ $NSCD_PER_LABEL = 0 ] ; then
			sharePasswd
		else
			unsharePasswd
			resolveXdisplay
		fi
	fi
}

initialize() {
	hostname=`hostname`
	hostname=$(zenity --entry \
	    --title="$title" \
	    --text="Enter Host Name: " \
	    --entry-text $hostname)
	if [ $? != 0 ]; then
		exit 1
	fi

	ZONE_PATH=`zoneadm list -ip|grep ":${zonename}:"|cut -d ":" -f4`
	if [ -z "$ZONE_PATH" ] ; then
		x=$(zenity --error \
		    --title="$title" \
		    --text="$zonename is not an installed zone")
		exit 1
	fi
	ZONE_ETC_DIR=$ZONE_PATH/root/etc
	ipaddress=`getent hosts $hostname|cut -f1`
	SYSIDCFG=${ZONE_ETC_DIR}/sysidcfg

	if [ -f /var/ldap/ldap_client_file ]; then
		ldapaddress=`ldapclient list | \
		    /bin/grep "^NS_LDAP_SERVERS" | cut -d " " -f2`
		echo "name_service=LDAP {" > ${SYSIDCFG}
		domain=`domainname`
		echo "domain_name=$domain" >> ${SYSIDCFG}
		profName=`ldapclient list | \
		    /bin/grep "^NS_LDAP_PROFILE" | cut -d " " -f2`
		proxyPwd=`ldapclient list | \
		    /bin/grep "^NS_LDAP_BINDPASSWD" | cut -d " " -f2`
		proxyDN=`ldapclient list | \
		    /bin/grep "^NS_LDAP_BINDDN" | cut -d " " -f 2`
		if [ "$proxyDN" ]; then
			echo "proxy_dn=\"$proxyDN\"" >> ${SYSIDCFG}
			echo "proxy_password=\"$proxyPwd\"" >> ${SYSIDCFG}
		fi
		echo "profile=$profName" >> ${SYSIDCFG}
		echo "profile_server=$ldapaddress }" >> ${SYSIDCFG}
		cp /etc/nsswitch.conf $ZONE_ETC_DIR/nsswitch.ldap
	else
		echo "name_service=NONE" > ${SYSIDCFG}
		if [ $NSCD_PER_LABEL = 0 ] ; then
			sharePasswd
		else
			# had to put resolveXdisplay lower down for this case
			unsharePasswd
		fi
	fi

	echo "security_policy=NONE" >> ${SYSIDCFG}
	locale=`locale|grep LANG | cut -d "=" -f2`
	if [[ -z $locale ]]; then
		locale="C"
	fi
	echo "system_locale=$locale" >> ${SYSIDCFG}
	timezone=`/bin/grep "^TZ" /etc/TIMEZONE|cut -d "=" -f2`
	echo "timezone=$timezone" >> ${SYSIDCFG}
	echo "terminal=vt100" >> ${SYSIDCFG}
	rootpwd=`/bin/grep "^root:" /etc/shadow|cut -d ":" -f2`
	echo "root_password=$rootpwd" >> ${SYSIDCFG}
	echo "network_interface=PRIMARY {" >> ${SYSIDCFG}
	echo "protocol_ipv6=no" >> ${SYSIDCFG}
	echo "hostname=$hostname" >> ${SYSIDCFG}
	echo "ip_address=$ipaddress }" >> ${SYSIDCFG}
	cp /etc/default/nfs ${ZONE_ETC_DIR}/default/nfs
	touch ${ZONE_ETC_DIR}/.NFS4inst_state.domain
	if [ $NSCD_PER_LABEL = 1 ] ; then
		resolveXdisplay
	fi
}

install() {
	# if there is a zfs pool for zone
	# create a new dataset for the zone
	# This step is done automatically by zonecfg
	# in Solaris Express 8/06 or newer

	if [ $ZDSET != none ]; then
		zfs create -o mountpoint=/zone/$zonename \
		    $ZDSET/$zonename
		chmod 700 /zone/$zonename
	fi

	/usr/bin/gnome-terminal \
	    --title="$title: Installing $zonename zone" \
	    --command "zoneadm -z $zonename install" \
	    --disable-factory \
	    --hide-menubar

	initialize
}

delete() {
	# if there is an entry for this zone in tnzonecfg, remove it
	# before deleting the zone.

	tnzone=`egrep "^$zonename:" /etc/security/tsol/tnzonecfg 2>/dev/null`
	if [ -n "${tnzone}" ]; then
		sed -e "/^$tnzone:*/d" /etc/security/tsol/tnzonecfg > \
		    /tmp/tnzonefg.$$ 2>/dev/null
		mv /tmp/tnzonefg.$$ /etc/security/tsol/tnzonecfg
	fi
	zonecfg -z $zonename delete -F
	dataset=`zfs list |grep $ZDSET/$zonename |cut -d " " -f1`
	if [[ -n $dataset ]]; then
		/usr/sbin/zfs destroy $ZDSET/$zonename
	fi
	zonename=
}

getNIC(){

	nics=
	for i in `ifconfig -a4|grep  "^[a-z].*:" |grep -v LOOPBACK`
	do
		echo $i |grep "^[a-z].*:" >/dev/null 2>&1
		if [ $? -eq 1 ]; then
			continue
		fi
		i=${i%:} # Remove colon after interface name
		echo $i |grep ":" >/dev/null 2>&1
		if [ $? -eq 0 ]; then
			continue
		fi
		nics="$nics $i"
	done

	nic=$(zenity --list \
	    --title="$title" \
	    --column="Interface" \
	    $nics)
}

getNetmask() {

	cidr=
	nm=$(zenity --entry \
	    --title="$title" \
	    --text="$ipaddr: Enter netmask: " \
	    --entry-text 255.255.255.0)
	if [ $? != 0 ]; then
	       return;
	fi

	cidr=`perl -e 'use Socket; print unpack("%32b*",inet_aton($ARGV[0])), "\n";' $nm`
}

addNet() {
	getNIC
	if [[ -z $nic ]]; then
		return;
	fi
	getIPaddr
	if [[ -z $ipaddr ]]; then
		return;
	fi
	getNetmask
	if [[ -z $cidr ]]; then
		return;
	fi
	zcfg="
add net
set address=${ipaddr}/${cidr}
set physical=$nic
end
commit
"
	echo "$zcfg" > $config ;
	zonecfg -z $zonename -f $config ;
	rm $config
}

getAttrs() {
	zone=global
	type=ignore
	for j in `ifconfig $nic`
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
			   esac;\
			   type=ignore;;
		esac
	done
	if [ $ipaddr != 0.0.0.0 ]; then
		template=`tninfo -h $ipaddr|grep Template| cut -d" " -f3`
	else
		template="..."
		ipaddr="..."
	fi
}

updateTnrhdb() {
	tnctl -h ${ipaddr}:$template
	x=`grep "^${ipaddr}[^0-9]" /etc/security/tsol/tnrhdb`
	if [ $? = 0 ]; then
		sed s/$x/${ipaddr}:$template/g /etc/security/tsol/tnrhdb \
		    > /tmp/txnetmgr.$$
		mv /tmp/txnetmgr.$$ /etc/security/tsol/tnrhdb
	else
		echo ${ipaddr}:$template >> /etc/security/tsol/tnrhdb
	fi
}

getIPaddr() {
        hostname=$(zenity --entry \
            --title="$title" \
            --text="$nic: Enter hostname: ")

        if [ $? != 0 ]; then
               return;
	fi

	ipaddr=`getent hosts $hostname|cut -f1`
        if [[ -z $ipaddr ]]; then

		ipaddr=$(zenity --entry \
		    --title="$title" \
		    --text="$nic: Enter IP address: " \
		    --entry-text a.b.c.d)
		if [ $? != 0 ]; then
		       return;
		fi
	fi

}

addHost() {
	# Update hosts and ipnodes
        if [[ -z $ipaddr ]]; then
               return;
	fi
	grep "^${ipaddr}[^0-9]" /etc/inet/hosts >/dev/null
	if [ $? -eq 1 ]; then
		echo "$ipaddr\t$hostname" >> /etc/inet/hosts
	fi

	grep "^${ipaddr}[^0-9]" /etc/inet/ipnodes >/dev/null
	if [ $? -eq 1 ]; then
		echo "$ipaddr\t$hostname" >> /etc/inet/ipnodes
	fi

	template=cipso
	updateTnrhdb

	ifconfig $nic $ipaddr netmask + broadcast +
	echo $hostname > /etc/hostname.$nic
}

getTemplate() {
	templates=$(cat /etc/security/tsol/tnrhtp|\
	    grep "^[A-z]"|grep "type=cipso"|cut -f1 -d":")

	while [ 1 -gt 0 ]; do
		t_cmd=$(zenity --list \
		    --title="$title" \
		    --height=300 \
		    --column="Network Templates" \
		    $templates)

		if [ $? != 0 ]; then
		       break;
		fi

		t_label=$(tninfo -t $t_cmd | grep sl|zenity --list \
		    --title="$title" \
		    --height=300 \
		    --width=450 \
		    --column="Click OK to associate $t_cmd template with $ipaddr" )

		if [ $? != 0 ]; then
			continue
		fi
		template=$t_cmd
		updateTnrhdb
		break
	done
}

createInterface() {
	msg=`ifconfig $nic addif 0.0.0.0`
	$(zenity --info \
	    --title="$title" \
	    --text="$msg" )
}

shareInterface() {
	ifconfig $nic all-zones;\
	if_file=/etc/hostname.$nic
	sed q | sed -e "s/$/ all-zones/" < $if_file >/tmp/txnetmgr.$$
	mv /tmp/txnetmgr.$$ $if_file
}

setMacPrivs() {
	zcfg="
set limitpriv=default,win_mac_read,win_mac_write,win_selection,win_dac_read,win_dac_write,file_downgrade_sl,file_upgrade_sl,sys_trans_label
commit
"
	echo "$zcfg" > $config ;
	zonecfg -z $zonename -f $config ;
	rm $config
}

resetMacPrivs() {
	zcfg="
set limitpriv=default
commit
"
	echo "$zcfg" > $config ;
	zonecfg -z $zonename -f $config ;
	rm $config
}

unsharePasswd() {
	for i in `zoneadm list -i | grep -v global`; do
		zonecfg -z $i remove fs dir=/etc/passwd 2>&1 | grep -v such
		zonecfg -z $i remove fs dir=/etc/shadow 2>&1 | grep -v such
	done
}

sharePasswd() {
	if [ $NSCD_PER_LABEL -ne 0 ] ; then
		return
	fi
	passwd=`zonecfg -z $zonename info|grep /etc/passwd`
	if [[ $? -eq 1 ]]; then
		zcfg="
add fs
set special=/etc/passwd
set dir=/etc/passwd
set type=lofs
add options ro
end
add fs
set special=/etc/shadow
set dir=/etc/shadow
set type=lofs
add options ro
end
commit
"
		echo "$zcfg" > $config ;
		zonecfg -z $zonename -f $config ;
		rm $config
	fi
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
		NSCD_PER_LABEL=1
		unsharePasswd
		resolveXdisplay
	else
		export zonename
		rm -f $NSCD_INDICATOR
		NSCD_PER_LABEL=0
		for i in `zoneadm list -i | grep -v global`; do
			zonename=$i
			sharePasswd
		done
		zonename=
	fi
}

manageNets() {
	while [ 1 -gt 0 ]; do
		attrs=
		for i in `ifconfig -au4|grep  "^[a-z].*:" |grep -v LOOPBACK`
		do
			echo $i |grep "^[a-z].*:" >/dev/null 2>&1
			if [ $? -eq 1 ]; then
				continue
			fi
			nic=${i%:} # Remove colon after interface name
			getAttrs
			attrs="$nic $zone $ipaddr $template Up $attrs"
		done

		for i in `ifconfig -ad4 |grep  "^[a-z].*:" |grep -v LOOPBACK`
		do
			echo $i |grep "^[a-z].*:" >/dev/null 2>&1
			if [ $? -eq 1 ]; then
				continue
			fi
			nic=${i%:} # Remove colon after interface name
			getAttrs
			attrs="$nic $zone $ipaddr $template Down $attrs"
		done

		nic=$(zenity --list \
		    --title="$title" \
		    --height=300 \
		    --width=450 \
		    --column="Interface" \
		    --column="Zone Name" \
		    --column="IP Address" \
		    --column="Template" \
		    --column="State" \
		    $attrs)

		if [[ -z $nic ]]; then
			return
		fi

		getAttrs

		# Clear list of commands

		share=
		setipaddr=
		settemplate=
		newlogical=
		unplumb=
		bringup=
		bringdown=

		# Check for physical interface

		hascolon=`echo $nic |grep :`
		if [ $? != 0 ]; then
			newlogical="Create Logical Interface\n";
		else
			up=`echo $flags|grep "UP,"`
			if [ $? != 0 ]; then
				unplumb="Remove Logical Interface\n"
				if [ $ipaddr != "..." ]; then
					bringup="Bring Up\n"
				fi
			else
				bringdown="Bring Down\n"
			fi
		fi

		if [ $ipaddr = "..." ]; then
			setipaddr="Set IP address...\n";
		else
			settemplate="View Templates...\n"
			if [ $zone = global ]; then
				share="Share\n"
			fi
		fi

		command=$(echo ""\
		    $share \
		    $setipaddr \
		    $settemplate \
		    $newlogical \
		    $unplumb \
		    $bringup \
		    $bringdown \
		    | zenity --list \
		    --title="$title" \
		    --height=300 \
		    --column "Interface: $nic" )

		case $command in
		    " Create Logical Interface")\
			createInterface;;
		    " Set IP address...")\
			getIPaddr
			addHost;;
		    " Share")\
			shareInterface;;
		    " View Templates...")\
			getTemplate;;
		    " Remove Logical Interface")\
			ifconfig $nic unplumb;\
			rm -f /etc/hostname.$nic;;
		    " Bring Up")\
			ifconfig $nic up;;
		    " Bring Down")\
			ifconfig $nic down;;
		    *) continue;;
		esac
	done
}

createLDAPclient() {
	ldaptitle="$title: Create LDAP Client"
	ldapdomain=$(zenity --entry \
	    --width=400 \
	    --title="$ldaptitle" \
	    --text="Enter Domain Name: ")
	ldapserver=$(zenity --entry \
	    --width=400 \
	    --title="$ldaptitle" \
	    --text="Enter Hostname of LDAP Server: ")
	ldapserveraddr=$(zenity --entry \
	    --width=400 \
	    --title="$ldaptitle" \
	    --text="Enter IP adddress of LDAP Server $ldapserver: ")
	ldappassword=""
	while [[ -z ${ldappassword} || "x$ldappassword" != "x$ldappasswordconfirm" ]]; do
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
	    "Password" "`echo "$ldappassword" | sed 's/./*/g'`" \
	    "Profile" "$ldapprofile")
	if [ $? != 0 ]; then
		return
	fi

	/bin/grep "^${ldapserveraddr}[^0-9]" /etc/hosts > /dev/null
	if [ $? -eq 1 ]; then
		/bin/echo "$ldapserveraddr $ldapserver" >> /etc/hosts
	fi

	/bin/grep "${ldapserver}:" /etc/security/tsol/tnrhdb > /dev/null
	if [ $? -eq 1 ]; then
		/bin/echo "# ${ldapserver} - ldap server" \
		    >> /etc/security/tsol/tnrhdb
		/bin/echo "${ldapserveraddr}:cipso" \
		    >> /etc/security/tsol/tnrhdb
		/usr/sbin/tnctl -h "${ldapserveraddr}:cipso"
	fi

	proxyDN=`echo $ldapdomain|awk -F"." \
	    "{ ORS = \"\" } { for (i = 1; i < NF; i++) print \"dc=\"\\\$i\",\" }{ print \"dc=\"\\\$NF }"`

	zenity --info \
	    --title="$ldaptitle" \
	    --width=500 \
	    --text="global zone will be LDAP client of $ldapserver"

	ldapout=/tmp/ldapclient.$$

	ldapclient init -a profileName="$ldapprofile" \
	    -a domainName="$ldapdomain" \
	    -a proxyDN"=cn=proxyagent,ou=profile,$proxyDN" \
	    -a proxyPassword="$ldappassword" \
	    "$ldapserveraddr" >$ldapout 2>&1

	if [ $? -eq 0 ]; then
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

# Loop for single-zone menu
singleZone() {

	while [ "${command}" != Exit ]; do
		if [[ ! -n $zonename ]]; then
			x=$(zenity --error \
			    --title="$title" \
			    --text="zonename \"$zonename\" is not valid")
			return
		fi
		# Clear list of commands

		console=
		label=
		start=
		reboot=
		stop=
		clone=
		copy=
		install=
		ready=
		uninstall=
		delete=
		snapshot=
		addnet=
		deletenet=
		permitrelabel=

		zonestate=`zoneadm -z $zonename list -p | cut -d ":" -f 3`

		consoleCheck;
		labelCheck;
		delay=0

		case $zonestate in
			running) ready="Ready\n"; \
			       reboot="Reboot\n"; \
			       stop="Halt\n"; \
			;;
			ready) start="Boot\n"; \
			       stop="Halt\n" \
			;;
			installed)
				if [[ -z $label ]]; then \
					ready="Ready\n"; \
					start="Boot\n"; \
				fi; \
				uninstall="Uninstall\n"; \
				snapshotCheck; \
				relabelCheck;
				addnet="Add Network...\n"
			;;
			configured) install="Install...\n"; \
				copyCheck; \
				delete="Delete\n"; \
				console=; \
			;;
			incomplete) delete="Delete\n"; \
			;;
			*)
			;;
		esac

		command=$(echo ""\
		    $console \
		    $label \
		    $start \
		    $reboot \
		    $stop \
		    $clone \
		    $copy \
		    $install \
		    $ready \
		    $uninstall \
		    $delete \
		    $snapshot \
		    $addnet \
		    $deletenet \
		    $permitrelabel \
		    "Return to Main Menu" \
		    | zenity --list \
		    --title="$title" \
		    --height=300 \
		    --column "$zonename: $zonestate" )

		case $command in
		    " Zone Console...")
			delay=2; \
			/usr/bin/gnome-terminal \
			    --title="Zone Terminal Console: $zonename" \
			    --command "/usr/sbin/zlogin -C $zonename" &;;

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

		    " Clone")
			clone ;;

		    " Copy...")
			copy ;;

		    " Uninstall")
			zoneadm -z $zonename uninstall -F;;

		    " Delete")
			delete
			return ;;

		    " Create Snapshot")
			zfs snapshot $ZDSET/${zonename}@snapshot;;

		    " Add Network...")
			addNet ;;

		    " Permit Relabeling")
			setMacPrivs ;;

		    " Deny Relabeling")
			resetMacPrivs ;;

		    *)
			zonename=
			return ;;
		esac
		sleep $delay;
	done
}

# Main loop for top-level window
#


ZDSET=none
# are there any zfs pools?
zpool iostat 1>/dev/null 2>&1
if [ $? = 0 ]; then
	# is there a zfs pool named "zone"?
	zpool list -H zone 1>/dev/null 2>&1
	if [ $? = 0 ]; then
		# yes
		ZDSET=zone
	else
		# no, but is there a root pool?
		rootfs=`df -n / | awk '{print $3}'`
		if [ $rootfs = "zfs" ]; then
			# yes, use it
			ZDSET=`zfs list -Ho name / | cut -d/ -f 1`/zones
			zfs list -H $ZDSET 1>/dev/null 2>&1
			if [ $? = 1 ]; then
				zfs create -o mountpoint=/zone $ZDSET
			fi
		fi
	fi
fi

export NSCD_OPT
while [ "${command}" != Exit ]; do
	zonelist=""
	for p in `zoneadm list -cp |grep -v global:`; do
		zonename=`echo $p|cut -d : -f2`
		state=`echo $p|cut -d : -f3`
		labelCheck
		zonelist="$zonelist$zonename\n$state\n$curlabel\n"
	done

	if [ $NSCD_PER_LABEL -eq 0 ]  ; then
		NSCD_OPT="Configure per-zone name service"
	else
		NSCD_OPT="Unconfigure per-zone name service"
	fi
	zonelist=${zonelist}"Manage Network Interfaces...\n\n\n"
	zonelist=${zonelist}"Create a new zone...\n\n\n"
	zonelist=${zonelist}"${NSCD_OPT}"
	zonelist=${zonelist}"\n\n\nCreate LDAP Client...\n\n\n"
	zonelist=${zonelist}"Exit\n\n"

	zonename=""
	topcommand=$(echo $zonelist|zenity --list \
	    --title="$title" \
	    --height=300 \
	    --width=500 \
	    --column="Zone Name" \
	    --column="Status" \
	    --column="Sensitivity Label" \
	    )

	if [[ ! -n $topcommand ]]; then
		command=Exit
		exit
	fi

	if [ "$topcommand" = "$NSCD_OPT" ]; then
		topcommand=
		manageNscd
		continue
	elif [ "$topcommand" = "Manage Network Interfaces..." ]; then
		topcommand=
		manageNets
		continue
	elif [ "$topcommand" = "Exit" ]; then
		command=Exit
		exit
	elif [ "$topcommand" = "Create a new zone..." ]; then
		zonename=$(zenity --entry \
		    --title="$title" \
		    --entry-text="" \
		    --text="Enter Zone Name: ")

		if [[ ! -n $zonename ]]; then
			continue
		fi

		zcfg="
create -t SUNWtsoldef
set zonepath=/zone/$zonename
commit
"
		echo "$zcfg" > $config ;
		zonecfg -z $zonename -f $config ;
		rm $config
		# Now, go to the singleZone menu, using the global
		# variable zonename, and continue with zone creation
		singleZone
		continue
	elif [ "$topcommand" = "Create LDAP Client..." ]; then
		command=LDAPclient
		createLDAPclient
		continue
	fi
	# if the menu choice was a zonename, pop up zone menu
	zonename=$topcommand
	singleZone
done
