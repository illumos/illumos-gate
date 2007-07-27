#!/bin/pfksh
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

# This script provides a simple GUI for managing labeled zones.
# It takes no arguments, but provides contextual menus which
# provide appropriate choices. It must be run in the global
# zone as root.

PATH=/usr/bin:/usr/sbin:/usr/lib export PATH
title="Labeled Zone Manager"
maxlabel=`chk_encodings -X 2>/dev/null`
if [[ ! -n $maxlabel ]]; then
	maxlabel=0x000a-08-f8
fi
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
	filesystem=`zfs list |grep zone/$zonename |cut -d " " -f1`
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
		newlabel=`atohexlabel "$alabel" 2>null`
		if [[ -n $newlabel ]]; then
			echo $zonename:$newlabel:0:: >> /etc/security/tsol/tnzonecfg
		else
			x=$(zenity --error \
			    --title="$title" \
			    --text="$alabel is not valid")
		fi
	fi
}

clone() {
	image=`zfs list |grep snapshot|cut -d " " -f1| \
	    zenity --list \
		--title="$title" \
	        --height=300 \
		--column="ZFS Zone Snapshots"`
	if [[ -n $image ]]; then
		dataset=`zfs list |grep zone/$zonename |cut -d " " -f1`
		if [[ -n $dataset ]]; then
			/usr/sbin/zfs destroy zone/$zonename
		fi
		/usr/sbin/zfs clone $image zone/$zonename
		/usr/sbin/zoneadm -z $zonename attach -F
		if [ ! -f /var/ldap/ldap_client_file ]; then
			sharePasswd
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
	    --command "zoneadm -z $zonename clone -m copy $image" 
	    --hide-menubar

	if [ ! -f /var/ldap/ldap_client_file ]; then
		sharePasswd
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
	
	ZONE_PATH=`zoneadm list -cp|grep ":${zonename}:"|cut -d ":" -f4`
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
		sharePasswd
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
}

install() {
	# if there is a zfs pool for zone
	# create a new dataset for the zone
	# This step is done automatically by zonecfg
	# in Solaris Express 8/06 or newer

	zp=`zpool list -H zone 2>/dev/null`
	if [ $? = 0 ]; then
		zfs create zone/$zonename
		chmod 700 /zone/$zonename
	fi

	/usr/bin/gnome-terminal \
	    --title="$title: Installing $zonename zone" \
	    --command "zoneadm -z $zonename install" \
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
	
sharePasswd() {
	passwd=`zonecfg -z $zonename info|grep /etc/passwd`
	if [[ $? -eq 1 ]]; then
		zcfg="
add fs
set special=/etc/passwd
set dir=/etc/passwd
set type=lofs
end
add fs
set special=/etc/shadow
set dir=/etc/shadow
set type=lofs
end
commit
"
		echo "$zcfg" > $config ;
		zonecfg -z $zonename -f $config ;
		rm $config
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

# Main loop for top-level window
#
# Always display vni0 since it is useful for cross-zone networking
#
ifconfig vni0 > /dev/null 2>&1
if [ $? != 0 ]; then
	ifconfig vni0 plumb >/dev/null 2>&1
fi
while [ "${command}" != Exit ]; do
	if [[ ! -n $zonename ]]; then
		zonelist=""
		for p in `zoneadm list -cp|grep -v global:`; do
			zonename=`echo $p|cut -d : -f2`
			state=`echo $p|cut -d : -f3`
			labelCheck
			zonelist="$zonelist$zonename\n$state\n$curlabel\n"
		done

		zonelist="${zonelist}Create a new zone...\n\n\nManage Network Interfaces...\n\n"
		zonename=$(echo $zonelist|zenity --list \
		    --title="$title" \
		    --height=300 \
		    --width=500 \
		    --column="Zone Name" \
		    --column="Status" \
		    --column="Sensitivity Label" \
		    )

		if [[ ! -n $zonename ]]; then
			exit
		fi

		if [ "$zonename" = "Manage Network Interfaces..." ]; then
			zonename=
			manageNets
			continue
		elif [ "$zonename" = "Create a new zone..." ]; then
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
		fi
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
	    "Select another zone...\n" \
	    "Exit" \
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
		delete ;;

	    " Create Snapshot")
		zfs snapshot zone/${zonename}@snapshot;;

	    " Add Network...")
		addNet ;;

	    " Permit Relabeling")
		setMacPrivs ;;

	    " Deny Relabeling")
		resetMacPrivs ;;

	    " Select another zone...")
		zonename= ;;

	    *)
		exit ;;
	esac
	sleep $delay;
done
