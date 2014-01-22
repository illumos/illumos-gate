#!/bin/ksh93 -p
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
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
#
# This script is used to setup the Kerberos client by
# supplying information about the Kerberos realm and kdc.
#
# The kerberos configuration file (/etc/krb5/krb5.conf) would
# be generated and local host's keytab file setup. The script
# can also optionally setup the system to do kerberized nfs and
# bringover a master krb5.conf copy from a specified location.
#

function cleanup {

	kdestroy -q > $TMP_FILE 2>&1
	rm -r $TMPDIR > /dev/null 2>&1

	exit $1
}
function exiting {
	
        printf "\n$(gettext "Exiting setup, nothing changed").\n\n"

	cleanup $1
}

function error_message {

        printf -- "---------------------------------------------------\n" >&2
        printf "$(gettext "Setup FAILED").\n\n" >&2

        cleanup 1
}

function check_bin {

	typeset bin=$1

	if [[ ! -x $bin ]]; then
		printf "$(gettext "Could not access/execute %s").\n" $bin >&2
		error_message
	fi
}

function cannot_create {
	typeset filename="$1"
	typeset stat="$2"

	if [[ $stat -ne 0 ]]; then
		printf "\n$(gettext "Can not create/edit %s, exiting").\n" $filename >&2
		error_message
	fi
}

function update_pam_conf {
	typeset PAM TPAM service

	PAM=/etc/pam.conf

	TPAM=$(mktemp -q -t kclient-pamconf.XXXXXX)
	if [[ -z $TPAM ]]; then
		printf "\n$(gettext "Can not create temporary file, exiting").\n" >&2
		error_message
	fi

	cp $PAM $TPAM >/dev/null 2>&1

	printf "$(gettext "Configuring %s").\n\n" $PAM

	for service in $SVCs; do
		svc=${service%:*}
		auth_type=${service#*:}
		if egrep -s "^$svc[ 	][ 	]*auth.*pam_krb5*" $TPAM; then
			printf "$(gettext "The %s service is already configured for pam_krb5, please merge this service in %s").\n\n" $svc $PAM >&2
			continue
		else
			exec 3>>$TPAM
			printf "\n$svc\tauth include\t\tpam_krb5_$auth_type\n" 1>&3
		fi
	done

	cp $TPAM $PAM > /dev/null 2>&1

	rm $TPAM > /dev/null 2>&1
}

function modify_nfssec_conf {
	typeset NFSSEC_FILE="/etc/nfssec.conf"

	if [[ -r $NFSSEC_FILE ]]; then
		cat $NFSSEC_FILE > $NFSSEC_FILE.sav
		cannot_create $NFSSEC_FILE.sav $?
	fi

	cat $NFSSEC_FILE > $TMP_FILE
	cannot_create $TMP_FILE $?

	if grep -s "#krb5" $NFSSEC_FILE > /dev/null 2>&1; then
		sed "s%^#krb5%krb5%" $TMP_FILE >$NFSSEC_FILE
		cannot_create $NFSSEC_FILE $?
	fi
}

function call_kadmin {
	typeset svc="$1"
	typeset bool1 bool2 bool3 bool4
	typeset service_princ getprincsubcommand anksubcommand ktaddsubcommand
	typeset ktremsubcommand

	for listentry in $fqdnlist; do

	# Reset conditional vars to 1
	bool1=1; bool2=1; bool3=1; bool4=1

	service_princ=$(echo "${svc}/${listentry}")
	getprincsubcommand="getprinc $service_princ"
	anksubcommand="addprinc -randkey $service_princ"
	ktaddsubcommand="ktadd $service_princ"
	ktremsubcommand="ktrem $service_princ all"

	kadmin -c $KRB5CCNAME -q "$getprincsubcommand" 1>$TMP_FILE 2>&1

	egrep -s "$(gettext "get_principal: Principal does not exist")" $TMP_FILE
	bool1=$?
	egrep -s "$(gettext "get_principal: Operation requires ``get")" $TMP_FILE
	bool2=$?

	if [[ $bool1 -eq 0 || $bool2 -eq 0 ]]; then
		kadmin -c $KRB5CCNAME -q "$anksubcommand" 1>$TMP_FILE 2>&1

		egrep -s "$(gettext "add_principal: Principal or policy already exists while creating \"$service_princ@$realm\".")" $TMP_FILE
		bool3=$?

		egrep -s "$(gettext "Principal \"$service_princ@$realm\" created.")" $TMP_FILE
		bool4=$?

		if [[ $bool3 -eq 0 || $bool4 -eq 0 ]]; then
			printf "$(gettext "%s entry ADDED to KDC database").\n" $service_princ
		else
			cat $TMP_FILE;
			printf "\n$(gettext "kadmin: add_principal of %s failed, exiting").\n" $service_princ >&2
			error_message
		fi
	else
		printf "$(gettext "%s entry already exists in KDC database").\n" $service_princ >&2
	fi

	klist -k 1>$TMP_FILE 2>&1
	egrep -s "$service_princ@$realm" $TMP_FILE
	if [[ $? -eq 0 ]]; then
		printf "$(gettext "%s entry already present in keytab").\n" $service_princ >&2
		# Don't care is this succeeds or not, just need to replace old
		# entries as it is assummed that the client is reinitialized
		kadmin -c $KRB5CCNAME -q "$ktremsubcommand" 1>$TMP_FILE 2>&1
	fi

	kadmin -c $KRB5CCNAME -q "$ktaddsubcommand" 1>$TMP_FILE 2>&1
	egrep -s "$(gettext "added to keytab WRFILE:$KRB5_KEYTAB_FILE.")" $TMP_FILE
	if [[ $? -ne 0 ]]; then
		cat $TMP_FILE;
		printf "\n$(gettext "kadmin: ktadd of %s failed, exiting").\n" $service_princ >&2
		error_message
	else
		printf "$(gettext "%s entry ADDED to keytab").\n" $service_princ
	fi

	done
}

function writeup_krb5_conf {
	typeset dh

	printf "\n$(gettext "Setting up %s").\n\n" $KRB5_CONFIG_FILE

	exec 3>$KRB5_CONFIG
	if [[ $? -ne 0 ]]; then
		printf "\n$(gettext "Can not write to %s, exiting").\n" $KRB5_CONFIG >&2
		error_message
	fi

	printf "[libdefaults]\n" 1>&3
	if [[ $no_keytab == yes ]]; then
		printf "\tverify_ap_req_nofail = false\n" 1>&3
	fi
	if [[ $dns_lookup == yes ]]; then
	    printf "\t$dnsarg = on\n" 1>&3
	    if [[ $dnsarg == dns_lookup_kdc ]]; then
		printf "\tdefault_realm = $realm\n" 1>&3
		printf "\n[domain_realm]\n" 1>&3
		if [[ -n $fkdc_list ]]; then
			for kdc in $fkdc_list; do
				printf "\t$kdc = $realm\n" 1>&3
			done
		fi
		printf "\t$FKDC = $realm\n" 1>&3
		printf "\t$client_machine = $realm\n" 1>&3
		if [[ -z $short_fqdn ]]; then
			printf "\t.$domain = $realm\n\n" 1>&3
		else
			printf "\t.$short_fqdn = $realm\n\n" 1>&3
		fi
		if [[ -n $domain_list ]]; then
			for dh in $domain_list; do
				printf "\t$dh = $realm\n" 1>&3
			done
		fi
	    else
		if [[ $dnsarg = dns_lookup_realm ]]; then
		    printf "\tdefault_realm = $realm\n" 1>&3
		    printf "\n[realms]\n" 1>&3
		    printf "\t$realm = {\n" 1>&3
		    if [[ -n $kdc_list ]]; then
			for kdc in $kdc_list; do
				printf "\t\tkdc = $kdc\n" 1>&3
			done
		    else
		    	printf "\t\tkdc = $KDC\n" 1>&3
		    fi
		    printf "\t\tadmin_server = $KDC\n" 1>&3
		    if [[ $non_solaris == yes ]]; then
			printf "\n\t\tkpasswd_protocol = SET_CHANGE\n" 1>&3
		    fi
		    printf "\t}\n\n" 1>&3
		else
		    printf "\tdefault_realm = $realm\n\n" 1>&3
		fi
	    fi
	else
	    printf "\tdefault_realm = $realm\n\n" 1>&3

	    printf "[realms]\n" 1>&3
	    printf "\t$realm = {\n" 1>&3
	    if [[ -n $kdc_list ]]; then
		for kdc in $kdc_list; do
			printf "\t\tkdc = $kdc\n" 1>&3
		done
	    else
	    	printf "\t\tkdc = $KDC\n" 1>&3
	    fi
	    printf "\t\tadmin_server = $KDC\n" 1>&3
	    if [[ $non_solaris == yes ]]; then
	    	printf "\n\t\tkpasswd_protocol = SET_CHANGE\n" 1>&3
	    fi
	    printf "\t}\n\n" 1>&3

	    printf "[domain_realm]\n" 1>&3
	    if [[ -n $fkdc_list ]]; then
		for kdc in $fkdc_list; do
			printf "\t$kdc = $realm\n" 1>&3
		done
	    fi
	    printf "\t$FKDC = $realm\n" 1>&3
	    printf "\t$client_machine = $realm\n" 1>&3
	    if [[ -z $short_fqdn ]]; then
		printf "\t.$domain = $realm\n\n" 1>&3
	    else
		printf "\t.$short_fqdn = $realm\n\n" 1>&3
	    fi
	    if [[ -n $domain_list ]]; then
		for dh in $domain_list; do
			printf "\t$dh = $realm\n" 1>&3
		done
	    fi
	fi

	printf "[logging]\n" 1>&3
	printf "\tdefault = FILE:/var/krb5/kdc.log\n" 1>&3
	printf "\tkdc = FILE:/var/krb5/kdc.log\n" 1>&3
	printf "\tkdc_rotate = {\n\t\tperiod = 1d\n\t\tversions = 10\n\t}\n\n" 1>&3

	printf "[appdefaults]\n" 1>&3
	printf "\tkinit = {\n\t\trenewable = true\n\t\tforwardable = true\n" 1>&3
	if [[ $no_keytab == yes ]]; then
		printf "\t\tno_addresses = true\n" 1>&3
	fi
	printf "\t}\n" 1>&3
}

function ask {
	typeset question=$1
	typeset default_answer=$2

	if [[ -z $default_answer ]]; then
		printf "$question :"
	else
		printf "$question [$default_answer]: "
	fi
	read answer
	test -z "$answer" && answer="$default_answer"
}

function yesno {
	typeset question="$1"

	answer=
	yn=`printf "$(gettext "y/n")"`
	y=`printf "$(gettext "y")"`
	n=`printf "$(gettext "n")"`
	yes=`printf "$(gettext "yes")"`
	no=`printf "$(gettext "no")"`

	while [[ -z $answer ]]; do
		ask "$question" $yn
		case $answer in
			$y|$yes)	answer=yes;;
			$n|$no)		answer=no;;
			*)		answer=;;
		esac
	done
}

function query {
	yesno "$*"

	if [[ $answer == no ]]; then
		printf "\t$(gettext "No action performed").\n"
	fi
}


function read_profile {
	typeset param value
	typeset file="$1"

	if [[ ! -d $file && -r $file ]]; then
		while read param value
		do
			case $param in
			REALM)  if [[ -z $realm ]]; then
					realm="$value"
					checkval="REALM"; check_value $realm
				fi
				;;
			KDC)    if [[ -z $KDC ]]; then
					KDC="$value"
					checkval="KDC"; check_value $KDC
				fi
				;;
			ADMIN)  if [[ -z $ADMIN_PRINC ]]; then
					ADMIN_PRINC="$value"
					checkval="ADMIN_PRINC"
    					check_value $ADMIN_PRINC
				fi
				;;
			FILEPATH)  if [[ -z $filepath ]]; then
					filepath="$value"
				   fi
				   ;;
			NFS)    if [[ -z $add_nfs ]]; then
				    if [[ $value == 1 ]]; then
					    add_nfs=yes
				    else
					    add_nfs=no
				    fi
				fi
				;;
			NOKEY)    if [[ -z $no_keytab ]]; then
				    if [[ $value == 1 ]]; then
					    no_keytab=yes
				    else
					    no_keytab=no
				    fi
				fi
				;;
			NOSOL)  if [[ -z $non_solaris ]]; then
				    if [[ $value == 1 ]]; then
					    non_solaris=yes
					    no_keytab=yes
				    else
					    non_solaris=no
				    fi
				fi
				;;
			LHN)    if [[ -z $logical_hn ]]; then
					logical_hn="$value"
					checkval="LOGICAL_HOSTNAME"
    					check_value $logical_hn
				fi
				;;
			DNSLOOKUP) if [[ -z $dnsarg ]]; then
					dnsarg="$value"
					checkval="DNS_OPTIONS"
					check_value $dnsarg
				   fi
				   ;;
			FQDN) if [[ -z $fqdnlist ]]; then
					fqdnlist="$value"
					checkval="FQDN"
					check_value $fqdnlist
					verify_fqdnlist "$fqdnlist"
			      fi
			      ;;
			MSAD) if [[ -z $msad ]]; then
				if [[ $value == 1 ]]; then
					msad=yes
					non_solaris=yes
				else
					msad=no
				fi
			      fi
			      ;;
			esac
		done <$file
	else
		printf "\n$(gettext "The kclient profile \`%s' is not valid, exiting").\n" $file >&2
		error_message
	fi
}

function ping_check {
	typeset machine="$1"
	typeset string="$2"

	if ping $machine 2 > /dev/null 2>&1; then
		:
	else
		printf "\n$(gettext "%s %s is unreachable, exiting").\n" $string $machine >&2
		error_message
	fi

	# Output timesync warning if not using a profile, i.e. in
	# interactive mode.
	if [[ -z $profile && $string == KDC ]]; then
		# It's difficult to sync up time with KDC esp. if in a
		# zone so just print a warning about KDC time sync.
		printf "\n$(gettext "Note, this system and the KDC's time must be within 5 minutes of each other for Kerberos to function").\n" >&2
		printf "$(gettext "Both systems should run some form of time synchronization system like Network Time Protocol (NTP)").\n" >&2
break
	fi
}

function check_value {
	typeset arg="$1"

	if [[ -z $arg ]]; then
		printf "\n$(gettext "No input obtained for %s, exiting").\n" $checkval >&2
		error_message
	else
		echo "$arg" > $TMP_FILE
		if egrep -s '[*$^#!]+' $TMP_FILE; then
			printf "\n$(gettext "Invalid input obtained for %s, exiting").\n" $checkval >&2
			error_message
		fi
	fi
}

function set_dns_value {
	typeset -l arg="$1"

	if [[ $arg == dns_lookup_kdc  ||  $arg == dns_lookup_realm  || $arg == dns_fallback ]]; then
		dns_lookup=yes
	else
		if [[ $arg == none ]]; then
			dns_lookup=no
		else
			printf "\n$(gettext "Invalid DNS lookup option, exiting").\n" >&2
			error_message
		fi
	fi
}

function verify_kdcs {
	typeset k_list="$1"
	typeset -l kdc
	typeset list fqhn f_list

	kdc_list=$(echo "$k_list" | sed 's/,/ /g')

	if [[ -z $k_list ]]; then
		printf "\n$(gettext "At least one KDC should be listed").\n\n" >&2
		usage
	fi

	for kdc in $k_list; do
		if [[ $kdc != $KDC ]]; then
			list="$list $kdc"
			fkdc=`$KLOOKUP $kdc`
			if ping $fkdc 2 > /dev/null; then
				:
			else
				printf "\n$(gettext "%s %s is unreachable, no action performed").\n" "KDC" $fkdc >&2
			fi
			f_list="$f_list $fkdc"
		fi
	done

	fkdc_list="$f_list"
	kdc_list="$list"
}

function parse_service {
	typeset service_list=$1

	service_list=${service_list//,/ }
	for service in $service_list; do
		svc=${service%:}
		auth_type=${service#:}
		[[ -z $svc || -z $auth_type ]] && return
		print -- $svc $auth_type
	done
}

function verify_fqdnlist {
	typeset list="$1"
	typeset -l hostname
	typeset -i count=1
	typeset fqdnlist eachfqdn tmpvar fullhost

	list=$(echo "$list" | tr -d " " | tr -d "\t")
	hostname=$(uname -n | cut -d"." -f1)
	fqdnlist=$client_machine

	eachfqdn=$(echo "$list" | cut -d"," -f$count)
	if [[ -z $eachfqdn ]]; then
		printf "\n$(gettext "If the -f option is used, at least one FQDN should be listed").\n\n" >&2
		usage
	else
		while [[ ! -z $eachfqdn ]]; do
			tmpvar=$(echo "$eachfqdn" | cut -d"." -f1)
			if [[ -z $tmpvar ]]; then
				fullhost="$hostname$eachfqdn"
			else
				fullhost="$hostname.$eachfqdn"
			fi

			ping_check $fullhost $(gettext "System")
			if [[ $fullhost == $client_machine ]]; then
				:
			else
				fqdnlist="$fqdnlist $fullhost"
			fi

			if [[ $list == *,* ]]; then
				((count = count + 1))
				eachfqdn=$(echo "$list" | cut -d"," -f$count)
			else
				break
			fi
		done
	fi
}

function setup_keytab {
	typeset cname ask_fqdns current_release

	#
	# 1. kinit with ADMIN_PRINC
	#

	if [[ -z $ADMIN_PRINC ]]; then
		printf "\n$(gettext "Enter the krb5 administrative principal to be used"): "
		read ADMIN_PRINC
		checkval="ADMIN_PRINC"; check_value $ADMIN_PRINC
	fi

	echo "$ADMIN_PRINC">$TMP_FILE

	[[ -n $msad ]] && return
	if egrep -s '\/admin' $TMP_FILE; then
		# Already in "/admin" format, do nothing
		:
	else
		if egrep -s '\/' $TMP_FILE; then
			printf "\n$(gettext "Improper entry for krb5 admin principal, exiting").\n" >&2
			error_message
		else
			ADMIN_PRINC=$(echo "$ADMIN_PRINC/admin")
		fi
	fi

	printf "$(gettext "Obtaining TGT for %s") ...\n" $ADMIN_PRINC

	cname=$(canon_resolve $KDC)
	if [[ -n $cname ]]; then
		kinit -S kadmin/$cname $ADMIN_PRINC
	else
		kinit -S kadmin/$FKDC $ADMIN_PRINC
	fi
	klist 1>$TMP_FILE 2>&1
	if egrep -s "$(gettext "Valid starting")" $TMP_FILE && egrep -s "kadmin/$FKDC@$realm" $TMP_FILE; then
    		:
	else
		printf "\n$(gettext "kinit of %s failed, exiting").\n" $ADMIN_PRINC >&2
		error_message
	fi

	#
	# 2. Do we want to create and/or add service principal(s) for fqdn's
	#    other than the one listed in resolv.conf(4) ?
	#
	if [[ -z $options ]]; then
		query "$(gettext "Do you have multiple DNS domains spanning the Kerberos realm") $realm ?"
		ask_fqdns=$answer
		if [[ $ask_fqdns == yes ]]; then
			printf "$(gettext "Enter a comma-separated list of DNS domain names"): "
			read fqdnlist
			verify_fqdnlist "$fqdnlist"
		else
			fqdnlist=$client_machine
		fi
	else
		if [[ -z $fqdnlist ]]; then
			fqdnlist=$client_machine
		fi
	fi

	if [[ $add_nfs == yes ]]; then
		echo; call_kadmin nfs
	fi

	# Add the host entry to the keytab
	echo; call_kadmin host

}

function setup_lhn {
	typeset -l logical_hn

	echo "$logical_hn" > $TMP_FILE
	if egrep -s '[^.]\.[^.]+$' $TMP_FILE; then
		# do nothing, logical_hn is in fqdn format
		:
	else
		if egrep -s '\.+' $TMP_FILE; then
			printf "\n$(gettext "Improper format of logical hostname, exiting").\n" >&2
			error_message
		else
			# Attach fqdn to logical_hn, to get the Fully Qualified
			# Host Name of the client requested
			logical_hn=$(echo "$logical_hn.$fqdn")
		fi
	fi

	client_machine=$logical_hn

	ping_check $client_machine $(gettext "System")
}

function usage {
	printf "\n$(gettext "Usage: kclient [ options ]")\n" >&2
	printf "\t$(gettext "where options are any of the following")\n\n" >&2
	printf "\t$(gettext "[ -D domain_list ]  configure a client that has mul
tiple mappings of doamin and/or hosts to the default realm")\n" >&2
	printf "\t$(gettext "[ -K ]  configure a client that does not have host/service keys")\n" >&2
	printf "\t$(gettext "[ -R realm ]  specifies the realm to use")\n" >&2
	printf "\t$(gettext "[ -T kdc_vendor ]  specifies which KDC vendor is the server")\n" >&2
	printf "\t$(gettext "[ -a adminuser ]  specifies the Kerberos administrator")\n" >&2
	printf "\t$(gettext "[ -c filepath ]  specifies the krb5.conf path used to configure this client")\n" >&2
	printf "\t$(gettext "[ -d dnsarg ]  specifies which information should be looked up in DNS (dns_lookup_kdc, dns_lookup_realm, and dns_fallback)")\n" >&2
	printf "\t$(gettext "[ -f fqdn_list ]  specifies which domains to configure host keys for this client")\n" >&2
	printf "\t$(gettext "[ -h logicalhostname ]  configure the logical host name for a client that is in a cluster")\n" >&2
	printf "\t$(gettext "[ -k kdc_list ]  specify multiple KDCs, if -m is not used the first KDC in the list is assumed to be the master.  KDC host names are used verbatim.")\n" >&2
	printf "\t$(gettext "[ -m master ]  master KDC server host name")\n" >&2
	printf "\t$(gettext "[ -n ]  configure client to be an NFS client")\n" >&2
	printf "\t$(gettext "[ -p profile ]  specifies which profile file to use to configure this client")\n" >&2
	printf "\t$(gettext "[ -s pam_list ]  update the service for Kerberos authentication")\n" >&2
	error_message
}

function discover_domain {
	typeset dom DOMs

	if [[ -z $realm ]]; then
		set -A DOMs -- `$KLOOKUP _ldap._tcp.dc._msdcs S`
	else
		set -A DOMs -- `$KLOOKUP _ldap._tcp.dc._msdcs.$realm S`
	fi

	[[ -z ${DOMs[0]} ]] && return 1

	dom=${DOMs[0]}

	dom=${dom#*.}
	dom=${dom% *}

	domain=$dom

	return 0
}

function check_nss_hosts_or_ipnodes_config {
	typeset backend

	for backend in $1
	do
		[[ $backend == dns ]] && return 0
	done
	return 1
}

function check_nss_conf {
	typeset i j hosts_config

	for i in hosts ipnodes
	do
		grep "^${i}:" /etc/nsswitch.conf|read j hosts_config
		check_nss_hosts_or_ipnodes_config "$hosts_config" || return 1
	done

	return 0
}

function canon_resolve {
	typeset name ip

	name=`$KLOOKUP $1 C`
	[[ -z $name ]] && name=`$KLOOKUP $1 A`
	[[ -z $name ]] && return

	ip=`$KLOOKUP $name I`
	[[ -z $ip ]] && return
	for i in $ip
	do
		if ping $i 2 > /dev/null 2>&1; then
			break
		else
			i=
		fi
	done

	cname=`$KLOOKUP $ip P`
	[[ -z $cname ]] && return

	print -- "$cname"
}

function rev_resolve {
	typeset name ip

	ip=`$KLOOKUP $1 I`

	[[ -z $ip ]] && return
	name=`$KLOOKUP $ip P`
	[[ -z $name ]] && return

	print -- $name
}

# Convert an AD-style domain DN to a DNS domainname
function dn2dns {
	typeset OIFS dname dn comp components

	dn=$1
	dname=

	OIFS="$IFS"
	IFS=,
	set -A components -- $1
	IFS="$OIFS"

	for comp in "${components[@]}"
	do
		[[ "$comp" == [dD][cC]=* ]] || continue
		dname="$dname.${comp#??=}"
	done

	print ${dname#.}
}

# Form a base DN from a DNS domainname and container
function getBaseDN {
	if [[ -n "$2" ]]
	then
		baseDN="CN=$1,$(dns2dn $2)"
	else
		baseDN="$(dns2dn $2)"
	fi
}

# Convert a DNS domainname to an AD-style DN for that domain
function dns2dn {
	typeset OIFS dn labels

	OIFS="$IFS"
	IFS=.
	set -A labels -- $1
	IFS="$OIFS"

	dn=
	for label in "${labels[@]}"
	do
		dn="${dn},DC=$label"
	done

	print -- "${dn#,}"
}

function getSRVs {
	typeset srv port

	$KLOOKUP $1 S | while read srv port
	do
		if ping $srv 2 > /dev/null 2>&1; then
			print -- $srv $port
		fi
	done
}

function getKDC {
	typeset j

	set -A KPWs -- $(getSRVs _kpasswd._tcp.$dom.)
	kpasswd=${KPWs[0]}

	if [[ -n $siteName ]]
	then
		set -A KDCs -- $(getSRVs _kerberos._tcp.$siteName._sites.$dom.)
		kdc=${KDCs[0]}
		[[ -n $kdc ]] && return
	fi

	# No site name
	set -A KDCs -- $(getSRVs _kerberos._tcp.$dom.)
	kdc=${KDCs[0]}
	[[ -n $kdc ]] && return

	# Default
	set -A KDCs -- $DomainDnsZones 88
	kdc=$ForestDnsZones
}

function getDC {
	typeset j

	if [[ -n $siteName ]]
	then
		set -A DCs -- $(getSRVs _ldap._tcp.$siteName._sites.dc._msdcs.$dom.)
		dc=${DCs[0]}
		[[ -n $dc ]] && return
	fi

	# No site name
	set -A DCs -- $(getSRVs _ldap._tcp.dc._msdcs.$dom.)
	dc=${DCs[0]}
	[[ -n $dc ]] && return

	# Default
	set -A DCs -- $DomainDnsZones 389
	dc=$DomainDnsZones
}

function write_ads_krb5conf {
	typeset kdcs

	printf "\n$(gettext "Setting up %s").\n\n" $KRB5_CONFIG_FILE

	for i in ${KDCs[@]}
	do
		[[ $i == +([0-9]) ]] && continue
		if [[ -n $kdcs ]]
		then
			kdcs="$kdcs,$i"
		else
			kdcs=$i
		fi
	done

	$KCONF -f $KRB5_CONFIG -r $realm -k $kdcs -m $KDC -p SET_CHANGE -d .$dom

	if [[ $? -ne 0 ]]; then
		printf "\n$(gettext "Can not update %s, exiting").\n" $KRB5_CONFIG >&2
		error_message
	fi
}

function getForestName {
	ldapsearch -R -T -h $dc $ldap_args \
	    -b "" -s base "" schemaNamingContext| \
		grep ^schemaNamingContext|read j schemaNamingContext

	if [[ $? -ne 0 ]]; then
		printf "$(gettext "Can't find forest").\n" >&2
		error_message
	fi
	schemaNamingContext=${schemaNamingContext#CN=Schema,CN=Configuration,}

	[[ -z $schemaNamingContext ]] && return 1

	forest=
	while [[ -n $schemaNamingContext ]]
	do
		schemaNamingContext=${schemaNamingContext#DC=}
		forest=${forest}.${schemaNamingContext%%,*}
		[[ "$schemaNamingContext" = *,* ]] || break
		schemaNamingContext=${schemaNamingContext#*,}
	done
	forest=${forest#.}
}

function getGC {
	typeset j

	[[ -n $gc ]] && return 0

	if [[ -n $siteName ]]
	then
		set -A GCs -- $(getSRVs _ldap._tcp.$siteName._sites.gc._msdcs.$forest.)
		gc=${GCs[0]}
		[[ -n $gc ]] && return
	fi

	# No site name
	set -A GCs -- $(getSRVs _ldap._tcp.gc._msdcs.$forest.)
	gc=${GCs[0]}
	[[ -n $gc ]] && return

	# Default
	set -A GCs -- $ForestDnsZones 3268
	gc=$ForestDnsZones
}

#
# The local variables used to calculate the IP address are of type unsigned
# integer (-ui), as this is required to restrict the integer to 32b.
# Starting in ksh88, Solaris has incorrectly assummed that -i represents 64b.
#
function ipAddr2num {
	typeset OIFS
	typeset -ui16 num

	if [[ "$1" != +([0-9]).+([0-9]).+([0-9]).+([0-9]) ]]
	then
		print 0
		return 0
	fi

	OIFS="$IFS"
	IFS=.
	set -- $1
	IFS="$OIFS"

	num=$((${1}<<24 | ${2}<<16 | ${3}<<8 | ${4}))

	print -- $num
}

#
# The local variables used to calculate the IP address are of type unsigned
# integer (-ui), as this is required to restrict the integer to 32b.
# Starting in ksh88, Solaris has incorrectly assummed that -i represents 64b.
#
function num2ipAddr {
	typeset -ui16 num
	typeset -ui10 a b c d

	num=$1
	a=$((num>>24        ))
	b=$((num>>16 & 16#ff))
	c=$((num>>8  & 16#ff))
	d=$((num     & 16#ff))
	print -- $a.$b.$c.$d
}

#
# The local variables used to calculate the IP address are of type unsigned
# integer (-ui), as this is required to restrict the integer to 32b.
# Starting in ksh88, Solaris has incorrectly assummed that -i represents 64b.
#
function netmask2length {
	typeset -ui16 netmask
	typeset -i len

	netmask=$1
	len=32
	while [[ $((netmask % 2)) -eq 0 ]]
	do
		netmask=$((netmask>>1))
		len=$((len - 1))
	done
	print $len
}

#
# The local variables used to calculate the IP address are of type unsigned
# integer (-ui), as this is required to restrict the integer to 32b.
# Starting in ksh88, Solaris has incorrectly assummed that -i represents 64b.
#
function getSubnets {
	typeset -ui16 addr netmask
	typeset -ui16 classa=16\#ff000000

	ifconfig -a|while read line
	do
		addr=0
		netmask=0
		set -- $line
		[[ $1 == inet ]] || continue
		while [[ $# -gt 0 ]]
		do
			case "$1" in
				inet) addr=$(ipAddr2num $2); shift;;
				netmask) eval netmask=16\#$2; shift;;
				*) :;
			esac
			shift
		done

		[[ $addr -eq 0 || $netmask -eq 0 ]] && continue
		[[ $((addr & classa)) -eq 16\#7f000000 ]] && continue

		print $(num2ipAddr $((addr & netmask)))/$(netmask2length $netmask)
	done
}

function getSite {
	typeset subnet siteDN j ldapsrv subnet_dom

	eval "[[ -n \"\$siteName\" ]]" && return
	for subnet in $(getSubnets)
	do
		ldapsearch -R -T -h $dc $ldap_args \
		    -p 3268 -b "" -s sub cn=$subnet dn |grep ^dn|read j subnetDN

		[[ -z $subnetDN ]] && continue
		subnet_dom=$(dn2dns $subnetDN)
		ldapsrv=$(canon_resolve DomainDnsZones.$subnet_dom)
		[[ -z $ldapsrv ]] && continue
		ldapsearch -R -T -h $ldapsrv $ldap_args \
		    -b "$subnetDN" -s base "" siteObject \
		    |grep ^siteObject|read j siteDN

		[[ -z $siteDN ]] && continue

		eval siteName=${siteDN%%,*}
		eval siteName=\${siteName#CN=}
		return
	done
}

function doKRB5config {
	[[ -f $KRB5_CONFIG_FILE ]] && \
		cp $KRB5_CONFIG_FILE ${KRB5_CONFIG_FILE}-pre-kclient

	[[ -f $KRB5_KEYTAB_FILE ]] && \
		cp $KRB5_KEYTAB_FILE ${KRB5_KEYTAB_FILE}-pre-kclient

	[[ -s $KRB5_CONFIG ]] && cp $KRB5_CONFIG $KRB5_CONFIG_FILE
	[[ -s $KRB5_CONFIG_FILE ]] && chmod 0644 $KRB5_CONFIG_FILE
	[[ -s $new_keytab ]] && cp $new_keytab $KRB5_KEYTAB_FILE
	[[ -s $KRB5_KEYTAB_FILE ]] && chmod 0600 $KRB5_KEYTAB_FILE
}

function addDNSRR {
	smbFMRI=svc:/network/smb/server:default
	ddnsProp=smbd/ddns_enable
	enProp=general/enabled

	enabled=`svcprop -p $enProp $smbFMRI`
	ddns_enable=`svcprop -p $ddnsProp $smbFMRI`

	if [[ $enabled == true && $ddns_enable != true ]]; then
		printf "$(gettext "Warning: won't create DNS records for client").\n"
		printf "$(gettext "%s property not set to 'true' for the %s FMRI").\n" $ddnsProp $smbFMRI
		return
	fi
	
	# Destroy any existing ccache as GSS_C_NO_CREDENTIAL will pick up any
	# residual default credential in the cache.
	kdestroy > /dev/null 2>&1

	$KDYNDNS -d $1 > /dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		#
		# Non-fatal, we should carry-on as clients may resolve to
		# different servers and the client could already exist there.
		#
		printf "$(gettext "Warning: unable to create DNS records for client").\n"
		printf "$(gettext "This could mean that '%s' is not included as a 'nameserver' in the /etc/resolv.conf file or some other type of error").\n" $dc
	fi
}

function setSMB {
	typeset domain=$1
	typeset server=$2
	smbFMRI=svc:/network/smb/server

	printf "%s" "$newpw" | $KSMB -d $domain -s $server
	if [[ $? -ne 0 ]]; then
		printf "$(gettext "Warning: unable to set %s domain, server and password information").\n" $smbFMRI
		return
	fi

	svcadm restart $smbFMRI > /dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		printf "$(gettext "Warning: unable to restart %s").\n" $smbFMRI
	fi
}

function compareDomains {
	typeset oldDom hspn newDom=$1

	# If the client has been previously configured in a different
	# realm/domain then we need to prompt the user to see if they wish to
	# switch domains.
	klist -k 2>&1 | grep @ | read j hspn
	[[ -z $hspn ]] && return

	oldDom=${hspn#*@}
	if [[ $oldDom != $newDom ]]; then
		printf "$(gettext "The client is currently configured in a different domain").\n"
		printf "$(gettext "Currently in the '%s' domain, trying to join the '%s' domain").\n" $oldDom $newDom
		query "$(gettext "Do you want the client to join a new domain") ?"
		printf "\n"
		if [[ $answer != yes ]]; then
			printf "$(gettext "Client will not be joined to the new domain").\n" >&2
			error_message
		fi
	fi
}

function getKDCDC {

	getKDC
	if [[ -n $kdc ]]; then
		KDC=$kdc
		dc=$kdc
	else
		getDC
		if [[ -n $dc ]]; then
			KDC=$dc
		else
			printf "$(gettext "Could not find domain controller server for '%s'.  Exiting").\n" $realm >&2
			error_message
		fi
	fi
}

function gen_rand {
	typeset -u hex

	dd if=/dev/random bs=1 count=1 2>/dev/null | od -A n -tx1 | read hex

	printf %s $((16#$hex))
}

function join_domain {
	typeset -u upcase_nodename
	typeset -l locase_nodename
	typeset -L15 string15
	typeset netbios_nodename fqdn
	
	container=Computers
	ldap_args="-o authzid= -o mech=gssapi"
	userAccountControlBASE=4096

	if [[ -z $ADMIN_PRINC ]]; then
		cprinc=Administrator
	else
		cprinc=$ADMIN_PRINC
	fi

	if ! discover_domain; then
		printf "$(gettext "Can not find realm") '%s'.\n" $realm >&2
		error_message
	fi

	dom=$domain
	realm=$domain

	if [[ ${#hostname} -gt 15 ]]; then
		string15=$hostname
		upcase_nodename=$string15
		locase_nodename=$string15
	else
		upcase_nodename=$hostname
		locase_nodename=$hostname
	fi

	netbios_nodename="${upcase_nodename}\$"
	fqdn=$hostname.$domain
	upn=host/${fqdn}@${realm}

	object=$(mktemp -q -t kclient-computer-object.XXXXXX)
	if [[ -z $object ]]; then
		printf "\n$(gettext "Can not create temporary file, exiting").\n
" >&2
		error_message
        fi

	modify_existing=false
	recreate=false

	DomainDnsZones=$(rev_resolve DomainDnsZones.$dom.)
	ForestDnsZones=$(rev_resolve ForestDnsZones.$dom.)

	getBaseDN "$container" "$dom"

	if [[ -n $KDC ]]; then
		dc=$KDC
	else
		getKDCDC
	fi

	write_ads_krb5conf

	printf "$(gettext "Attempting to join '%s' to the '%s' domain").\n\n" $upcase_nodename $realm

	kinit $cprinc@$realm
	if [[ $? -ne 0 ]]; then
		printf "$(gettext "Could not authenticate %s.  Exiting").\n" $cprinc@$realm >&2
		error_message
	fi

	if getForestName
	then
		printf "\n$(gettext "Forest name found: %s")\n\n" $forest
	else
		printf "\n$(gettext "Forest name not found, assuming forest is the domain name").\n"
	fi

	getGC
	getSite

	if [[ -z $siteName ]]
	then
    		printf "$(gettext "Site name not found.  Local DCs/GCs will not be discovered").\n\n"
	else
    		printf "$(gettext "Looking for _local_ KDCs, DCs and global catalog servers (SRV RRs)").\n"
		getKDCDC
		getGC

		write_ads_krb5conf
	fi

	if [[ ${#GCs} -eq 0 ]]; then
		printf "$(gettext "Could not find global catalogs.  Exiting").\n" >&2
		error_message
	fi

	# Check to see if the client is transitioning between domains.
	compareDomains $realm

	# Here we check domainFunctionality to see which release:
	# 0, 1, 2: Windows 2000, 2003 Interim, 2003 respecitively
	# 3: Windows 2008
	level=0
	ldapsearch -R -T -h "$dc" $ldap_args -b "" -s base "" \
	 domainControllerFunctionality| grep ^domainControllerFunctionality| \
	 read j level
	if [[ $? -ne 0 ]]; then
		printf "$(gettext "Search for domain functionality failed, exiting").\n" >&2
		error_message
	fi

	if ldapsearch -R -T -h "$dc" $ldap_args -b "$baseDN" \
	    -s sub sAMAccountName="$netbios_nodename" dn > /dev/null 2>&1
	then
		:
	else
		printf "$(gettext "Search for node failed, exiting").\n" >&2
		error_message
	fi
	ldapsearch -R -T -h "$dc" $ldap_args -b "$baseDN" -s sub \
	    sAMAccountName="$netbios_nodename" dn|grep "^dn:"|read j dn

	if [[ -z $dn ]]; then
		: # modify_existing is already false, which is what we want.
	else
		printf "$(gettext "Computer account '%s' already exists in the '%s' domain").\n" $upcase_nodename $realm
		query "$(gettext "Do you wish to recreate this computer account") ?"
		printf "\n"
		if [[ $answer == yes ]]; then
			recreate=true
		else
			modify_existing=true
		fi
	fi

	if [[ $modify_existing == false && -n $dn ]]; then
		query "$(gettext "Would you like to delete any sub-object found for this computer account") ?"
		if [[ $answer == yes ]]; then
			printf "$(gettext "Looking to see if the machine account contains other objects")...\n"
			ldapsearch -R -T -h "$dc" $ldap_args -b "$dn" -s sub "" dn | while read j sub_dn
			do
				[[ $j != dn: || -z $sub_dn || $dn == $sub_dn ]] && continue
				if $recreate; then
					printf "$(gettext "Deleting the following object: %s")\n" ${sub_dn#$dn}
					ldapdelete -h "$dc" $ldap_args "$sub_dn" > /dev/null 2>&1
					if [[ $? -ne 0 ]]; then
						printf "$(gettext "Error in deleting object: %s").\n" ${sub_dn#$dn}
					fi
				else
					printf "$(gettext "The following object will not be deleted"): %s\n" ${sub_dn#$dn}
				fi
			done
		fi

		if $recreate; then
			ldapdelete -h "$dc" $ldap_args "$dn" > /dev/null 2>&1
			if [[ $? -ne 0 ]]; then
				printf "$(gettext "Error in deleting object: %s").\n" ${sub_dn#$dn} >&2
				error_message
			fi
		elif $modify_existing; then
			: # Nothing to delete
		else
			printf "$(gettext "A machine account already exists").\n" >&2
			error_message
		fi
	fi

	[[ -z $dn ]] && dn="CN=${upcase_nodename},${baseDN}"
	if $modify_existing; then
		cat > "$object" <<EOF
dn: $dn
changetype: modify
replace: userPrincipalName
userPrincipalName: $upn
-
replace: servicePrincipalName
servicePrincipalName: host/${fqdn}
-
replace: userAccountControl
userAccountControl: $((userAccountControlBASE + 32 + 2))
-
replace: dNSHostname
dNSHostname: ${fqdn}
EOF

		printf "$(gettext "A machine account already exists; updating it").\n"
		ldapadd -h "$dc" $ldap_args -f "$object" > /dev/null 2>&1
		if [[ $? -ne 0 ]]; then
			printf "$(gettext "Failed to modify the AD object via LDAP").\n" >&2
			error_message
		fi
	else
		dn="CN=${upcase_nodename},${baseDN}"
		cat > "$object" <<EOF
dn: $dn
objectClass: computer
cn: $upcase_nodename
sAMAccountName: ${netbios_nodename}
userPrincipalName: $upn
servicePrincipalName: host/${fqdn}
userAccountControl: $((userAccountControlBASE + 32 + 2))
dNSHostname: ${fqdn}
EOF

		printf "$(gettext "Creating the machine account in AD via LDAP").\n\n"

		ldapadd -h "$dc" $ldap_args -f "$object" > /dev/null 2>&1
		if [[ $? -ne 0 ]]; then
			printf "$(gettext "Failed to create the AD object via LDAP").\n" >&2
			error_message
		fi
	fi

	# Generate a new password for the new account
	MAX_PASS=120
        i=0

	# first check to see if /dev/random exists to generate a new password
	if [[ ! -h /dev/random ]]; then
		printf "$(gettext "/dev/random does not exist").\n" >&2
		error_message
	fi

	while ((MAX_PASS > i))
	do
		# [MS-DISO] A machine password is an ASCII string of randomly
		# chosen characters. Each character's ASCII code is between 32
		# and 122 inclusive.
		c=$(printf "\\$(printf %o $(($(gen_rand) % 91 + 32)))\n")
		p="$p$c"
		((i+=1))
	done

	newpw=$p
	if [[ ${#newpw} -ne MAX_PASS ]]; then
		printf "$(gettext "Password created was of incorrect length").\n" >&2
		error_message
	fi

	# Set the new password
	printf "%s" "$newpw" | $KSETPW ${netbios_nodename}@${realm} > /dev/null 2>&1
	if [[ $? -ne 0 ]]
	then
		printf "$(gettext "Failed to set account password").\n" >&2
		error_message
	fi

	# Lookup the new principal's kvno:
	ldapsearch -R -T -h "$dc" $ldap_args -b "$baseDN" \
		 -s sub cn=$upcase_nodename msDS-KeyVersionNumber| \
		grep "^msDS-KeyVersionNumber"|read j kvno
	[[ -z $kvno ]] && kvno=1

	# Set supported enctypes.  This only works for Longhorn/Vista, so we
	# ignore errors here.
	userAccountControl=$((userAccountControlBASE + 524288 + 65536))
	set -A enctypes --

	# Do we have local support for AES?
	encrypt -l|grep ^aes|read j minkeysize maxkeysize
	val=
	if [[ $maxkeysize -eq 256 ]]; then
		val=16
		enctypes[${#enctypes[@]}]=aes256-cts-hmac-sha1-96
	fi
	if [[ $minkeysize -eq 128 ]]; then
		((val=val+8))
		enctypes[${#enctypes[@]}]=aes128-cts-hmac-sha1-96
	fi

	# RC4 comes next (whether it's better than 1DES or not -- AD prefers it)
	if encrypt -l|grep -q ^arcfour
	then
		((val=val+4))
		enctypes[${#enctypes[@]}]=arcfour-hmac-md5
	else
		# Use 1DES ONLY if we don't have arcfour
		userAccountControl=$((userAccountControl + 2097152))
	fi
	if encrypt -l | grep -q ^des
	then
		((val=val+2))
		enctypes[${#enctypes[@]}]=des-cbc-md5
	fi

	if [[ ${#enctypes[@]} -eq 0 ]]
	then
		printf "$(gettext "No enctypes are supported").\n"
		printf "$(gettext "Please enable arcfour or 1DES, then re-join; see cryptoadm(1M)").\n" >&2
		error_message
	fi

	# If domain crontroller is Longhorn or above then set new supported
	# encryption type attributes.
	if [[ $level -gt 2 ]]; then
		cat > "$object" <<EOF
dn: $dn
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: $val
EOF
		ldapmodify -h "$dc" $ldap_args -f "$object" >/dev/null 2>&1
		if [[ $? -ne 0 ]]; then
			printf "$(gettext "Warning: Could not set the supported encryption type for computer account").\n"
		fi
	fi

	# We should probably check whether arcfour is available, and if not,
	# then set the 1DES only flag, but whatever, it's not likely NOT to be
	# available on S10/Nevada!

	# Reset userAccountControl
	#
	#  NORMAL_ACCOUNT (512) | DONT_EXPIRE_PASSWORD (65536) |
	#  TRUSTED_FOR_DELEGATION (524288)
	#
	# and possibly UseDesOnly (2097152) (see above)
	#
	cat > "$object" <<EOF
dn: $dn
changetype: modify
replace: userAccountControl
userAccountControl: $userAccountControl
EOF
	ldapmodify -h "$dc" $ldap_args -f "$object" >/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		printf "$(gettext "ldapmodify failed to modify account attribute").\n" >&2
		error_message
	fi

	# Setup a keytab file
	set -A args --
	for enctype in "${enctypes[@]}"
	do
		args[${#args[@]}]=-e
		args[${#args[@]}]=$enctype
	done

	rm $new_keytab > /dev/null 2>&1

	cat > "$object" <<EOF
dn: $dn
changetype: modify
add: servicePrincipalName
servicePrincipalName: nfs/${fqdn}
servicePrincipalName: HTTP/${fqdn}
servicePrincipalName: root/${fqdn}
servicePrincipalName: cifs/${fqdn}
servicePrincipalName: host/${upcase_nodename}
EOF
	ldapmodify -h "$dc" $ldap_args -f "$object" >/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		printf "$(gettext "ldapmodify failed to modify account attribute").\n" >&2
		error_message
	fi

	#
	# In Windows, unlike MIT based implementations we salt the keys with
	# the UPN, which is based on the host/string15@realm elements, not
	# with the individual SPN strings.
	#
	salt=host/${locase_nodename}.${domain}@${realm}

	skeys=(host/${fqdn}@${realm} nfs/${fqdn}@${realm} HTTP/${fqdn}@${realm})
	skeys+=(root/${fqdn}@${realm} cifs/${fqdn}@${realm})
	skeys+=(${netbios_nodename}@${realm} host/${upcase_nodename}@${realm})
	skeys+=(cifs/${upcase_nodename}@${realm})

	ks_args="-n -s $salt -v $kvno -k $new_keytab ${args[@]}" 

	for skey in ${skeys[@]}
	do
		printf "%s" "$newpw" | $KSETPW $ks_args $skey > /dev/null 2>&1
		if [[ $? -ne 0 ]]
		then
			printf "$(gettext "Failed to set password").\n" >&2
			error_message
		fi
	done

	doKRB5config

	addDNSRR $dom

	setSMB $dom $dc

	printf -- "---------------------------------------------------\n"
	printf "$(gettext "Setup COMPLETE").\n\n"

	kdestroy -q 1>$TMP_FILE 2>&1
	rm -f $TMP_FILE
	rm -rf $TMPDIR > /dev/null 2>&1

	exit 0
}

###########################
#	Main section	  #
###########################
#
# Set the Kerberos config file and some default strings/files
#
KRB5_CONFIG_FILE=/etc/krb5/krb5.conf
KRB5_KEYTAB_FILE=/etc/krb5/krb5.keytab
RESOLV_CONF_FILE=/etc/resolv.conf

KLOOKUP=/usr/lib/krb5/klookup;	check_bin $KLOOKUP
KSETPW=/usr/lib/krb5/ksetpw;	check_bin $KSETPW
KSMB=/usr/lib/krb5/ksmb;	check_bin $KSMB
KDYNDNS=/usr/lib/krb5/kdyndns;	check_bin $KDYNDNS
KCONF=/usr/lib/krb5/kconf;	check_bin $KCONF

dns_lookup=no
ask_fqdns=no
adddns=no
no_keytab=no
checkval=""
profile=""
typeset -u realm
typeset -l hostname KDC

export TMPDIR="/var/run/kclient"

mkdir $TMPDIR > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
	printf "\n$(gettext "Can not create directory: %s")\n\n" $TMPDIR >&2
	exit 1
fi

TMP_FILE=$(mktemp -q -t kclient-tmpfile.XXXXXX)
export KRB5_CONFIG=$(mktemp -q -t kclient-krb5conf.XXXXXX)
export KRB5CCNAME=$(mktemp -q -t kclient-krb5ccache.XXXXXX) 
new_keytab=$(mktemp -q -t kclient-krb5keytab.XXXXXX) 
if [[ -z $TMP_FILE || -z $KRB5_CONFIG || -z $KRB5CCNAME || -z $new_keytab ]]
then
	printf "\n$(gettext "Can not create temporary files, exiting").\n\n" >&2
	exit 1
fi

#
# If we are interrupted, cleanup after ourselves
#
trap "exiting 1" HUP INT QUIT TERM

if [[ -d /usr/bin ]]; then
	if [[ -d /usr/sbin ]]; then
		PATH=/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH
		export PATH
	else
		printf "\n$(gettext "Directory /usr/sbin not found, exiting").\n" >&2
		exit 1
	fi
else
	printf "\n$(gettext "Directory /usr/bin not found, exiting").\n" >&2
	exit 1
fi

printf "\n$(gettext "Starting client setup")\n\n"
printf -- "---------------------------------------------------\n"

#
# Check for uid 0, disallow otherwise
#
id 1>$TMP_FILE 2>&1
if [[ $? -eq 0 ]]; then
	if egrep -s "uid=0\(root\)" $TMP_FILE; then
		# uid is 0, go ahead ...
		:
	else
		printf "\n$(gettext "Administrative privileges are required to run this script, exiting").\n" >&2
		error_message
	fi
else
	cat $TMP_FILE;
	printf "\n$(gettext "uid check failed, exiting").\n" >&2
	error_message
fi

uname=$(uname -n)
hostname=${uname%%.*}

#
# Process the command-line arguments (if any)
#
OPTIND=1
while getopts nD:Kp:R:k:a:c:d:f:h:m:s:T: OPTIONS
do
	case $OPTIONS in
	    D) options="$options -D"
	       domain_list="$OPTARG"
	       ;;
	    K) options="$options -K"
	       no_keytab=yes
	       ;;
	    R) options="$options -R"
	       realm="$OPTARG"
	       checkval="REALM"; check_value $realm
	       ;;
	    T) options="$options -T"
	       type="$OPTARG"
	       if [[ $type == ms_ad ]]; then
		msad=yes
		adddns=yes
	       else
		non_solaris=yes
		no_keytab=yes
	       fi
	       ;;
	    a) options="$options -a"
	       ADMIN_PRINC="$OPTARG"
	       checkval="ADMIN_PRINC"; check_value $ADMIN_PRINC
	       ;;
	    c) options="$options -c"
	       filepath="$OPTARG"
	       ;;
	    d) options="$options -d"
	       dnsarg="$OPTARG"
	       checkval="DNS_OPTIONS"; check_value $dnsarg
	       ;;
	    f) options="$options -f"
	       fqdnlist="$OPTARG"
 	       ;;
	    h) options="$options -h"
	       logical_hn="$OPTARG"
	       checkval="LOGICAL_HOSTNAME"; check_value $logical_hn
	       ;;
	    k) options="$options -k"
	       kdc_list="$OPTARG"
	       ;;
	    m) options="$options -m"
	       KDC="$OPTARG"
	       checkval="KDC"; check_value $KDC
	       ;;
	    n) options="$options -n"
	       add_nfs=yes
	       ;;
	    p) options="$options -p"
	       profile="$OPTARG"
	       read_profile $profile
	       ;;
	    s) options="$options -s"
	       svc_list="$OPTARG"
	       SVCs=${svc_list//,/ }
 	       ;;
	    \?) usage
	       ;;
	    *) usage
	       ;;
	esac
done

#correct argument count after options
shift `expr $OPTIND - 1`

if [[ -z $options ]]; then
	:
else
	if [[ $# -ne 0 ]]; then
		usage
	fi
fi

#
# Check to see if we will be a client of a MIT, Heimdal, Shishi, etc.
#
if [[ -z $options ]]; then
	query "$(gettext "Is this a client of a non-Solaris KDC") ?"
	non_solaris=$answer
	if [[ $non_solaris == yes ]]; then
		printf "$(gettext "Which type of KDC is the server"):\n"
		printf "\t$(gettext "ms_ad: Microsoft Active Directory")\n"
		printf "\t$(gettext "mit: MIT KDC server")\n"
		printf "\t$(gettext "heimdal: Heimdal KDC server")\n"
		printf "\t$(gettext "shishi: Shishi KDC server")\n"
		printf "$(gettext "Enter required KDC type"): "
		read kdctype
		if [[ $kdctype == ms_ad ]]; then
			msad=yes
		elif [[ $kdctype == mit || $kdctype == heimdal || \
		    $kdctype == shishi ]]; then
			no_keytab=yes
		else
			printf "\n$(gettext "Invalid KDC type option, valid types are ms_ad, mit, heimdal, or shishi, exiting").\n" >&2
			error_message
		fi
	fi
fi

[[ $msad == yes ]] && join_domain

#
# Check for /etc/resolv.conf
#
if [[ -r $RESOLV_CONF_FILE ]]; then
	client_machine=`$KLOOKUP`

	if [[ $? -ne 0 ]]; then
		if [[ $adddns == no ]]; then
			printf "\n$(gettext "%s does not have a DNS record and is required for Kerberos setup")\n" $hostname >&2
			error_message
		fi

	else
		#
		# If client entry already exists then do not recreate it
		#
		adddns=no

		hostname=${client_machine%%.*}
		domain=${client_machine#*.}
	fi

	short_fqdn=${domain#*.*}
	short_fqdn=$(echo $short_fqdn | grep "\.")
else
	#
	# /etc/resolv.conf not present, exit ...
	#
	printf "\n$(gettext "%s does not exist and is required for Kerberos setup")\n" $RESOLV_CONF_FILE >&2
	printf "$(gettext "Refer to resolv.conf(4), exiting").\n" >&2
	error_message
fi

check_nss_conf || printf "$(gettext "/etc/nsswitch.conf does not make use of DNS for hosts and/or ipnodes").\n"

[[ -n $fqdnlist ]] && verify_fqdnlist "$fqdnlist"

if [[ -z $dnsarg && (-z $options || -z $filepath) ]]; then
	query "$(gettext "Do you want to use DNS for kerberos lookups") ?"
	if [[ $answer == yes ]]; then
		printf "\n$(gettext "Valid DNS lookup options are dns_lookup_kdc, dns_lookup_realm,\nand dns_fallback. Refer krb5.conf(4) for further details").\n"
		printf "\n$(gettext "Enter required DNS option"): "
		read dnsarg
		checkval="DNS_OPTIONS"; check_value $dnsarg
		set_dns_value $dnsarg
	fi
else
	[[ -z $dnsarg ]] && dnsarg=none
	set_dns_value $dnsarg
fi

if [[ -n $kdc_list ]]; then
	if [[ -z $KDC ]]; then
		for kdc in $kdc_list; do
			break
		done
		KDC="$kdc"
	fi
fi

if [[ -z $realm ]]; then
	printf "$(gettext "Enter the Kerberos realm"): "
	read realm
	checkval="REALM"; check_value $realm
fi
if [[ -z $KDC ]]; then
	printf "$(gettext "Specify the master KDC hostname for the above realm"): "
	read KDC
	checkval="KDC"; check_value $KDC
fi

FKDC=`$KLOOKUP $KDC`

#
# Ping to see if the kdc is alive !
#
ping_check $FKDC "KDC"

if [[ -z $kdc_list && (-z $options || -z $filepath) ]]; then
	query "$(gettext "Do you have any slave KDC(s)") ?"
	if [[ $answer == yes ]]; then
		printf "$(gettext "Enter a comma-separated list of slave KDC host names"): "
		read kdc_list
	fi
fi

[[ -n $kdc_list ]] && verify_kdcs "$kdc_list"

#
# Check to see if we will have a dynamic presence in the realm
#
if [[ -z $options ]]; then
	query "$(gettext "Will this client need service keys") ?"
	if [[ $answer == no ]]; then
		no_keytab=yes
	fi
fi

#
# Check to see if we are configuring the client to use a logical host name
# of a cluster environment
#
if [[ -z $options ]]; then
	query "$(gettext "Is this client a member of a cluster that uses a logical host name") ?"
	if [[ $answer == yes ]]; then
		printf "$(gettext "Specify the logical hostname of the cluster"): "
		read logical_hn
		checkval="LOGICAL_HOSTNAME"; check_value $logical_hn
		setup_lhn
	fi
fi

if [[ -n $domain_list && (-z $options || -z $filepath) ]]; then
	query "$(gettext "Do you have multiple domains/hosts to map to realm %s"
) ?" $realm
	if [[ $answer == yes ]]; then
		printf "$(gettext "Enter a comma-separated list of domain/hosts
to map to the default realm"): "
		read domain_list
	fi
fi
[[ -n domain_list ]] && domain_list=${domain_list//,/ }

#
# Start writing up the krb5.conf file, save the existing one
# if already present
#
writeup_krb5_conf

#
# Is this client going to use krb-nfs?  If so then we need to at least
# uncomment the krb5* sec flavors in nfssec.conf.
#
if [[ -z $options ]]; then
	query "$(gettext "Do you plan on doing Kerberized nfs") ?"
	add_nfs=$answer
fi

if [[ $add_nfs == yes ]]; then
	modify_nfssec_conf

	#	
	# We also want to enable gss as we now live in a SBD world
	#
	svcadm enable svc:/network/rpc/gss:default
	[[ $? -ne 0 ]] && printf "$(gettext "Warning: could not enable gss service").\n"
fi

if [[ -z $options ]]; then
	query "$(gettext "Do you want to update /etc/pam.conf") ?"
	if [[ $answer == yes ]]; then
		printf "$(gettext "Enter a list of PAM service names in the following format: service:{first|only|optional}[,..]"): "
		read svc_list
		SVCs=${svc_list//,/ }
	fi
fi
[[ -n $svc_list ]] && update_pam_conf

#
# Copy over krb5.conf master copy from filepath
#
if [[ -z $options || -z $filepath ]]; then
	query "$(gettext "Do you want to copy over the master krb5.conf file") ?"
	if [[ $answer == yes ]]; then
		printf "$(gettext "Enter the pathname of the file to be copied"): "
		read filepath
	fi
fi

if [[ -n $filepath && -r $filepath ]]; then
	cp $filepath $KRB5_CONFIG
	if [[ $? -eq 0 ]]; then
		printf "$(gettext "Copied %s to %s").\n" $filepath $KRB5_CONFIG
	else
		printf "$(gettext "Copy of %s failed, exiting").\n" $filepath >&2
		error_message
	fi
elif [[ -n $filepath ]]; then
	printf "\n$(gettext "%s not found, exiting").\n" $filepath >&2
	error_message
fi

doKRB5config

#
# Populate any service keys needed for the client in the keytab file
#
if [[ $no_keytab != yes ]]; then
	setup_keytab
else
	printf "\n$(gettext "Note: %s file not created, please refer to verify_ap_req_nofail in krb5.conf(4) for the implications").\n" $KRB5_KEYTAB_FILE
	printf "$(gettext "Client will also not be able to host services that use Kerberos").\n"
fi

printf -- "\n---------------------------------------------------\n"
printf "$(gettext "Setup COMPLETE").\n\n"

#
# If we have configured the client in a cluster we need to remind the user
# to propagate the keytab and configuration files to the other members.
#
if [[ -n $logical_hn ]]; then
	printf "\n$(gettext "Note, you will need to securely transfer the /etc/krb5/krb5.keytab and /etc/krb5/krb5.conf files to all the other members of your cluster").\n"
fi

#
# Cleanup.
#
kdestroy -q 1>$TMP_FILE 2>&1
rm -f $TMP_FILE
rm -rf $TMPDIR > /dev/null 2>&1
exit 0
