#!/usr/bin/ksh
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# This command provides an simple interface to configure, destroy, and to obtain
# the status of a master or slave Kerberos KDC server.
#

function usage {

	app=`basename $0`

	printf "\n$(gettext "Usage: %s [ -a admprincipal ] [ -e enctype ] [ -h ]")\n" $app
	printf "\t$(gettext "[ -p pwfile ] [ -r realm ] subcommand")\n\n"

	printf "\t$(gettext "-a: Create non-default admin principal.")\n"
	printf "\t$(gettext "-e: Encryption type used to encrypt the master key")\n"
	printf "\t$(gettext "-h: This help message.")\n"
	printf "\t$(gettext "-p: File that contains the admin principal and master key password.")\n"
	printf "\t$(gettext "-r: Set the default realm for this server.")\n\n"

	printf "\t$(gettext "where 'subcommand' is one of the following:")\n\n"

	printf "\t$(gettext "create [ master ]")\n"
	printf "\t$(gettext "create [ -m masterkdc ] slave")\n"
	printf "\t$(gettext "destroy")\n"
	printf "\t$(gettext "status")\n\n"

	cleanup 1
}

function ask {

	# ask question, set global answer
	typeset question=$1 default_answer=$2
	if [[ -z $default_answer ]]; then
		print "$question \c"
	else
		print "$question [$default_answer]: \c"
	fi
	read answer
	[ -z "$answer" ] && answer="$default_answer"
}

function yesno {

	typeset question="$1"
	# answer is a global set by ask
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
	if [[ $answer = no ]]; then
		printf "\t$(gettext "No action performed").\n"
	fi
}

function cleanup {

	integer ret=$1

	kdestroy -q -c $TMP_CCACHE 1>$TMP_FILE 2>&1
        rm -f $TMP_FILE

        exit $ret
}

function error_message {

        printf "---------------------------------------------------\n"
        printf "$(gettext "Setup FAILED").\n\n"

	cleanup 1
}

function check_bin {

	bin=$1

	if [[ ! -x $bin ]]; then
		printf "$(gettext "Could not access/execute %s").\n" $bin
		error_message
	fi
}

function check_ret {
	
	integer ret=$1
	prog=$2

	if [[ $ret -ne 0 ]]; then
		printf "\n$(gettext "%s failed with return value %d, exiting").\n\n" $prog $ret
		error_message
	fi
}


function ok_to_proceed {

	yesno "$@"

	if [[ $answer = no ]]; then
		printf "\n$(gettext "Exiting, no action performed")\n\n"
		cleanup 0
	fi
}

function check_value {

	typeset arg="$1"

	if [[ -z $arg ]]; then
		printf "\n$(gettext "No input obtained for %s, exiting").\n" $checkval
		error_message
	else
		echo "$arg">$TMP_FILE
		if egrep -s '[*$^#!]+' $TMP_FILE; then
			printf "\n$(gettext "Invalid input obtained for %s, exiting").\n" $checkval
			error_message
		fi
	fi
}

function setup_kdc_conf {

	printf "\n$(gettext "Setting up %s").\n" $KRB5_KDC_CONF

	if [[ -r $KRB5_KDC_CONF ]]; then
		cat $KRB5_KDC_CONF > $KRB5_KDC_CONF.sav
		cannot_create $KRB5_KDC_CONF.sav $?
	fi

	exec 3>$KRB5_KDC_CONF
	if [[ $? -ne 0 ]]; then
		printf "\n$(gettext "Cannot write to %s, exiting").\n" $KRB5_KDC_CONF
		error_message
	fi

	printf "\n[kdcdefaults]\n\tkdc_ports = 88,750\n\n" 1>&3
	printf "[realms]\n\t$REALM = {\n" 1>&3
	printf "\t\tprofile = $KRB5_KRB_CONF\n" 1>&3
	printf "\t\tdatabase_name = $PRINCDB\n" 1>&3
	printf "\t\tmaster_key_type = $ENCTYPE\n" 1>&3
	printf "\t\tacl_file = $KADM5ACL\n" 1>&3
	printf "\t\tkadmind_port = 749\n" 1>&3
	printf "\t\tmax_life = 8h 0m 0s\n" 1>&3
	printf "\t\tmax_renewable_life = 7d 0h 0m 0s\n" 1>&3
	printf "\t\tdefault_principal_flags = +preauth\n" 1>&3

	printf "\t\tsunw_dbprop_enable = true\n" 1>&3
	if [[ $master = yes ]]; then
		printf "\t\tsunw_dbprop_master_ulogsize = 1000\n" 1>&3
	fi
	if [[ $slave = yes ]]; then
		printf "\t\tsunw_dbprop_slave_poll = 2m\n" 1>&3
	fi

	printf "\t}\n" 1>&3
}

function setup_krb_conf {

	printf "\n$(gettext "Setting up %s").\n" $KRB5_KRB_CONF

	if [[ -r $KRB5_KRB_CONF ]]; then
		cat $KRB5_KRB_CONF > $KRB5_KRB_CONF.sav
		cannot_create $KRB5_KRB_CONF.sav $?
	fi

	exec 3>$KRB5_KRB_CONF
	if [[ $? -ne 0 ]]; then
		printf "\n$(gettext "Cannot write to %s, exiting").\n" $KRB5_KRB_CONF
		error_message
	fi

	printf "[libdefaults]\n" 1>&3
	printf "\tdefault_realm = $REALM\n\n" 1>&3

	printf "[realms]\n" 1>&3
	printf "\t$REALM = {\n" 1>&3
	if [[ $slave = yes ]]; then
		printf "\t\tkdc = $master_hn\n" 1>&3
	fi
	printf "\t\tkdc = $fqhn\n" 1>&3
	if [[ $master = yes ]]; then
		printf "\t\tadmin_server = $fqhn\n" 1>&3
	else
		printf "\t\tadmin_server = $master_hn\n" 1>&3
	fi
	printf "\t}\n\n" 1>&3

	printf "[domain_realm]\n" 1>&3
	printf "\t.$domain = $REALM\n\n" 1>&3

	printf "[logging]\n" 1>&3
	printf "\tdefault = FILE:/var/krb5/kdc.log\n" 1>&3
	printf "\tkdc = FILE:/var/krb5/kdc.log\n" 1>&3
	printf "\tkdc_rotate = {\n\t\tperiod = 1d\n\t\tversions = 10\n\t}\n\n" 1>&3

	printf "[appdefaults]\n" 1>&3
	printf "\tkinit = {\n\t\trenewable = true\n\t\tforwardable = true\n" 1>&3
	printf "\t}\n" 1>&3
}

function cannot_create {

	typeset filename="$1"
	typeset stat="$2"
	if [[ $stat -ne 0 ]]; then
		printf "\n$(gettext "Cannot create/edit %s, exiting").\n" $filename
		error_message
	fi
}

function check_admin {

	message=$1

	if [[ -z $ADMIN_PRINC ]]; then
		printf "$message"
		read ADMIN_PRINC
		checkval="ADMIN_PRINC"; check_value $ADMIN_PRINC
	fi

	echo "$ADMIN_PRINC">$TMP_FILE

	if egrep -s '\/admin' $TMP_FILE; then
		# Already in "/admin" format, do nothing
		:
	else
		if egrep -s '\/' $TMP_FILE; then
			printf "\n$(gettext "Improper entry for krb5 admin principal, exiting").\n"
			error_message
		else
			ADMIN_PRINC=$(echo "$ADMIN_PRINC/admin")
		fi
	fi

}

function ping_check {

	typeset machine="$1"

	if $PING $machine > /dev/null 2>&1; then
		:
	else
		printf "\n$(gettext "%s %s is unreachable, exiting").\n" $string $machine
		error_message
	fi
}

function check_host {

	echo "$host">$TMP_FILE
	if egrep -s '[^.]\.[^.]+$' $TMP_FILE; then
		# do nothing, host is in fqhn format
		:
	else
		if egrep -s '\.+' $TMP_FILE; then
			printf "\n$(gettext "Improper format of host name: '%s'").\n"
			printf "$(gettext "Expecting the following format: 'somehost.example.com' or 'somehost', exiting").\n"
			error_message
		else
			# Attach fqdn to host, to get the Fully Qualified Domain
			# Name of the host requested
			host=$(echo "$host.$domain")
		fi
	fi

	#
	# Ping to see if the host is alive!
	#
	ping_check $host
}

function kill_daemons {

	# Kill daemons so they won't go into maintenance mode
	$SVCADM disable -s krb5kdc
	if [[ $? -ne 0 ]]; then
		printf "\n$(gettext "Error in disabling krb5kdc, exiting").\n"
		error_message
	fi
	$SVCADM disable -s kadmin
	if [[ $? -ne 0 ]]; then
		printf "\n$(gettext "Error in disabling kadmind, exiting").\n"
		error_message
	fi
	$SVCADM disable -s krb5_prop
	if [[ $? -ne 0 ]]; then
		printf "\n$(gettext "Error in disabling kpropd, exiting").\n"
		error_message
	fi

	# Make sure that none of the daemons outside of SMF are running either
	pkill kadmind
	if [[ $? -gt 1 ]]; then
		printf "\n$(gettext "Error in killing kadmind, exiting").\n"
		error_message
	fi
	pkill krb5kdc
	if [[ $? -gt 1 ]]; then
		printf "\n$(gettext "Error in killing krb5kdc, exiting").\n"
		error_message
	fi
	pkill kpropd
	if [[ $? -gt 1 ]]; then
		printf "\n$(gettext "Error in killing kpropd, exiting").\n"
		error_message
	fi
}

function setup_mkeytab {

	check_admin "\n$(gettext "Enter the krb5 administrative principal to be created"): \c"

	if [[ -z $PWFILE ]]; then
		echo
		$KADMINL -q "ank $ADMIN_PRINC"
		check_ret $? $KADMINL
	else
		cat $PWFILE $PWFILE | $KADMINL -q "ank $ADMIN_PRINC" > /dev/null 2>&1
		check_ret $? $KADMINL
	fi

	$KADMINL -q "ank -randkey host/$fqhn" 1>$TMP_FILE 2>&1
	check_ret $? $KADMINL
	$KADMINL -q "ktadd host/$fqhn" 1>$TMP_FILE 2>&1
	check_ret $? $KADMINL
}

function setup_skeytab {

	check_admin "\n$(gettext "Enter the krb5 administrative principal to be used"): \c"

	printf "$(gettext "Obtaining TGT for %s") ...\n" $ADMIN_PRINC

	if [[ -z $PWFILE ]]; then
		kinit -c $TMP_CCACHE -S kadmin/$master_hn $ADMIN_PRINC
		check_ret $? kinit
	else
		cat $PWFILE | kinit -c $TMP_CCACHE -S kadmin/$master_hn \
			$ADMIN_PRINC > /dev/null 2>&1
	fi
	klist -c $TMP_CCACHE 1>$TMP_FILE 2>&1
	if egrep -s "$(gettext "Valid starting")" $TMP_FILE && \
	   egrep -s "kadmin/$master_hn@$REALM" $TMP_FILE; then
		:
	else
		printf "\n$(gettext "kinit of %s failed, exiting").\n" $ADMIN_PRINC
		error_message
	fi

	$KADMIN -c $TMP_CCACHE -q "ank -randkey kiprop/$fqhn" 1>$TMP_FILE 2>&1
	check_ret $? $KADMIN
	$KADMIN -c $TMP_CCACHE -q "ktadd kiprop/$fqhn" 1>$TMP_FILE 2>&1
	check_ret $? $KADMIN

	$KADMIN -c $TMP_CCACHE -q "ank -randkey host/$fqhn" 1>$TMP_FILE 2>&1
	check_ret $? $KADMIN
	$KADMIN -c $TMP_CCACHE -q "ktadd host/$fqhn" 1>$TMP_FILE 2>&1
	check_ret $? $KADMIN

	kdestroy -q -c $TMP_CCACHE 1>$TMP_FILE 2>&1
	check_ret $? $kdestroy
}

function setup_kadm5acl {

	printf "\n$(gettext "Setting up %s").\n" $KADM5ACL

	if [[ -r $KADM5ACL ]]; then
		cat $KADM5ACL > $KADM5ACL.sav
		cannot_create $KADM5ACL.sav $?
	fi

	exec 3>$KADM5ACL
	if [[ $? -ne 0 ]]; then
		printf "\n$(gettext "Cannot write to %s, exiting").\n" $KADM5ACL
		error_message
	fi

	if [[ $master = yes ]]; then
		printf "\n$ADMIN_PRINC@$REALM\t\tacmil\n" 1>&3
		printf "\nkiprop/*@$REALM\t\tp\n" 1>&3
	else
		printf "\n*/admin@___default_realm___\t\t*\n" 1>&3
	fi
}

function setup_kpropdacl {

	printf "\n$(gettext "Setting up %s").\n\n" $KPROPACL

	if [[ -r $KPROPACL ]]; then
		cat $KPROPACL > $KPROPACL.sav
		cannot_create $KPROPACL.sav $?
	fi

	exec 3>$KPROPACL
	if [[ $? -ne 0 ]]; then
		printf "\n$(gettext "Cannot write to %s, exiting").\n" $KPROPACL
		error_message
	fi
	printf "\nhost/$master_hn@$REALM\n" 1>&3
}

function setup_master {

	# create principal DB (KDB)
	if [[ -z $PWFILE ]]; then
		echo
		kdb5_util create
		check_ret $? kdb5_util
	else
		cat $PWFILE $PWFILE | kdb5_util create > /dev/null
		check_ret $? kdb5_util
	fi

	setup_mkeytab
	setup_kadm5acl

	$SVCADM enable -r -s krb5kdc
	$SVCADM enable -r -s kadmin
}

function setup_slave {

	integer count=1

	setup_skeytab

	# Clear the kadm5acl, since the start methods look at this file
	# to see if the server has been configured as a master server
	setup_kadm5acl

	setup_kpropdacl

	$SVCADM enable -r -s krb5_prop

	# Wait for full propagation of the database, in some environments
	# this could take a few seconds
	while [[ ! -f /var/krb5/principal ]]; do
		if [[ count -gt $LOOPCNT ]]; then
			printf "\n$(gettext "Could not receive updates from the master").\n"
                        error_message
			((count = count + 1))
		fi
		printf "$(gettext "Waiting for database from master")...\n"
		sleep $SLEEPTIME
	done

	# The database is propagated now we need to create the stash file
	if [[ -z $PWFILE ]]; then
		kdb5_util stash
		check_ret $? kdb5_util
	else
		cat $PWFILE | kdb5_util stash > /dev/null 2>&1
		check_ret $? kdb5_util
	fi

	$SVCADM enable -r -s krb5kdc
}

function kdb5_destroy {
	typeset status=0
	typeset arg=

	[[ -n $REALM ]] && arg="-r $REALM"
	printf "$(gettext "yes")\n" | kdb5_util $arg destroy > /dev/null 2>&1

	status=$?
	[[ $status -eq 0 ]] && return $status

	# Could mean that the admin could have already removed part of the
	# configuration.  Better to check to see if anything else should be
	# destroyed.  We check by looking at any other stash files in /var/krb5
	stashfiles=`ls $STASH`
	for stash in $stashfiles
	do
		realm=${stash#*.k5.}
		[[ -z $realm ]] && continue

		printf "$(gettext "Found non-default realm: %s")\n" $realm
		query "$(gettext "Do you wish to destroy realm"): $realm ?"
		if [[ $answer == yes ]]; then
			printf "$(gettext "yes")\n" | kdb5_util -r $realm destroy > /dev/null 2>&1
			status=$?
			if [[ $status -ne 0 ]]; then
				printf "$(gettext "Could not destroy realm: %s")\n" $realm
				return $status
			fi
		else
			printf "$(gettext "%s will not be destroyed").\n" $realm
			status=0
		fi
	done

	return $status
}

function destroy_kdc {
	typeset status

	# Check first to see if this is an existing KDC or server
	if [[ -f $KRB5KT || -f $PRINCDB || -f $OLDPRINCDB ]]
	then
		if [[ -z $PWFILE ]]; then
			printf "\n$(gettext "Some of the following files are present on this system"):\n"
			echo "\t$KRB5KT\n\t$PRINCDB\n\t$OLDPRINCDB\n\t$STASH\n"
			if [[ -z $d_option ]]; then
				printf "$(gettext "You must first run 'kdcmgr destroy' to remove all of these files before creating a KDC server").\n\n"
				cleanup 1
			else
				ok_to_proceed "$(gettext "All of these files will be removed, okay to proceed?")"
			fi
		fi
	else
		if [[ -n $d_option ]]; then
			printf "\n$(gettext "No KDC related files exist, exiting").\n\n"
			cleanup 0
		fi
		return
	fi

	kdb5_destroy
	status=$?
 
	rm -f $KRB5KT

	[[ $status -ne 0 ]] && cleanup 1
}

function kadm5_acl_configed {

	if [[ -s $KADM5ACL ]]; then
		grep -v '^[    ]*#' $KADM5ACL | \
			egrep '_default_realm_' > /dev/null 2>&1
		if [[ $? -gt 0 ]]; then
			return 0
		fi
	fi

	return 1
}

function status_kdc {

	integer is_master=0

	printf "\n$(gettext "KDC Status Information")\n"
	echo "--------------------------------------------"
	svcs -xv svc:/network/security/krb5kdc:default

	if kadm5_acl_configed; then
		is_master=1
		printf "\n$(gettext "KDC Master Status Information")\n"
		echo "--------------------------------------------"
		svcs -xv svc:/network/security/kadmin:default
	else
		printf "\n$(gettext "KDC Slave Status Information")\n"
		echo "--------------------------------------------"
		svcs -xv svc:/network/security/krb5_prop:default
	fi

	printf "\n$(gettext "Transaction Log Information")\n"
	echo "--------------------------------------------"
	/usr/sbin/kproplog -h

	printf "$(gettext "Kerberos Related File Information")\n"
	echo "--------------------------------------------"
	printf "$(gettext "(will display any missing files below)")\n"
	FILELIST="$KRB5_KDC_CONF $KRB5_KRB_CONF $KADM5ACL $KRB5KT $PRINCDB "
	for file in $FILELIST; do
		if [[ ! -s $file ]]; then
			printf "$(gettext "%s not found").\n" $file
		fi
	done
	if [[ $is_master -eq 0 && ! -s $KPROPACL ]]; then
		printf "$(gettext "%s not found").\n" $KPROPACL
	fi

	test ! -s $STASH &&
	    printf "$(gettext "Stash file not found") (/var/krb5/.k5.*).\n"
	echo

	cleanup 0
}

# Start of Main script

typeset -u REALM
typeset -l host
typeset -l fqhn

# Defaults
KRB5_KDC_CONF=/etc/krb5/kdc.conf
KRB5_KRB_CONF=/etc/krb5/krb5.conf
KADM5ACL=/etc/krb5/kadm5.acl
KPROPACL=/etc/krb5/kpropd.acl

KRB5KT=/etc/krb5/krb5.keytab
PRINCDB=/var/krb5/principal
OLDPRINCDB=/var/krb5/principal.old
STASH=/var/krb5/.k5.*

KADMINL=/usr/sbin/kadmin.local;	check_bin $KADMINL
KADMIN=/usr/sbin/kadmin;	check_bin $KADMIN
KDCRES=/usr/lib/krb5/klookup;	check_bin $KDCRES
SVCADM=/usr/sbin/svcadm;	check_bin $SVCADM
PING=/usr/sbin/ping;		check_bin $PING

ENCTYPE=aes128-cts-hmac-sha1-96
LOOPCNT=10
SLEEPTIME=5

if [[ -x /usr/bin/mktemp ]]; then
	TMP_FILE=$(/usr/bin/mktemp /etc/krb5/krb5tmpfile.XXXXXX)
	TMP_CCACHE=$(/usr/bin/mktemp /etc/krb5/krb5tmpccache.XXXXXX)
else
	TMP_FILE="/etc/krb5/krb5tmpfile.$$"
	TMP_CCACHE="/etc/krb5/krb5tmpccache.$$"
fi

if [[ ! -f /etc/resolv.conf ]]; then
	printf "$(gettext "Error: need to configure /etc/resolv.conf").\n"

	cleanup 1
fi

fqhn=`$KDCRES`
if [[ -n "$fqhn" ]]; then
	:
elif [[ -n $(hostname) && -n $(domainname) ]]; then
	fqhn=$(hostname|cut -f1 -d'.').$(domainname|cut -f2- -d'.')
else
	printf "$(gettext "Error: can not determine full hostname (FQHN).  Aborting")\n"
	printf "$(gettext "Note, trying to use hostname and domainname to get FQHN").\n"

	cleanup 1
fi

ping_check $fqhn

domain=${fqhn#*.} # remove host part

exitmsg=`printf "$(gettext "Exiting...")"`

trap "echo $exitmsg; rm -f $TMP_FILE $TMP_CCACHE; exit 1" HUP INT QUIT TERM

while getopts :a:e:hp:r:s flag
do
	case "$flag" in
		a)	ADMIN_PRINC=$OPTARG;;
		e)	ENCTYPE=$OPTARG;;
		h)	usage;;
		p)	PWFILE=$OPTARG
			if [[ ! -r $PWFILE ]]; then
				printf "\n$(gettext "Password file %s does not exist, exiting").\n\n" $PWFILE
				cleanup 1
			fi
			;;
		r)	REALM=$OPTARG;;
		*)	usage;;
	esac
done
shift $(($OPTIND - 1))

case "$*" in
	create)			master=yes;;
	"create master")	master=yes;;
	"create -m "*)		host=$3
				checkval="MASTER"; check_value $host
				check_host
				master_hn=$host
				if [[ $4 != slave ]]; then
					usage
				fi;&
	"create slave")		slave=yes;;
	destroy)		d_option=yes
				kill_daemons
				destroy_kdc
				cleanup 0;;
	status)			status_kdc;;
	*)			usage;;
esac

kill_daemons

printf "\n$(gettext "Starting server setup")\n"
printf "---------------------------------------------------\n"

# Checks for existing kdb and destroys if desired
destroy_kdc

if [[ -z $REALM ]]; then
	printf "$(gettext "Enter the Kerberos realm"): \c"
	read REALM
	checkval="REALM"; check_value $REALM
fi

if [[ -z $master && -z $slave ]]; then
	query "$(gettext "Is this machine to be configured as a master?"): \c"
	master=$answer
	
	if [[ $answer = no ]]; then
		query "$(gettext "Is this machine to be configured as a slave?"): \c"
		slave=$answer
		if [[ $answer = no ]]; then
			printf "\n$(gettext "Machine must either be a master or a slave KDC server").\n"
			error_message
		fi
	fi
fi

if [[ $slave = yes && -z $master_hn ]]; then
	printf "$(gettext "What is the master KDC's host name?"): \c"
	read host
	checkval="MASTER"; check_value $host
	check_host
	master_hn=$host
fi

setup_kdc_conf

setup_krb_conf

if [[ $master = yes ]]; then
	setup_master
else
	setup_slave
fi

printf "\n---------------------------------------------------\n"
printf "$(gettext "Setup COMPLETE").\n\n"

cleanup 0
