#!/bin/ksh -p
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# This script is used to setup the Kerberos client by
# supplying information about the Kerberos realm and kdc.
#
# The kerberos configuration file (/etc/krb5/krb5.conf) would
# be generated and local host's keytab file setup. The script
# can also optionally setup the system to do kerberized nfs and
# bringover a master krb5.conf copy from a specified location.

error_message() {
	kdestroy -q -c $TMP_CCACHE 1>$TMP_FILE 2>&1
	rm -f $TMP_FILE
	printf "---------------------------------------------------\n"
	printf "$(gettext "Setup FAILED").\n\n"
	exit 1
}

cannot_create() {
	typeset filename="$1"
	typeset stat="$2"
	if [ $stat -ne 0 ]; then
		printf "\n$(gettext "Cannot create/edit %s, exiting").\n" $filename
		error_message
	fi
}

modify_nfssec_conf() {
	if [ -r $NFSSEC_FILE ]; then
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

call_kadmin() {
	typeset svc="$1"
	typeset bool1 bool2 bool3 bool4

	for listentry in $fqdnlist; do

	# Reset conditional vars to 1
	bool1=1; bool2=1; bool3=1; bool4=1

	service_princ=$(echo "$svc/$listentry")
	getprincsubcommand="getprinc $service_princ"
	anksubcommand="addprinc -randkey $service_princ"
	ktaddsubcommand="ktadd $service_princ"

	kadmin -c $TMP_CCACHE -q "$getprincsubcommand" 1>$TMP_FILE 2>&1

	egrep -s "get_principal: Principal does not exist" $TMP_FILE
	bool1=$?
	egrep -s "get_principal: Operation requires ``get" $TMP_FILE
	bool2=$?

	if [[ $bool1 -eq 0 || $bool2 -eq 0 ]]; then
		kadmin -c $TMP_CCACHE -q "$anksubcommand" 1>$TMP_FILE 2>&1

		egrep -s "add_principal: Principal or policy already exists while creating \"$service_princ@$REALM\"." $TMP_FILE
		bool3=$?

		egrep -s "Principal \"$service_princ@$REALM\" created." $TMP_FILE
		bool4=$?

		if [[ $bool3 -eq 0 || $bool4 -eq 0 ]]; then
			printf "$(gettext "%s entry ADDED to KDC database").\n" $service_princ
		else
			cat $TMP_FILE;
			printf "\n$(gettext "kadmin: add_principal of %s failed, exiting").\n" $service_princ
			error_message
		fi
	else
		printf "$(gettext "%s entry already exists in KDC database").\n" $service_princ
	fi

	klist -k 1>$TMP_FILE 2>&1
	egrep -s "$service_princ@$REALM" $TMP_FILE
	if [ $? -eq 0 ]; then
		printf "$(gettext "%s entry already present in keytab").\n" $service_princ
	else
		kadmin -c $TMP_CCACHE -q "$ktaddsubcommand" 1>$TMP_FILE 2>&1
		egrep -s "added to keytab WRFILE:$KRB5_KEYTAB_FILE." $TMP_FILE
		if [ $? -ne 0 ]; then
			cat $TMP_FILE;
			printf "\n$(gettext "kadmin: ktadd of %s failed, exiting").\n" $service_princ
			error_message
		else
			printf "$(gettext "%s entry ADDED to keytab").\n" $service_princ
		fi
	fi

	done
}

writeup_krb5_conf() {
	printf "\n$(gettext "Setting up %s").\n" $KRB5_CONFIG_FILE

	if [ -r $KRB5_CONFIG_FILE ]; then
		cat $KRB5_CONFIG_FILE > $KRB5_CONFIG_FILE.sav
		cannot_create $KRB5_CONFIG_FILE.sav $?
	fi

	exec > $KRB5_CONFIG_FILE
	if [ $? -ne 0 ]; then
		exec > /dev/tty
		printf "\n$(gettext "Cannot write to %s, exiting").\n" $KRB5_CONFIG_FILE
		error_message
	fi

	printf "[libdefaults]\n"
	if [ "$dns_lookup" = yes ]; then
	    printf "\t$dnsarg = on\n"
	    if [ "$dnsarg" = dns_lookup_kdc ]; then
		printf "\tdefault_realm = $REALM\n"
		printf "\n[domain_realm]\n"
		printf "\t$KDC = $REALM\n"
		printf "\t$client_machine = $REALM\n"
		printf "\t.$fqdn = $REALM\n\n"
	    else
		if [ "$dnsarg" = dns_lookup_realm ]; then

		    printf "\n[realms]\n"
		    printf "\t$REALM = {\n"
		    printf "\t\tkdc = $KDC\n"
		    printf "\t\tadmin_server = $KDC\n"
		    printf "\t}\n\n"
		else
		    printf "\n\n"
		fi
	    fi
	else
	    printf "\tdefault_realm = $REALM\n\n"

	    printf "[realms]\n"
	    printf "\t$REALM = {\n"
	    printf "\t\tkdc = $KDC\n"
	    printf "\t\tadmin_server = $KDC\n"
	    printf "\t}\n\n"

	    printf "[domain_realm]\n"
	    printf "\t$KDC = $REALM\n"
	    printf "\t$client_machine = $REALM\n"
	    printf "\t.$fqdn = $REALM\n\n"
	fi

	printf "[logging]\n"
	printf "\tdefault = FILE:/var/krb5/kdc.log\n"
	printf "\tkdc = FILE:/var/krb5/kdc.log\n"

	#
	# return output to TTY
	#
	exec > /dev/tty
}

ask() {
	question=$1
	default_answer=$2
	if [ -z "$default_answer" ]; then
		printf "$question :\c"
	else
		printf "$question [$default_answer]: \c"
	fi
	read answer
	test -z "$answer" && answer="$default_answer"
}

yesno() {
	typeset question="$1"
	answer=""
	while [ -z "$answer" ]; do
		ask "$question" y/n
		case "$answer" in
			y|yes)	answer=yes;;
			n|no)	answer=no;;
			*)	answer="";;
		esac
	done
}

query() {
	yesno "$*"
	if [ "$answer" = no ]; then
		printf "\t$(gettext "No action performed").\n"
	fi
}


read_profile() {
	typeset param value
	typeset file="$1"
	if [[ ! -d $file && -r $file ]]; then
		while read param value
		do
			case "$param" in
			REALM)  if [ -z "$REALM" ]; then
					REALM="$value"
					checkval="REALM"; check_value $REALM
				fi
				;;
			KDC)    if [ -z "$KDC" ]; then
					KDC="$value"
					checkval="KDC"; check_value $KDC
				fi
				;;
			ADMIN)  if [ -z "$ADMIN_PRINC" ]; then
					ADMIN_PRINC="$value"
					checkval="ADMIN_PRINC"
    					check_value $ADMIN_PRINC
				fi
				;;
			FILEPATH)  if [ -z "$filepath" ]; then
					filepath="$value"
				   fi
				   ;;
			NFS)    if [ -z "$add_nfs" ]; then
				    if [ "$value" = 1 ]; then
					    add_nfs=yes
				    else
					    add_nfs=no
				    fi
				fi
				;;
			DNSLOOKUP) if [ -z "$dnsarg" ]; then
					dnsarg="$value"
					checkval="DNS_OPTIONS"
					check_value $dnsarg
				   fi
				   ;;
			FQDN) if [ -z "$fqdnlist" ]; then
					fqdnlist="$value"
					checkval="FQDN"
					check_value $fqdnlist
					verify_fqdnlist "$fqdnlist"
			      fi
			      ;;
			esac
		done <$file
	else
		printf "\n$(gettext "The kclient profile \`%s' is not valid, exiting").\n" $file
		error_message
	fi
}

ping_check() {
	typeset machine="$1"
	typeset string="$2"
	if ping $machine > /dev/null; then
		:
	else
		printf "\n$(gettext "%s %s is unreachable, exiting").\n" $string $machine
		error_message
	fi

	# Output timesync warning if not using a profile, i.e. in
	# interactive mode.
	if [[ -z "$profile" && "$string" = KDC ]]; then
		# It's difficult to sync up time with KDC esp. if in a
		# zone so just print a warning about KDC time sync.
		printf "\n$(gettext "Note, this system and the KDC's time must be within 5 minutes of each other for Kerberos to function.  Both systems should run some form of time synchronization system like Network Time Protocol (NTP)").\n"
	fi
}

check_value() {
	typeset arg="$1"
	if [ -z "$arg" ]; then
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

set_dns_value() {
	typeset arg="$1"
	if [[ "$arg" = dns_lookup_kdc  ||  "$arg" = dns_lookup_realm  || "$arg" = dns_fallback ]]; then
		dns_lookup=yes
	else
		arg=$(echo "$arg"|tr '[A-Z]' '[a-z]')
		if [ "$arg" = none ]; then
			dns_lookup=no
		else
			printf "\n$(gettext "Invalid DNS lookup option, exiting").\n"
			error_message
		fi
	fi
}

verify_fqdnlist() {
	integer count=1

	list=$(echo "$1" | tr -d " " | tr -d "\t")
	hostname=$(uname -n | tr '[A-Z]' '[a-z]' | cut -d"." -f1)
	fqdnlist=$client_machine

	eachfqdn=$(echo "$list" | cut -d"," -f$count)
	if [ -z "$eachfqdn" ]; then
		printf "\n$(gettext "If the -f option is used, atleast one FQDN should be listed").\n\n"

		usage
	else
		while [ ! -z "$eachfqdn" ]; do
			tmpvar=$(echo "$eachfqdn" | cut -d"." -f1)
			if [ -z "$tmpvar" ]; then
				fullhost="$hostname$eachfqdn"
			else
				fullhost="$hostname.$eachfqdn"
			fi

			ping_check $fullhost "System"
			if [ "$fullhost" = "$client_machine" ]; then
				:
			else
				fqdnlist="$fqdnlist $fullhost"
			fi

			if [[ "$list" == *,* ]]; then
				((count = count + 1))
				eachfqdn=$(echo "$list" | cut -d"," -f$count)
			else
				break
			fi
		done
	fi
}

usage() {
	printf "\n$(gettext "Usage: kclient [ -n ] [ -R realm ] [ -k kdc ] [ -a adminuser ] [ -c filepath ] [ -d dnsarg ] [ -f fqdn_list ] [ -p profile ]")\n\n"
	printf "$(gettext "Refer kclient(1M) for details, exiting").\n"
	error_message
}

###########################
#	Main section	  #
###########################
#
# Set the Kerberos config file and some default strings/files
#
KRB5_CONFIG_FILE="/etc/krb5/krb5.conf"
KRB5_KEYTAB_FILE="/etc/krb5/krb5.keytab"
RESOLV_CONF_FILE="/etc/resolv.conf"
NFSSEC_FILE="/etc/nfssec.conf"
dns_lookup="no"
ask_fqdns="no"
checkval=""
profile=""

# Set OS release level to Solaris 10, inorder to track the requirement
# of the root/fqdn service principal for kerberized NFS.
release_level=10

if [ -x /usr/bin/mktemp ]; then
	TMP_FILE=$(/usr/bin/mktemp /etc/krb5/krb5tmpfile.XXXXXX)
	TMP_CCACHE=$(/usr/bin/mktemp /etc/krb5/krb5tmpccache.XXXXXX)
else
	TMP_FILE="/etc/krb5/krb5tmpfile.$$"
	TMP_CCACHE="/etc/krb5/krb5tmpccache.$$"
fi

if [[ -z "$TMP_FILE" || -z "$TMP_CCACHE" ]]; then
	printf "\n$(gettext "Temporary file creation failed, exiting").\n" >&2
	exit 1
fi

#
# If we are interrupted, cleanup after ourselves
#
trap "/usr/bin/rm -f $TMP_FILE $TMP_CCACHE; exit 1" HUP INT QUIT TERM

if [ -d /usr/bin ]; then
	if [ -d /usr/sbin ]; then
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
printf "---------------------------------------------------\n"

#
# Check for uid 0, disallow otherwise
#
id 1>$TMP_FILE 2>&1
if [ $? -eq 0 ]; then
	if egrep -s "uid=0\(root\)" $TMP_FILE; then
		# uid is 0, go ahead ...
		:
	else
		printf "\n$(gettext "Root privileges are required to run this script, exiting").\n"
		error_message
	fi
else
	cat $TMP_FILE;
	printf "\n$(gettext "uid check failed, exiting").\n"
	error_message
fi

#
# Check for /etc/resolv.conf
#
if [ -r $RESOLV_CONF_FILE ]; then
	while read label text
	do
		case "$label" in
		domain) # Copy the entry into $fqdn
			if [ -z "$text" ]; then
				printf "\n$(gettext "DNS domain info malformed in %s, exiting").\n" $RESOLV_CONF_FILE
				error_message
			fi
			fqdn=$(echo "$text"|tr '[A-Z]' '[a-z]')
			break
			;;
		esac
	done <$RESOLV_CONF_FILE

	if [ -z "$fqdn" ]; then
		printf "\n$(gettext "DNS domain info missing in %s, exiting").\n" $RESOLV_CONF_FILE
		error_message
	fi
else
	#
	# /etc/resolv.conf not present, exit ...
	#
	printf "\n$(gettext "%s does not exist and is required for Kerberos setup")\n" $RESOLV_CONF_FILE
	printf "$(gettext "Refer resolv.conf(4), exiting").\n"
	error_message
fi

client_machine=$(uname -n | tr '[A-Z]' '[a-z]' | cut -d"." -f1).$fqdn

#
# Process the command-line arguments (if any)
#
OPTIND=1
while getopts np:R:k:a:c:d:f: OPTIONS
do
	case $OPTIONS in
	    p) options="$options -p"
	       profile="$OPTARG"
	       read_profile $profile
	       ;;
	    R) options="$options -R"
	       REALM="$OPTARG"
	       checkval="REALM"; check_value $REALM
	       ;;
	    k) options="$options -k"
	       KDC="$OPTARG"
	       checkval="KDC"; check_value $KDC
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
	       verify_fqdnlist "$fqdnlist"
 	       ;;
	    n) options="$options -n"
	       add_nfs=yes
	       ;;
	    \?) usage
		;;
	    *) usage
	       ;;
	esac
done

#correct argument count after options
shift `expr $OPTIND - 1`

if [ -z "$options" ]; then
	:
else
	if [ $# -ne 0 ]; then
		usage
	fi
fi

if [ -z "$dnsarg" ]; then
	query "$(gettext "Do you want to use DNS for kerberos lookups") ?"
	if [ "$answer" = yes ]; then
		printf "\n$(gettext "Valid DNS lookup options are dns_lookup_kdc, dns_lookup_realm\nand dns_fallback. Refer krb5.conf(4) for further details").\n"
		printf "\n$(gettext "Enter required DNS option"): \c"
		read dnsarg
		checkval="DNS_OPTIONS"; check_value $dnsarg
		set_dns_value $dnsarg
	fi
else
	set_dns_value $dnsarg
fi

if [ -z "$REALM" ]; then
	printf "$(gettext "Enter the Kerberos realm"): \c"
	read REALM
	checkval="REALM"; check_value $REALM
fi
if [ -z "$KDC" ]; then
	printf "$(gettext "Specify the KDC hostname for the above realm"): \c"
	read KDC
	checkval="KDC"; check_value $KDC
fi

REALM=$(echo "$REALM"|tr '[a-z]' '[A-Z]')
KDC=$(echo "$KDC"|tr '[A-Z]' '[a-z]')

echo "$KDC">$TMP_FILE
if egrep -s '[^.]\.[^.]+$' $TMP_FILE; then
	# do nothing, KDC is in fqdn format
	:
	echo "$KDC"
else
	if egrep -s '\.+' $TMP_FILE; then
		printf "\n$(gettext "Improper format of KDC hostname, exiting").\n"
		error_message
	else
		# Attach fqdn to KDC, to get the Fully Qualified Domain Name
		# of the KDC requested
		KDC=$(echo "$KDC.$fqdn")
	fi
fi
#
# Ping to see if the kdc is alive !
#
ping_check $KDC "KDC"


#
# Start writing up the krb5.conf file, save the existing one
# if already present
#
writeup_krb5_conf


#
# Done creating krb5.conf, so now we ...
#
# 1. kinit with ADMIN_PRINC
#

if [ -z "$ADMIN_PRINC" ]; then
	printf "\n$(gettext "Enter the krb5 administrative principal to be used"): \c"
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

printf "$(gettext "Obtaining TGT for %s") ...\n" $ADMIN_PRINC
KDC=$(echo "$KDC"|tr '[A-Z]' '[a-z]')
kinit -c $TMP_CCACHE -S kadmin/$KDC $ADMIN_PRINC
klist -c $TMP_CCACHE 1>$TMP_FILE 2>&1
if egrep -s "Valid starting" $TMP_FILE && egrep -s "kadmin/$KDC@$REALM" $TMP_FILE; then
    	:
else
	printf "\n$(gettext "kinit of %s failed, exiting").\n" $ADMIN_PRINC
	error_message
fi

#
# 2. Do we want to create and/or add service principal(s) for fqdn's
#    other than the one listed in resolv.conf(4) ?
#
if [ -z "$options" ]; then
	echo
	query "$(gettext "Do you have multiple DNS domains spanning the Kerberos realm") $REALM ?"
	ask_fqdns=$answer
	if [ "$ask_fqdns" = yes ]; then
		printf "$(gettext "Enter a comma-seperated list of DNS domain names"): \c"
		read fqdnlist
		verify_fqdnlist "$fqdnlist"
	else
		fqdnlist=$client_machine
	fi
else
	if [ -z "$fqdnlist" ]; then
		fqdnlist=$client_machine
	fi
fi

#
# 3. Set up keytab/config files for nfs/host/root entries (if requested)
#
echo
if [ -z "$options" ]; then
	query "$(gettext "Do you plan on doing Kerberized nfs") ?"
	add_nfs=$answer
fi

if [ "$add_nfs" = yes ]; then
	modify_nfssec_conf
	echo; call_kadmin nfs
	#
	# Check to see if the system is a pre-S10 system which would
	# require the root/FQDN svc principal for kerberized NFS.
	#
	current_release=$(uname -r | cut -d"." -f2)
	if [ $current_release -lt $release_level ]; then
		echo; call_kadmin root
	fi
fi

# Add the host entry to the keytab
echo; call_kadmin host

#
# 4. Copy over krb5.conf master copy from filepath
#
if [ -z "$options" ]; then
	echo
	query "$(gettext "Do you want to copy over the master krb5.conf file") ?"
	if [ "$answer" = yes ]; then
		printf "$(gettext "Enter the pathname of the file to be copied"): \c"
		read filepath
	fi
fi

if [ -z "$filepath" ]; then
	:
else
	if [ -r $filepath ]; then
		cp $filepath $KRB5_CONFIG_FILE
		if [ $? -eq 0 ]; then
			printf "\n$(gettext "Copied %s").\n" $filepath
		else
			printf "\n$(gettext "Copy of %s failed, exiting").\n" $filepath
			error_message
		fi
	else
		printf "\n$(gettext "%s not found, exiting").\n" $filepath
		error_message
	fi
fi

printf "\n---------------------------------------------------\n"
printf "$(gettext "Setup COMPLETE").\n"

#
# 5. Cleanup, please !
#
kdestroy -q -c $TMP_CCACHE 1>$TMP_FILE 2>&1
rm -f $TMP_FILE
exit 0
