#!/usr/bin/ksh
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1997-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#
# This script sets up a virtual FTP host.
#
# Usage:
#	ftpaddhost -c|-l [-b] [ -x xferlog ] hostname root_dir
#
# ftpaddhost configures virtual host hostname under directory root_dir.
# An IP address can be used for hostname.
#
# The -c (complete) option configures complete virtual hosting, which allows
# each virtual host to have its own version of the ftpaccess, ftpconversions,
# ftpgroups, ftphosts and ftpusers files. The master version of each of these
# configuration files is copied from the /etc/ftpd directory and placed in
# the /etc/ftpd/virtual-ftpd/hostname directory. If the /etc/ftpusers file
# exists it is appended to the virtual ftpusers file. If a virtual host lacks
# its own version of a configuration file, the master version is used.
#
# The -l (limited) option configures limited virtual hosting, which only
# allows a small number of parameters to be configured differently for a
# virtual host (see the virtual keyword on the ftpaccess(4) manual page).
#
# When the -b (banner) option is supplied, ftpaddhost creates a banner for
# the virtual host, useful to see that the virtual host is working.
#
# When the -x xferlog option is supplied, ftpaddhost creates a logfile entry
# which causes the transfer logs for the virtual host to be written to the
# specified file.
#
# Exit codes:	0 - success
#		1 - usage
#		2 - command failure
#

usage()
{
	fmt=`gettext "Usage: %s -c|-l [-b] [ -x xferlog ] hostname root_dir"`
	printf "$fmt\n" "$cmd" >&2
	exit 1
}

verify_root()
{
	# Verify caller has a real user ID of 0.
	set `id`
	if [ "$1" != "uid=0(root)" ]
	then
		fmt=`gettext "%s: Error: Only root can run %s"`
		printf "$fmt\n" "$cmd" "$cmd" >&2
		exit 1
	fi
}

# Make directory $1 with mode $2 and ownership $3.
make_dir()
{
	if [ ! -d "$1" ]
	then
		mkdir "$1" || exit 2
	fi
	chmod "$2" "$1"
	chown "$3" "$1"
}

setup_complete_vhost()
{
	fmt=`gettext "Setting up complete virtual host %s"`
	printf "$fmt\n" "$hostname"
	make_dir /etc/ftpd/virtual-ftpd 755 root:sys
	make_dir "/etc/ftpd/virtual-ftpd/$hostname" 755 root:sys

	fmt=`gettext "Configuration directory is %s"`
	printf "$fmt\n" "/etc/ftpd/virtual-ftpd/$hostname"

	# Update the virtual host configuration file.
	vhconfig=/etc/ftpd/ftpservers

	fmt=`gettext "Updating virtual hosting configuration file %s"`
	printf "$fmt\n" $vhconfig
	if [ -f $vhconfig ]
	then
		# Remove any existing entries for the virtual host.
		sed "/^[ 	]*$hostname[ 	]/d" $vhconfig >$vhconfig.tmp.$$
		mv -f $vhconfig.tmp.$$ $vhconfig || exit 2
	fi

	echo "$hostname /etc/ftpd/virtual-ftpd/$hostname" >>$vhconfig
	chmod 644 $vhconfig
	chown root:sys $vhconfig

	# Make copies of the master configuration files.
	for file in ftpconversions ftpgroups ftphosts ftpusers
	do
		target="/etc/ftpd/virtual-ftpd/$hostname/$file"
		rm -f "$target"
		if [ -f /etc/ftpd/$file ]
		then
			cp /etc/ftpd/$file "$target" || exit 2
			chmod 644 "$target"
			chown root:sys "$target"
		fi
	done

	# Append /etc/ftpusers to the virtual hosts ftpusers.
	if [ -f /etc/ftpusers ]
	then
		target="/etc/ftpd/virtual-ftpd/$hostname/ftpusers"
		cat /etc/ftpusers >>"$target"
		chmod 644 "$target"
		chown root:sys "$target"
	fi

	vhftpaccess="/etc/ftpd/virtual-ftpd/$hostname/ftpaccess"
	rm -f "$vhftpaccess"

	# Remove any existing root or logfile entries.
	sed "/^[ 	]*root[ 	]/d
	     /^[ 	]*logfile[ 	]/d" $ftpaccess >"$vhftpaccess"

	# Add the virtual host root.
	echo "root $vhroot" >>"$vhftpaccess"

	# Add a banner to show the virtual host configuration worked.
	if [ -n "$banner" ]
	then
		# Add a banner entry if there isn't already one.
		grep "^[ 	]*banner[ 	]" "$vhftpaccess" >/dev/null 2>&1
		if [ $? -eq 0 ]
		then
			fmt=`gettext "Existing banner entry not changed in %s"`
			printf "$fmt\n" "$vhftpaccess"
		else
			bannerf="/etc/ftpd/virtual-ftpd/$hostname/cbanner.msg"
			if [ -f "$bannerf" ]
			then
				fmt=`gettext "Using existing banner file %s"`
				printf "$fmt\n" "$bannerf"
			else
				fmt=`gettext "Creating banner file %s"`
				printf "$fmt\n" "$bannerf"
				fmt=`gettext "Complete virtual host %%L test banner"`
				printf "$fmt\n" >"$bannerf"
				chmod 644 "$bannerf"
				chown root:sys "$bannerf"
			fi
			echo "banner $bannerf" >>"$vhftpaccess"
		fi
	fi

	# Add the transfer logfile.
	if [ -n "$logfile" ]
	then
		echo "logfile $logfile" >>"$vhftpaccess"
	fi

	chmod 644 "$vhftpaccess"
	chown root:sys "$vhftpaccess"
}

setup_limited_vhost()
{
	# Check complete virtual hosting is not configured for the host.
	grep "^[ 	]*$hostname[ 	]" /etc/ftpd/ftpservers >/dev/null 2>&1
	if [ $? -eq 0 ]
	then
		fmt=`gettext "%s: Error: Complete virtual hosting already configured for %s"`
		printf "$fmt\n" "$cmd" "$hostname" >&2
		exit 1
	fi

	fmt=`gettext "Setting up limited virtual host %s"`
	printf "$fmt\n" "$hostname"

	# Update the ftpaccess file.
	fmt=`gettext "Updating FTP server configuration file %s"`
	printf "$fmt\n" $ftpaccess

	# Remove any existing entries for the virtual host.
	sed "/^[ 	]*virtual[ 	][ 	]*$hostname[ 	]/d" $ftpaccess >$ftpaccess.tmp.$$
	mv -f $ftpaccess.tmp.$$ $ftpaccess || exit 2

	# Add a limited virtual hosting entry for the virtual host.
	echo "virtual $hostname root $vhroot" >>$ftpaccess

	# Add a banner to show the virtual host configuration worked.
	if [ -n "$banner" ]
	then
		bannerf="/etc/ftpd/virtual-ftpd/$hostname/lbanner.msg"
		if [ -f "$bannerf" ]
		then
			fmt=`gettext "Using existing banner file %s"`
			printf "$fmt\n" "$bannerf"
		else
			fmt=`gettext "Creating banner file %s"`
			printf "$fmt\n" "$bannerf"
			make_dir /etc/ftpd/virtual-ftpd 755 root:sys
			make_dir "/etc/ftpd/virtual-ftpd/$hostname" 755 root:sys
			fmt=`gettext "Limited virtual host %%L test banner"`
			printf "$fmt\n" >"$bannerf"
			chmod 644 "$bannerf"
			chown root:sys "$bannerf"
		fi
		echo "virtual $hostname banner $bannerf" >>$ftpaccess
	fi

	# Add the transfer logfile.
	if [ -n "$logfile" ]
	then
		echo "virtual $hostname logfile $logfile" >>$ftpaccess
	fi

	chmod 644 $ftpaccess
	chown root:sys $ftpaccess
}

# Execution starts here.

IFS=" 	
"
SHELL=/usr/bin/ksh
PATH=/usr/bin
TEXTDOMAIN=SUNW_OST_OSCMD
export SHELL PATH IFS TEXTDOMAIN

cmd=`basename "$0"`

verify_root

while getopts bclx: arg
do
	case $arg in
	b)	banner=1;;
	c)	complete=1;;
	l)	limited=1;;
	x)	logfile="$OPTARG";;
	\?)	usage;;
	esac
done
shift `expr $OPTIND - 1`

# Check arguments.
[ -z "$complete" -a -z "$limited" ] && usage
[ -n "$complete" -a -n "$limited" ] && usage

[ $# -ne 2 ] && usage
hostname="$1"
vhroot="$2"

[ -z "$hostname" -o -z "$vhroot" ] && usage

echo "$hostname" | grep / >/dev/null 2>&1
if [ $? -eq 0 ]
then
	fmt=`gettext "%s: Error: hostname must not contain a /"`
	printf "$fmt\n" "$cmd" >&2
	usage
fi

echo "$vhroot" | grep "^/" >/dev/null 2>&1
if [ $? -ne 0 ]
then
	fmt=`gettext "%s: Error: root_dir must be an absolute pathname"`
	printf "$fmt\n" "$cmd" >&2
	usage
fi

if [ -n "$logfile" ]
then
	echo "$logfile" | grep "^/" >/dev/null 2>&1
	if [ $? -ne 0 ]
	then
		fmt=`gettext "%s: Error: xferlog must be an absolute pathname"`
		printf "$fmt\n" "$cmd" >&2
		usage
	fi
fi

ftpaccess=/etc/ftpd/ftpaccess
if [ ! -f $ftpaccess ]
then
	fmt=`gettext "%s: Error: FTP server configuration file %s missing"`
	printf "$fmt\n" "$cmd" $ftpaccess >&2
	exit 2
fi

grep "^ftp:" /etc/passwd >/dev/null 2>&1
if [ $? -ne 0 ]
then
	fmt=`gettext "Warning: Must create ftp user account before virtual hosts will work"`
	printf "$fmt\n"
fi

# Ignore certain signals.
trap '' 1 2 3 15

umask 022

if [ -n "$complete" ]
then
	setup_complete_vhost
else
	setup_limited_vhost
fi

/usr/sbin/ftpconfig -d "$vhroot" >/dev/null
if [ $? -ne 0 ]
then
	fmt=`gettext "%s: Error: ftpconfig -d %s failed"`
	printf "$fmt\n" "$cmd" "$vhroot" >&2
	exit 2
fi

exit 0
