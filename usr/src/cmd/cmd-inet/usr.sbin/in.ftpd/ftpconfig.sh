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
#
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
# This script sets up anonymous FTP on the current host.
#
# Usage:
#	ftpconfig [ftpdir]
#	ftpconfig -d ftpdir
#
# ftpconfig without any arguments updates the files required by anonymous FTP
# in an existing ftp users home directory.
#
# If ftpdir (which must be an absolute pathname) is supplied, ftpconfig
# creates an ftp user account with a home directory of ftpdir, or updates
# an existing ftp user account to have a home directory of ftpdir.
#
# If ftpdir already exists, the files it contains which are required by
# anonymous FTP are updated, otherwise ftpdir is created containing the files
# required by anonymous FTP.
#
# The -d (directory only) option just creates a new or updates an existing
# ftpdir without creating or updating the ftp user account. This is useful
# when creating guest FTP user accounts.
#
# Exit codes:	0 - success
#		1 - usage
#		2 - command failure
#

usage()
{
	fmt=`gettext "Usage: %s [ftpdir]\n       %s -d ftpdir"`
	printf "$fmt\n" "$cmd" "$cmd" >&2
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

# Make directory $1 under $home_dir with mode $2 and ownership $3.
make_dir()
{
	# Make a special case of creating $home_dir itself
	if [ -z "$1" ]
	then
		dir="$home_dir"
	else
		dir="$home_dir/$1"
	fi
	if [ ! -d "$dir" ]
	then
		mkdir "$dir" || exit 2
	fi
	chmod "$2" "$dir"
	chown "$3" "$dir"
}

# Copy file $1 to under $home_dir with mode $2 and ownership $3.
copy_file()
{
	if [ -f "$1" ]
	then
		file="$home_dir$1"
		rm -f "$file"
		cp "$1" "$file" || exit 2
		chmod "$2" "$file"
		chown "$3" "$file"
	fi
}

add_user()
{
	pwent=`grep "^$username:" /etc/passwd`
	if [ -z "$pwent" ]
	then
		# No existing ftp account.
		if [ -z "$home_dir" ]
		then
			fmt=`gettext "%s: Error: No directory specified and no existing ftp account to update"`
			printf "$fmt\n" "$cmd" >&2
			exit 1
		fi

		# Create a new ftp account.
		comment="Anonymous FTP"
		fmt=`gettext "Creating user %s"`
		printf "$fmt\n" "$username"
		/usr/sbin/useradd -c "$comment" -d "$home_dir" -s "$login_shell" -g other "$username" || exit 2
	else
		# ftp account already exists.
		if [ -z "$home_dir" ]
		then
			home_dir=`echo "$pwent" | cut -d: -f6`
			if [ -z "$home_dir" ]
			then
				fmt=`gettext "%s: Error: Existing ftp account has no home directory"`
				printf "$fmt\n" "$cmd" >&2
				exit 2
			fi
		else
			# Update an existing ftp account.
			old_dir=`echo "$pwent" | cut -d: -f6`
			if [ "$old_dir" != "$home_dir" ]
			then
				fmt=`gettext "Updating user %s"`
				printf "$fmt\n" "$username"
				/usr/sbin/usermod -d "$home_dir" "$username" || exit 2
			fi
		fi
	fi
}

list_pam_session()
{
	# Produce a list of the PAM session management modules.
	if [ -f /etc/pam.conf ]
	then
		awk '($1 == "ftp" || $1 == "other") && $2 == "session" {
			if ($4 !~ /^\//) printf "/usr/lib/security/"
			print $4
		}' </etc/pam.conf | sed 's/$ISA\///'
	fi
}

list_conv_cmds()
{
	# Produce a list of the commands specified in the conversions file.
	if [ -f /etc/ftpd/ftpconversions ]
	then
		sed 's/#.*$//' /etc/ftpd/ftpconversions | cut -d: -f5 |
			awk '$1 !~ /^$/ { print $1 }' | sort -u
	fi
}

list_dyn_libs()
{
	# Produce a list of the required dynamic libraries.
	for file in $* /usr/sbin/in.ftpd /usr/bin/ls `list_conv_cmds`
	do
		ldd "$file" 2>/dev/null | cut -d'>' -f2
	done | sort -u
}

create_home_dir()
{
	if [ "$home_dir" = "/" -o "$home_dir" = "/usr" ]
	then
		fmt=`gettext "%s: Error: Installing FTP in %s is not permitted"`
		printf "$fmt\n" "$cmd" "$home_dir" >&2
		exit 1
	fi

	if [ ! -d "$home_dir" ]
	then
		if [ -e "$home_dir" ]
		then
			fmt=`gettext "%s: Error: %s already exists but is not a directory"`
			printf "$fmt\n" "$cmd" "$home_dir" >&2
			exit 2
		else
			fmt=`gettext "Creating directory %s"`
			printf "$fmt\n" "$home_dir"
			make_dir "" 755 root:sys
		fi
	fi
}

install_slash_etc()
{
	# Preserve an existing etc directory.
	make_dir etc 111 root:sys
	make_dir etc/ftpd 111 root:sys

	# Create a stripped down password file.
	rm -f "$home_dir/etc/passwd"
	awk -F: '$1 ~ /^root$|^bin$|^sys$|^ftpadm$|^ftp$/ { print $1":x:"$3":"$4":::" }' </etc/passwd >"$home_dir/etc/passwd"
	chmod 444 "$home_dir/etc/passwd"
	chown root:sys "$home_dir/etc/passwd"

	# Create a stripped down group file.
	rm -f "$home_dir/etc/group"
	awk -F: '$1 ~ /^root$|^other$|^bin$|^sys$|^ftpadm$/ { print $1"::"$3":" }' </etc/group >"$home_dir/etc/group"
	chmod 444 "$home_dir/etc/group"
	chown root:sys "$home_dir/etc/group"

	# Copy in /etc/default/init, needed for timezone.
	if [ -f /etc/default/init ]
	then
		make_dir etc/default 111 root:sys
		copy_file /etc/default/init 444 root:sys
	fi

	# Copy in files used for hostname resolution
	copy_file /etc/hosts 444 root:sys
	copy_file /etc/resolv.conf 444 root:sys
	make_dir etc/inet 111 root:sys
	copy_file /etc/inet/ipnodes 444 root:sys
}

install_slash_usr()
{
	# Preserve an existing usr directory.
	make_dir usr 111 root:sys
	make_dir usr/bin 111 root:bin

	if [ -h "$home_dir/bin" ]
	then
		rm -f "$home_dir/bin"
	fi
	if [ ! -e "$home_dir/bin" ]
	then
		ln -s ./usr/bin "$home_dir/bin" || exit 2
		chown -h root:bin "$home_dir/bin"
	fi

	# Copy required dynamic libraries and PAM session management modules.
	libs="/lib/nss_files.so.1 /lib/nss_dns.so.1 /lib/libresolv.so.2"
	for lib in /lib/ld.so.1 $libs `list_dyn_libs $libs` `list_pam_session`
	do
		if [ -f "$lib" ]
		then
			dir=`dirname "$home_dir$lib"`
			if [ ! -d "$dir" ]
			then
				mkdir -p "$dir" || exit 2
			fi
			copy_file "$lib" 555 root:bin
		fi
	done

	# Copy required commands.
	for prog in /usr/bin/ls `list_conv_cmds`
	do
		if [ -f "$prog" ]
		then
			dir=`dirname "$home_dir$prog"`
			if [ ! -d "$dir" ]
			then
				mkdir -p "$dir" || exit 2
			fi
			copy_file "$prog" 111 root:bin
		fi
	done

	# Copy timezone files.
	if [ -d /usr/share/lib/zoneinfo ]
	then
		rm -rf "$home_dir/usr/share/lib/zoneinfo"
		find /usr/share/lib/zoneinfo | cpio -pduL "$home_dir" >/dev/null 2>&1
		(cd "$home_dir/usr/share/lib"; find zoneinfo -type f |
			xargs chmod 444)
		rm -rf "$home_dir/usr/share/lib/zoneinfo/src"
	fi

	for dir in usr lib platform
	do
		if [ -d "$home_dir/$dir" ]
		then
			(cd "$home_dir"; find $dir -type d | xargs chmod 111)
			(cd "$home_dir"; find $dir -type d | xargs chown root:bin)
			[ $dir != "lib" ] && chown root:sys "$home_dir/$dir"
		fi
	done
}

install_slash_dev()
{
	# Preserve an existing dev directory.
	make_dir dev 111 root:sys

	# Copy devices.
	for devname in conslog null udp udp6 zero
	do
		rm -f "$home_dir/dev/$devname"
	done
	cpio -pduL "$home_dir" >/dev/null 2>&1 <<-EOF
	/dev/conslog
	/dev/null
	/dev/udp
	/dev/udp6
	/dev/zero
	EOF
	if [ $? -ne 0 ]
	then
		fmt=`gettext "%s: Error: Creation of devices in %s failed"`
		printf "$fmt\n" "$cmd" "$home_dir/dev" >&2
		exit 2
	fi
}

install_slash_pub()
{
	# Preserve an existing pub directory.
	make_dir pub 755 root:sys
}

update_home_dir()
{
	fmt=`gettext "Updating directory %s"`
	printf "$fmt\n" "$home_dir"
	install_slash_dev
	install_slash_etc
	install_slash_usr
	install_slash_pub
}

# Execution starts here.

IFS=" 	
"
SHELL=/usr/bin/ksh
PATH=/usr/bin
TEXTDOMAIN=SUNW_OST_OSCMD
export SHELL PATH IFS TEXTDOMAIN

cmd=`basename "$0"`
username=ftp
login_shell=/bin/true

verify_root

while getopts d arg
do
	case $arg in
	d)	directory_only=1;;
	\?)	usage;;
	esac
done
shift `expr $OPTIND - 1`

# Check arguments.
[ $# -gt 1 ] && usage

home_dir="$1"
if [ -n "$directory_only" -a -z "$home_dir" ]
then
	fmt=`gettext "%s: Error: ftpdir required with -d option"`
	printf "$fmt\n" "$cmd" >&2
	usage
fi

if [ -n "$home_dir" ]
then
	echo "$home_dir" | grep "^/" >/dev/null 2>&1
	if [ $? -ne 0 ]
	then
		fmt=`gettext "%s: Error: ftpdir must be an absolute pathname"`
		printf "$fmt\n" "$cmd" >&2
		usage
	fi
fi

# Ignore certain signals.
trap '' 1 2 3 15

umask 022
[ -z "$directory_only" ] && add_user

create_home_dir
update_home_dir

exit 0
