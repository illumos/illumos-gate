#!/bin/ksh -p
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
#ident	"%Z%%M%	%I%	%E% SMI"

#
# This script runs within the scratch zone and updates the dependent files and
# pkg metadata within the zone to match the global zone.
#
# The algorithm for this is as follows:
#  1) Build the list of editable files and files to install based on the
#     dependent pkgs.  This is done in get_ed_cp_list().
#     Editable files are saved in gz_ed_list.
#     Files to install are saved in gz_cp_list
#     get_ed_cp_list() makes a pass through the global zone's contents file.
#  2) Build the list of files to remove in get_rm_list().
#     Files to remove are saved in rmlist.
#     The zone's editable files are saved in ngz_ed_list.
#     At the end we figure out which zone editable files are obsolete and those
#     are added to the rmlist.
#     get_rm_list() makes a pass through the non-global zone's contents file.
#  3) Remove the files listed in remove_files
#  4) Remove the old pkg metadata listed in remove_pkg
#  5) Copy files from the scratch zone (i.e. global zone) into the zone using
#     the gz_cp_list file.  Do this by running cpio.
#  6) Update the pkg metadata for the new pkgs using add_pkg.
#  7) Fix the editable file entries in the contents file using installf.
#
# We don't have to remove or add the pkg's in dependency order since we are
# not doing normal pkgrm or pkgadd operations.  We are simply updating pkg
# metadata with those commands.  The actual files will already be installed
# separately from the base files in the global zone using the same approach we
# use when we install a fresh zone.
#
# The script uses the following data files during the update process:
#	pkg_rm - list of pkgs to remove - provided by zoneadm
#	pkg_add - list of pkgs to add - provided by zoneadm
#	inherited - list of ipd's - provided by zoneadm
#
#	gz_ed_list - generated in get_ed_cp_list - GZ editable files
#	gz_cp_list - generated in get_ed_cp_list - files to copy from GZ
#	rmlist - generated in get_rm_list - list of file to remove
#	ngz_ed_list - generated in get_rm_list - NGZ editable files
# These files are stored in the scratch zone /tmp so there won't be any
# name conflicts with existing tmp files.
#

fatal()
{
	printf "${e_fatal}\n" "$@" >>$LOGFILE
	printf "${e_fatal}\n" "$@"
	printf "${v_loginfo}\n"
	exit 1
}

verbose_log()
{
	printf "$@" >>$LOGFILE
	printf "$@"
}

# Clean up on interrupt
trap_cleanup()
{
	printf "${e_intr}\n" >>$LOGFILE
	printf "${e_intr}\n"
	exit 1
}

save_to_log()
{
	FILENAME=$1

	echo "***** $FILENAME *****" >>$LOGFILE
	cat /tmp/$FILENAME >>$LOGFILE
	echo >>$LOGFILE
}

# 1) Build the list of editable files and files to install based on the
#    dependent pkgs.
# Processes the GZ contents file.
get_ed_cp_list()
{
	nawk '
	BEGIN {
		# Get the list of pkgs to add and see if they are hollow pkgs.
		while (getline p <"/tmp/pkg_add" > 0) {
			pkgs[p] = 1;

			pkginfo="/var/sadm/pkg/" p "/pkginfo";
			while (getline pi <pkginfo > 0) {
				if (pi ~ "SUNW_PKG_HOLLOW=true") {
					hollow[p] = 1;
					break;
				}
			}
			close(pkginfo);
		}
		close("/tmp/pkg_add");

		load_inherited();
		ndirs=0;
	}
	{
		# Read entries in the contents file, figure out what kind of
		# entry this is and where the pkg data is.
		# tp indicates what type of entry this is:
		#     editable or volatile files are tp == 0
		#     files are tp == 1
		#     dirs are tp == 2
		#     symlinks or hardlinks are tp == 1
		# fld is the field where the pkg names begin.
		# nm is the file/dir entry name.
		if ($2 == "e" || $2 == "v") {
			fld=10;
			nm=$1;
			tp=0;
		} else if ($2 == "f") {
			fld=10;
			nm=$1;
			tp=1;
		} else if ($2 == "d") {
			fld=7;
			nm=$1;
			tp=2;
		} else if ($2 == "s" || $2 == "l") {
			fld=4;
			split($1, a, "=");
			nm=a[1];
			tp=1;
		} else {
			next;
		}

		# Skip it if it is in an ipd.
		if (is_inherited(nm))
			next;

		# Determine if this entry is part of a pkg to install
		# and if it is in a hollow pkg.
		installpkg = 0;
		nhollow = 0;
		for (i = fld; i <= NF; i++) {
			pname = get_pkg_name($i)

			if (pkgs[pname] == 1)
				installpkg = 1;
			if (hollow[pname] == 1)
				nhollow++;
		}

		if (installpkg == 0)
			next;

		# If this entry is only in hollow pkgs, skip it.
		if (nhollow >= (NF - fld + 1))
			next;

		if (tp == 0) {
			# editable or volatile file
			printf("/a%s\n", nm) >>"/tmp/gz_ed_list";
		} else if (tp == 1) {
			# regular file or link
			printf("%s\n", nm) > "/tmp/gz_cp_list";
		} else {
			# directory
			dirs[ndirs++] = nm;
		}
	}
	END {
		for (i = ndirs - 1; i >= 0; i--)
			printf("%s\n", dirs[i]) > "/tmp/gz_cp_list";
	}

	# Get the list of inherited directories.
	# We are creating an array of regular expression matches here.
	function load_inherited() {
		nint=0
		while (getline p <"/tmp/inherited" > 0) {
			inherited[nint] = "^" p "/";
			nint++;
			inherited[nint] = "^" p "$";
			nint++;
		}
		close("/tmp/inherited");
	}

	# Check if this entry is in an inherited-pkg-dir.
	function is_inherited(nm) {
		for (i = 0; i < nint; i++) {
			if (nm ~ inherited[i])
				return (1);
		}
		return (0);
	}

	# Get the clean pkg name from the fld entry.
	function get_pkg_name(fld) {
		# Remove any pkg control prefix (e.g. *, !)
		first = substr(fld, 1, 1)
		if (match(first, /[A-Za-z]/)) {
			pname = fld 
		} else {
			pname = substr(fld, 2)
		}

		# Then remove any class action script name
		pos = index(pname, ":")
		if (pos != 0)
			pname = substr(pname, 1, pos - 1)

		return (pname)
	}

	' /var/sadm/install/contents || fatal "get_ed_cp_list"
}

create_admin_file()
{
	cat <<-EOF > /tmp/admin.dflt || fatal "create_admin_file"
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
}

# 2) Build the list of files to remove.
# Similar structure to get_ed_cp_list() but we're processing the NGZ contents
# file.
get_rm_list()
{
	nawk '
	BEGIN {
		while (getline p <"/tmp/pkg_rm" > 0)
			pkgs[p] = 1;
		close("/tmp/pkg_rm");
		load_inherited();
	}
	{
		# fld is the field where the pkg names begin.
		# nm is the file/dir entry name.
		# rm is set if we should remove the entry.
		if ($2 == "e" || $2 == "v") {
			fld=10;
			nm=$1;
			rm=0;
		} else if ($2 == "f") {
			fld=10;
			nm=$1;
			rm=1;
		} else if ($2 == "d") {
			fld=7;
			nm=$1;
			rm=1;
		} else if ($2 == "s" || $2 == "l") {
			fld=4;
			split($1, a, "=");
			nm=a[1];
			rm=1;
		} else {
			next;
		}

		# Skip it if it is in an ipd.
		if (is_inherited(nm))
			next;

		# Check if this entry is part of a pkg to remove.  Files,
		# including editable files, can be delivered by multiple pkgs.
		# We should only add this entry to the rm list or ed list if
		# all of the pkgs delivering this entry are being removed.
		for (i = fld; i <= NF; i++) {
			pname = get_pkg_name($i)

			# If this is in a pkg we are not removing, we are done.
			if (pkgs[pname] == 0)
				next;
		}

		if (rm == 1)
			printf("/a%s\n", nm) >>"/tmp/rmlist";
		else
			printf("/a%s\n", nm) >>"/tmp/ngz_ed_list";

	}

	# Get the list of inherited directories.
	# We are creating an array of regular expression matches here.
	function load_inherited() {
		nint=0
		while (getline p <"/tmp/inherited" > 0) {
			inherited[nint] = "^" p "/";
			nint++;
			inherited[nint] = "^" p "$";
			nint++;
		}
		close("/tmp/inherited");
	}

	# Check if this entry is in an inherited-pkg-dir.
	function is_inherited(nm) {
		for (i = 0; i < nint; i++) {
			if (nm ~ inherited[i])
				return (1);
		}
		return (0);
	}

	# Get the clean pkg name from the fld entry.
	function get_pkg_name(fld) {
		# Remove any pkg control prefix (e.g. *, !)
		first = substr(fld, 1, 1)
		if (match(first, /[A-Za-z]/)) {
			pname = fld 
		} else {
			pname = substr(fld, 2)
		}

		# Then remove any class action script name
		pos = index(pname, ":")
		if (pos != 0)
			pname = substr(pname, 1, pos - 1)

		return (pname)
	}

	' /a/var/sadm/install/contents || fatal "get_rm_list"

	# Add the obsolete editable files to the rm list.
	# comm assumes the files are sorted.  Since the contents file is
	# sorted and we wrote the files as we processed the contents file,
	# these files are already sorted.
	comm -13 /tmp/gz_ed_list /tmp/ngz_ed_list >>/tmp/rmlist || \
	    fatal "get_rm_list"
}

remove_files()
{
	for path in `cat /tmp/rmlist`
	do
		if [ "$path" != "" ] ; then
			# Check for symlink first since -d follows links.
			if [ -h $path ]; then
				rm -f $path || fatal "remove_files"
			elif [ -d $path ]; then
				# ignore errs since dir might not be empty
				rmdir $path >/dev/null 2>&1
			else
				rm -f $path || fatal "remove_files"
			fi
		fi
	done
}

remove_pkg()
{
	PKG=$1
	NUM=$2
	CNT=$3

	# pkgremove options:
	# -a	same as public pkgrm option
	# -F	private - used by upgrade to suppress actual removal of files
	#	delivered by the pkg
	# -M	same as public pkgrm option
	# -n	same as public pkgrm option
	# -O inherited-filesystem={IPD}	private - used to specify the zone's
	#	inherited-pkg-dir entries
	# -R	same as public pkgrm option
	/usr/sadm/install/bin/pkgremove -R /a -M -F -a /tmp/admin.dflt -n \
	    $IPDS $PKG >>$LOGFILE 2>&1
	errcode=$?
	printf "${v_rmpkgs}" $NUM $CNT
	# errcode 99 means the pkg doesn't exist.
	if [ $errcode -ne 0 -a $errcode -ne 99 ]; then
		ERR_PKGS=`echo $ERR_PKGS $PKG`
	fi
}

add_pkg()
{
	PKG=$1
	NUM=$2
	CNT=$3

	echo "===== ${PKG} ====" >>$LOGFILE
	# pkginstall options:
	# -a	same as public pkgrm option
	# -C	private - disable checksums since files are installed via a
	#	separate copy from the global zone
	# -h	private - enable hollow pkg support
	# -N pkgadd	private - error msgs use the name "pkgadd" instead
	#	of "pkginstall"
	# -n	same as public pkgrm option
	# -O addzonename	private - error msgs include zonename
	# -O inherited-filesystem={IPD}	private - used to specify the zone's
	#	inherited-pkg-dir entries
	# -R	same as public pkgrm option
	# -S	private - suppress copyright output
	# -t	private - suppress spooled pkg creation
	# -z	private - install zone pkg data from spooled pkg data
	/usr/sadm/install/bin/pkginstall -S -A -C -N pkgadd -R /a \
	    -a /etc/lu/zones_pkgadd_admin -h -n -t -z $IPDS -O addzonename \
	    /var/sadm/pkg/${PKG}/save/pspool $PKG >>$LOGFILE 2>&1
	errcode=$?
	printf "${v_addpkgs}" $NUM $CNT
	if [ $errcode -ne 0 ]; then
		ERR_PKGS=`echo $ERR_PKGS $PKG`
	fi
}

# installf the editable file so that the pkg metadata is correct.
finalize()
{
	nawk -v lf=$LOGFILE '
	BEGIN {
		logfile = " >>" lf " 2>&1"

		while (getline e <"/tmp/ngz_ed_list" > 0) {
			# remove /a/ prefix from the name
			nm=substr(e, 3)
			ed_path[nm] = 1;
		}
		close("/tmp/ngz_ed_list");
	}
	{
		if ($2 != "e" && $2 != "v")
			next;

		# For the contents file format:
		#     editable and volatile entry pkg names start at field 10
		#     $1 is filename, $2 is type (e or v), $3 is class name
		# That is:
		#   installf -R /a -c class pkgname filename type
		for (i = 10; i <= NF; i++) {
			if (ed_path[$1] == 1) {
				pname = get_pkg_name($i)

				pkg[pname] = 1;
				printf("%s\n", $1);
				basecmd = "/usr/sbin/installf -R /a -c "
				cmd = basecmd $3 " " pname " " $1 " " $2 logfile
				if (system(cmd) != 0)
					printf("ERROR: %s\n", cmd);
			}
		}
	}
	END {
		for (p in pkg) {
			printf("Finalize %s\n", p);
			cmd = "/usr/sbin/installf -R /a -f " p logfile
			if (system(cmd) != 0)
				printf("ERROR: %s\n", cmd);
		}
	}

	# Get the clean pkg name from the fld entry.
	function get_pkg_name(fld) {
		# Remove any pkg control prefix (e.g. *, !)
		first = substr(fld, 1, 1)
		if (match(first, /[A-Za-z]/)) {
			pname = fld 
		} else {
			pname = substr(fld, 2)
		}

		# Then remove any class action script name
		pos = index(pname, ":")
		if (pos != 0)
			pname = substr(pname, 1, pos - 1)

		return (pname)
	}

	' /a/var/sadm/install/contents >>$LOGFILE || fatal "finalize"
}

PATH=/sbin:/usr/bin:/usr/sbin; export PATH

SUNW_PKG_INSTALL_ZONENAME=$1
export SUNW_PKG_INSTALL_ZONENAME

# Setup i18n output
TEXTDOMAIN="SUNW_OST_OSCMD"
export TEXTDOMAIN

v_gathering=$(gettext "Getting the list of files to remove")
v_rmfiles=$(gettext "Removing %d files")
v_rmpkgs=$(gettext "Remove %d of %d packages\r")
v_instfiles=$(gettext "Installing %d files")
v_addpkgs=$(gettext "Add %d of %d packages\r")
v_updating=$(gettext "Updating editable files")
v_loginfo=$(gettext "The file </var/sadm/system/logs/update_log> within the zone contains a log of the zone update.")
e_intr=$(gettext "update cancelled due to interrupt")
e_rmpkgs=$(gettext "Problems removing the following pkgs: %s")
e_instkgs=$(gettext "Installation of these packages generated warnings: %s")
e_fatal=$(gettext "ERROR: zone update fatal error at: %s")

LOGFILE=/a/var/sadm/system/logs/update_log

if [ -f $LOGFILE ]; then
	tmpnm=$LOGFILE.`date +%y%m%d-%H:%M:%S` 
	mv $LOGFILE $tmpnm || fatal "backup log file"
fi

trap trap_cleanup INT

echo "`date`" >$LOGFILE
echo >>$LOGFILE

# Save file lists to LOGFILE
save_to_log inherited
save_to_log pkg_rm
save_to_log pkg_add

printf "${v_gathering}\n"

# Make sure we have these files, even though they might be empty.
touch /tmp/gz_ed_list /tmp/ngz_ed_list /tmp/gz_cp_list || fatal "touch files"

# Get the list of editable files for the dependent pkgs.  We do this to make
# sure we delete obsolete editable files as part of the removal of the files
# within the zone.  In the same pass through the contents file we get the
# list of files to copy into the zone.
get_ed_cp_list

save_to_log gz_cp_list
save_to_log gz_ed_list

get_rm_list
sort -r -o /tmp/rmlist /tmp/rmlist || fatal "sort rmlist"

save_to_log ngz_ed_list
save_to_log rmlist

CNT=`wc -l /tmp/rmlist | nawk '{print $1}'`
verbose_log "${v_rmfiles}\n" $CNT
remove_files

IPDS=""
for i in `cat /tmp/inherited`
do
	IPDS=`echo $IPDS -O inherited-filesystem=$i`
done

create_admin_file

echo "***** remove_pkg *****" >>$LOGFILE

ERR_PKGS=""
CNT=`wc -l /tmp/pkg_rm | nawk '{print $1}'`
num=1
for i in `cat /tmp/pkg_rm`
do
	remove_pkg $i $num $CNT
	num=`expr $num + 1`
done

echo
if [ -n "$ERR_PKGS" ]; then
	verbose_log "${e_rmpkgs}\n" "$ERR_PKGS"
fi

echo >>$LOGFILE

CNT=`wc -l /tmp/gz_cp_list | nawk '{print $1}'`
verbose_log "${v_instfiles}\n" $CNT
echo "***** cpio *****" >>$LOGFILE
cpio -pcdmu /a < /tmp/gz_cp_list >>$LOGFILE 2>&1

echo >>$LOGFILE
echo "***** add_pkg *****" >>$LOGFILE

ERR_PKGS=""
CNT=`wc -l /tmp/pkg_add | nawk '{print $1}'`
num=1
for i in `cat /tmp/pkg_add`
do
	add_pkg $i $num $CNT
	num=`expr $num + 1`
done

echo
if [ -n "$ERR_PKGS" ]; then
	verbose_log "${e_instkgs}\n" "$ERR_PKGS"
fi

echo >>$LOGFILE
echo "***** finalize *****" >>$LOGFILE

verbose_log "${v_updating}\n"
finalize

verbose_log "${v_loginfo}\n"

exit 0
