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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2014, Joyent, Inc. All rights reserved.
#

#
# Send the error message to the screen and to the logfile.
#
error()
{
        typeset fmt="$1"
        shift

        printf "${MSG_PREFIX}ERROR: ${fmt}\n" "$@"
        [[ -n $LOGFILE ]] && printf "[$(date)] ERROR: ${fmt}\n" "$@" >&2
}

fatal()
{
        typeset fmt="$1"
        shift

	error "$fmt" "$@"
	exit $EXIT_CODE
}

fail_fatal() {
        typeset fmt="$1"
        shift

	error "$fmt" "$@"
	exit $ZONE_SUBPROC_FATAL
}

#
# Send the provided printf()-style arguments to the screen and to the logfile.
#
log()
{
        typeset fmt="$1"
        shift

        printf "${MSG_PREFIX}${fmt}\n" "$@"
        [[ -n $LOGFILE ]] && printf "[$(date)] ${MSG_PREFIX}${fmt}\n" "$@" >&2
}

#
# Print provided text to the screen if the shell variable "OPT_V" is set.
# The text is always sent to the logfile.
#
vlog()
{
        typeset fmt="$1"
        shift

        [[ -n $OPT_V ]] && printf "${MSG_PREFIX}${fmt}\n" "$@"
        [[ -n $LOGFILE ]] && printf "[$(date)] ${MSG_PREFIX}${fmt}\n" "$@" >&2
}

#
# Validate that the directory is safe.
#
# It is possible for a malicious zone root user to modify a zone's filesystem
# so that modifications made to the zone's filesystem by administrators in the
# global zone modify the global zone's filesystem.  We can prevent this by
# ensuring that all components of paths accessed by scripts are real (i.e.,
# non-symlink) directories.
#
# NOTE: The specified path should be an absolute path as would be seen from
# within the zone.  Also, this function does not check parent directories.
# If, for example, you need to ensure that every component of the path
# '/foo/bar/baz' is a directory and not a symlink, then do the following:
#
#	safe_dir /foo
#	safe_dir /foo/bar
#	safe_dir /foo/bar/baz
#
safe_dir()
{
	typeset dir="$1"
	typeset pwd_dir=""

	if [[ -d $ZONEROOT/$dir ]]; then
		if [[ -h $ZONEROOT/$dir ]]; then
			#
			# When dir is a symlink to a directory, we 'cd' to that
			# directory to ensure that's under $ZONEROOT. We use pwd
			# from /usr/bin instead of built-in because they give
			# different results.
			#
			pwd_dir=$(cd $ZONEROOT/$dir && /usr/bin/pwd)
			if [[ $pwd_dir =~ "^$ZONEROOT" ]]; then
				return;
			else
				fatal \
				    "$e_baddir: symlink out of zoneroot" "$dir"
			fi
		else
			# it's a dir and not a symlink, so that's ok.
			return
		fi
	fi
}

# Like safe_dir except the dir doesn't have to exist.
safe_opt_dir()
{
	typeset dir="$1"

	[[ ! -e $ZONEROOT/$dir ]] && return

	safe_dir $dir
}

# Only make a copy if we haven't already done so.
safe_backup()
{
	typeset src="$1"
	typeset dst="$2"

	if [[ ! -h $src && ! -h $dst && ! -d $dst && ! -f $dst ]]; then
		/usr/bin/cp -p $src $dst || fatal "$e_badfile" "$src"
	fi
}

# Make a copy even if the destination already exists.
safe_copy()
{
	typeset src="$1"
	typeset dst="$2"

	if [[ ! -h $src && ! -h $dst && ! -d $dst ]]; then
		/usr/bin/cp -p $src $dst || fatal "$e_badfile" "$src"
	fi
}

# Move a file
safe_move()
{
	typeset src="$1"
	typeset dst="$2"

	if [[ ! -h $src && ! -h $dst && ! -d $dst ]]; then
		/usr/bin/mv $src $dst || fatal "$e_badfile" "$src"
	fi
}

safe_rm()
{
	if [[ ! -h $ZONEROOT/$1 && -f $ZONEROOT/$1 ]]; then
		rm -f "$ZONEROOT/$1"
	fi
}

#
# Replace the file with a wrapper pointing to the native brand code.
# However, we only do the replacement if the file hasn't already been
# replaced with our wrapper.  This function expects the cwd to be the
# location of the file we're replacing.
#
# Some of the files we're replacing are hardlinks to isaexec so we need to 'rm'
# the file before we setup the wrapper while others are hardlinks to rc scripts
# that we need to maintain.
#
safe_replace()
{
	typeset filename="$1"
	typeset runname="$2"
	typeset mode="$3"
	typeset own="$4"
	typeset rem="$5"

	if [ -h $filename -o ! -f $filename ]; then
		return
	fi

	egrep -s "Solaris Brand Replacement" $filename
	if [ $? -eq 0 ]; then
		return
	fi

	safe_backup $filename $filename.pre_p2v
	if [ $rem = "remove" ]; then
		rm -f $filename
	fi

	cat <<-END >$filename || exit 1
	#!/bin/sh
	#
	# Solaris Brand Replacement
	#
	# Attention.  This file has been replaced with a new version for
	# use in a virtualized environment.  Modification of this script is not
	# supported and all changes will be lost upon reboot.  The
	# {name}.pre_p2v version of this file is a backup copy of the
	# original and should not be deleted.
	#
	END

	echo ". $runname \"\$@\"" >>$filename || exit 1

	chmod $mode $filename
	chown $own $filename
}

safe_wrap()
{
	typeset filename="$1"
	typeset runname="$2"
	typeset mode="$3"
	typeset own="$4"

	if [ -f $filename ]; then
		log "$e_cannot_wrap" "$filename"
		exit 1
	fi

	cat <<-END >$filename || exit 1
	#!/bin/sh
	#
	# Solaris Brand Wrapper
	#
	# Attention.  This file has been created for use in a
	# virtualized environment.  Modification of this script
	# is not supported and all changes will be lost upon reboot.
	#
	END

	echo ". $runname \"\$@\"" >>$filename || exit 1

	chmod $mode $filename
	chown $own $filename
}

#
# Read zonecfg fs entries and save the relevant data, one entry per
# line.
# This assumes the properties from the zonecfg output, e.g.:
#	fs:
#		dir: /opt
#		special: /opt
#		raw not specified
#		type: lofs
#		options: [noexec,ro,noatime]
#
# and it assumes the order of the fs properties as above.
#
get_fs_info()
{
	zonecfg -z $zonename info fs | nawk '{
		if ($1 == "options:") {
			# Remove brackets.
			options=substr($2, 2, length($2) - 2);
			printf("%s %s %s %s\n", dir, type, special, options);
		} else if ($1 == "dir:") {
			dir=$2;
		} else if ($1 == "special:") {
			special=$2;
		} else if ($1 == "type:") {
			type=$2
		}
	}' >> $fstmpfile
}

#
# Mount zonecfg fs entries into the zonepath.
#
mnt_fs()
{
	if [ ! -s $fstmpfile ]; then
		return;
	fi

	# Sort the fs entries so we can handle nested mounts.
	sort $fstmpfile | nawk -v zonepath=$zonepath '{
		if (NF == 4)
			options="-o " $4;
		else
			options=""

		# Create the mount point.  Ignore errors since we might have
		# a nested mount with a pre-existing mount point.
		cmd="/usr/bin/mkdir -p " zonepath "/root" $1 " >/dev/null 2>&1"
		system(cmd);

		cmd="/usr/sbin/mount -F " $2 " " options " " $3 " " \
		    zonepath "/root" $1;
		if (system(cmd) != 0) {
			printf("command failed: %s\n", cmd);
			exit 1;
		}
	}' >>$LOGFILE
}

#
# Unmount zonecfg fs entries from the zonepath.
#
umnt_fs()
{
	if [ ! -s $fstmpfile ]; then
		return;
	fi

	# Reverse sort the fs entries so we can handle nested unmounts.
	sort -r $fstmpfile | nawk -v zonepath=$zonepath '{
		cmd="/usr/sbin/umount " zonepath "/root" $1
		if (system(cmd) != 0) {
			printf("command failed: %s\n", cmd);
		}
	}' >>$LOGFILE
}

# Find the dataset mounted on the zonepath.
get_zonepath_ds() {
	ZONEPATH_DS=`/usr/sbin/zfs list -H -t filesystem -o name,mountpoint | \
	    /usr/bin/nawk -v zonepath=$1 '{
		if ($2 == zonepath)
			print $1
	}'`

	if [ -z "$ZONEPATH_DS" ]; then
		fail_fatal "$f_no_ds"
	fi
}

#
# Perform validation and cleanup in the zoneroot after unpacking the archive.
#
post_unpack()
{
	#
	# Check if the image was created with a valid libc.so.1.
	#
	if [[ -f $ZONEROOT/lib/libc.so.1 ]]; then
		hwcap=`moe -v -32 $ZONEROOT/lib/libc.so.1 2>&1`
		if (( $? != 0 )); then
			vlog "$f_hwcap_info" "$hwcap"
			fail_fatal "$f_sanity_hwcap"
		fi
	fi

	( cd "$ZONEROOT" && \
	    find . \( -type b -o -type c \) -exec rm -f "{}" \; )
}

#
# Determine flar compression style from identification file.
#
get_compression()
{
	typeset ident=$1
	typeset line=$(grep "^files_compressed_method=" $ident)

	print ${line##*=}
}

#
# Determine flar archive style from identification file.
#
get_archiver()
{
        typeset ident=$1
        typeset line=$(grep "^files_archived_method=" $ident)

        print ${line##*=}
}

#
# Unpack flar into current directory (which should be zoneroot).  The flash
# archive is standard input.  See flash_archive(4) man page.
# 
# We can't use "flar split" since it will only unpack into a directory called
# "archive".  We need to unpack in place in order to properly handle nested
# fs mounts within the zone root.  This function does the unpacking into the
# current directory.
#
# This code is derived from the gen_split() function in /usr/sbin/flar so
# we keep the same style as the original.
#
install_flar()
{
	typeset result
        typeset archiver_command
        typeset archiver_arguments

	vlog "cd $ZONEROOT && $stage1 "$insrc" | install_flar"

	# Read cookie
	read -r input_line
	if (( $? != 0 )); then
		log "$not_readable" "$install_media"
		return 1
	fi
	# The cookie has format FlAsH-aRcHiVe-m.n where m and n are integers.
	if [[ ${input_line%%-[0-9]*.[0-9]*} != "FlAsH-aRcHiVe" ]]; then
		log "$not_flar"
		return 1
	fi

	while [ true ]
	do
		# We should always be at the start of a section here
		read -r input_line
		if [[ ${input_line%%=*} != "section_begin" ]]; then
			log "$bad_flar"
			return 1
		fi
		section_name=${input_line##*=}

		# If we're at the archive, we're done skipping sections.
		if [[ "$section_name" == "archive" ]]; then
			break
		fi
		
		#
		# Save identification section to a file so we can determine
		# how to unpack the archive.
		#
		if [[ "$section_name" == "identification" ]]; then
			/usr/bin/rm -f identification
			while read -r input_line
			do
				if [[ ${input_line%%=*} == \
				    "section_begin" ]]; then
					/usr/bin/rm -f identification
					log "$bad_flar"
					return 1
				fi

				if [[ $input_line == \
				    "section_end=$section_name" ]]; then
					break;
				fi
				echo $input_line >> identification
			done

			continue
		fi

		#
		# Otherwise skip past this section; read lines until detecting
		# section_end.  According to flash_archive(4) we can have
		# an arbitrary number of sections but the archive section
		# must be last.
		#
		success=0
		while read -r input_line
		do
			if [[ $input_line == "section_end=$section_name" ]];
			then
				success=1
				break
			fi
			# Fail if we miss the end of the section
			if [[ ${input_line%%=*} == "section_begin" ]]; then
				/usr/bin/rm -f identification
				log "$bad_flar"
				return 1
			fi
		done
		if (( $success == 0 )); then
			#
			# If we get here we read to the end of the file before
			# seeing the end of the section we were reading.
			#
			/usr/bin/rm -f identification
			log "$bad_flar"
			return 1
		fi
	done

	# Check for an archive made from a ZFS root pool.
	egrep -s "^rootpool=" identification
        if (( $? == 0 )); then
		/usr/bin/rm -f identification
                log "$bad_zfs_flar"
                return 1
        fi

	# Get the information needed to unpack the archive.
	archiver=$(get_archiver identification)
	if [[ $archiver == "pax" ]]; then
		# pax archiver specified
		archiver_command="/usr/bin/pax"
		if [[ -s $fspaxfile ]]; then
			archiver_arguments="-r -p e -c \
			    $(/usr/bin/cat $fspaxfile)"
		else
			archiver_arguments="-r -p e"
		fi
	elif [[ $archiver == "cpio" || -z $archiver ]]; then
		# cpio archived specified OR no archiver specified - use default
		archiver_command="/usr/bin/cpio"
		archiver_arguments="-icdumfE $fscpiofile"
	else
		# unknown archiver specified
		log "$unknown_archiver" $archiver
		return 1
	fi

	if [[ ! -x $archiver_command ]]; then
		/usr/bin/rm -f identification
		log "$cmd_not_exec" $archiver_command
		return 1
	fi 

	compression=$(get_compression identification)

	# We're done with the identification file
	/usr/bin/rm -f identification

	# Extract archive
	if [[ $compression == "compress" ]]; then
		/usr/bin/zcat | \
		    $archiver_command $archiver_arguments 2>/dev/null
	else
		$archiver_command $archiver_arguments 2>/dev/null
	fi
	result=$?

	post_unpack

	(( $result != 0 )) && return 1

	return 0 
}

#
# Get the archive base.
#
# We must unpack the archive in the right place within the zonepath so
# that files are installed into the various mounted filesystems that are set
# up in the zone's configuration.  These are already mounted for us by the
# mntfs function.
#
# Archives can be made of either a physical host's root file system or a
# zone's zonepath.  For a physical system, if the archive is made using an
# absolute path (/...) we can't use it.  For a zone the admin can make the
# archive from a variety of locations;
#
#   a) zonepath itself: This will be a single dir, probably named with the
#      zone name, it will contain a root dir and under the root we'll see all
#      the top level dirs; etc, var, usr...  We must be above the ZONEPATH
#      when we unpack the archive but this will only work if the the archive's
#      top-level dir name matches the ZONEPATH base-level dir name.  If not,
#      this is an error.
#
#   b) inside the zonepath: We'll see root and it will contain all the top
#      level dirs; etc, var, usr....  We must be in the ZONEPATH when we unpack
#      the archive.
#
#   c) inside the zonepath root: We'll see all the top level dirs, ./etc,
#      ./var, ./usr....  This is also the case we see when we get an archive
#      of a physical sytem.  We must be in ZONEROOT when we unpack the archive.
#
# Note that there can be a directory named "root" under the ZONEPATH/root
# directory.
#
# This function handles the above possibilities so that we reject absolute
# path archives and figure out where in the file system we need to be to
# properly unpack the archive into the zone.  It sets the ARCHIVE_BASE
# variable to the location where the achive should be unpacked.
#
get_archive_base()
{
	stage1=$1
	archive=$2
	stage2=$3

	vlog "$m_analyse_archive"

	base=`$stage1 $archive | $stage2 2>/dev/null | nawk -F/ '{
		# Check for an absolute path archive
		if (substr($0, 1, 1) == "/")
			exit 1

		if ($1 != ".")
			dirs[$1] = 1
		else
			dirs[$2] = 1
	}
	END {
		for (d in dirs) {
			cnt++
			if (d == "bin")  sawbin = 1
			if (d == "etc")  sawetc = 1
			if (d == "root") sawroot = 1
			if (d == "var")  sawvar = 1
                }

		if (cnt == 1) {
			# If only one top-level dir named root, we are in the
			# zonepath, otherwise this must be an archive *of*
			# the zonepath so print the top-level dir name.
			if (sawroot)
				print "*zonepath*"
			else
				for (d in dirs) print d
		} else {
			# We are either in the zonepath or in the zonepath/root
			# (or at the top level of a full system archive which
			# looks like the zonepath/root case).  Figure out which
			# one.
			if (sawroot && !sawbin && !sawetc && !sawvar)
				print "*zonepath*"
			else
				print "*zoneroot*"
		}
	}'`

	if (( $? != 0 )); then
		umnt_fs
		fatal "$e_absolute_archive"
	fi

	if [[ "$base" == "*zoneroot*" ]]; then
		ARCHIVE_BASE=$ZONEROOT
	elif [[ "$base" == "*zonepath*" ]]; then
		ARCHIVE_BASE=$ZONEPATH
	else
		# We need to be in the dir above the ZONEPATH but we need to
		# validate that $base matches the final component of ZONEPATH.
		bname=`basename $ZONEPATH`

		if [[ "$bname" != "$base" ]]; then
			umnt_fs
			fatal "$e_mismatch_archive" "$base" "$bname"
		fi
		ARCHIVE_BASE=`dirname $ZONEPATH`
	fi
}

#
# Unpack cpio archive into zoneroot.
#
install_cpio()
{
	stage1=$1
	archive=$2

	get_archive_base "$stage1" "$archive" "cpio -it"

	cpioopts="-idmfE $fscpiofile"

	vlog "cd \"$ARCHIVE_BASE\" && $stage1 \"$archive\" | cpio $cpioopts"

	# Ignore errors from cpio since we expect some errors depending on
	# how the archive was made.
	( cd "$ARCHIVE_BASE" && $stage1 "$archive" | cpio $cpioopts )

	post_unpack

	return 0
}

#
# Unpack pax archive into zoneroot.
#
install_pax()
{
	archive=$1

	get_archive_base "cat" "$archive" "pax"

	if [[ -s $fspaxfile ]]; then
		filtopt="-c $(/usr/bin/cat $fspaxfile)"
	fi

	vlog "cd \"$ARCHIVE_BASE\" && pax -r -f \"$archive\" $filtopt"

	# Ignore errors from pax since we expect some errors depending on
	# how the archive was made.
	( cd "$ARCHIVE_BASE" && pax -r -f "$archive" $filtopt )

	post_unpack

	return 0
}

#
# Unpack UFS dump into zoneroot.
#
install_ufsdump()
{
	archive=$1

	vlog "cd \"$ZONEROOT\" && ufsrestore rf \"$archive\""

	#
	# ufsrestore goes interactive if you ^C it.  To prevent that,
	# we make sure its stdin is not a terminal.
	#
	( cd "$ZONEROOT" && ufsrestore rf "$archive" < /dev/null )
	result=$?

	post_unpack

	return $result
}

#
# Copy directory hierarchy into zoneroot.
#
install_dir()
{
	source_dir=$1

	cpioopts="-pdm"

	first=1
	filt=$(for i in $(cat $fspaxfile)
		do
			echo $i | egrep -s "/" && continue
			if [[ $first == 1 ]]; then
				printf "^%s" $i
				first=0
			else
				printf "|^%s" $i
			fi
		done)

	list=$(cd "$source_dir" && ls -d * | egrep -v "$filt")
	flist=$(for i in $list
	do
		printf "%s " "$i"
	done)
	findopts="-xdev ( -type d -o -type f -o -type l ) -print"

	vlog "cd \"$source_dir\" && find $flist $findopts | "
	vlog "cpio $cpioopts \"$ZONEROOT\""

	# Ignore errors from cpio since we expect some errors depending on
	# how the archive was made.
	( cd "$source_dir" && find $flist $findopts | \
	    cpio $cpioopts "$ZONEROOT" )

	post_unpack

	return 0
}

#
# This is a common function for laying down a zone image from a variety of
# different sources.  This can be used to either install a fresh zone or as
# part of zone migration during attach.
#
# The first argument specifies the type of image: archive, directory or stdin.
# The second argument specifies the image itself.  In the case of stdin, the
# second argument specifies the format of the stream (cpio, flar, etc.).
# Any validation or post-processing on the image is done elsewhere.
#
# This function calls a 'sanity_check' function which must be provided by
# the script which includes this code.
#
install_image()
{
	intype=$1
	insrc=$2

	if [[ -z "$intype" || -z "$insrc" ]]; then
		return 1
	fi

	filetype="unknown"
	filetypename="unknown"
	stage1="cat"

	if [[ "$intype" == "directory" ]]; then
		if [[ "$insrc" == "-" ]]; then
			# Indicates that the existing zonepath is prepopulated.
			filetype="existing"
			filetypename="existing"
		else
			if [[ "$(echo $insrc | cut -c 1)" != "/" ]]; then
				fatal "$e_path_abs" "$insrc"
			fi

			if [[ ! -e "$insrc" ]]; then
				log "$e_not_found" "$insrc"
				fatal "$e_install_abort"
			fi

			if [[ ! -r "$insrc" ]]; then
				log "$e_not_readable" "$insrc"
				fatal "$e_install_abort"
			fi

			if [[ ! -d "$insrc" ]]; then
				log "$e_not_dir"
				fatal "$e_install_abort"
			fi

			sanity_check $insrc

			filetype="directory"
			filetypename="directory"
		fi

	else
		# Common code for both archive and stdin stream.

		if [[ "$intype" == "archive" ]]; then
			if [[ ! -f "$insrc" ]]; then
				log "$e_unknown_archive"
				fatal "$e_install_abort"
			fi
			ftype="$(LC_ALL=C file $insrc | cut -d: -f 2)"
		else
			# For intype == stdin, the insrc parameter specifies
			# the stream format coming on stdin.
			ftype="$insrc"
			insrc="-"
		fi

		# Setup vars for the archive type we have.
		case "$ftype" in
		*cpio*)		filetype="cpio"
				filetypename="cpio archive"
			;;
		*bzip2*)	filetype="bzip2"
				filetypename="bzipped cpio archive"
			;;
		*gzip*)		filetype="gzip"
				filetypename="gzipped cpio archive"
			;;
		*ufsdump*)	filetype="ufsdump"
				filetypename="ufsdump archive"
			;;
		"flar")
				filetype="flar"
				filetypename="flash archive"
			;;
		"flash")
				filetype="flar"
				filetypename="flash archive"
			;;
		*Flash\ Archive*)
				filetype="flar"
				filetypename="flash archive"
			;;
		"tar")
				filetype="tar"
				filetypename="tar archive"
			;;
		*USTAR\ tar\ archive)
				filetype="tar"
				filetypename="tar archive"
			;;
		"pax")
				filetype="xustar"
				filetypename="pax (xustar) archive"
			;;
		*USTAR\ tar\ archive\ extended\ format*)
				filetype="xustar"
				filetypename="pax (xustar) archive"
			;;
		"zfs")
				filetype="zfs"
				filetypename="ZFS send stream"
			;;
		*ZFS\ snapshot\ stream*)
				filetype="zfs"
				filetypename="ZFS send stream"
			;;
		*)		log "$e_unknown_archive"
				fatal "$e_install_abort"
			;;
		esac
	fi

	vlog "$filetypename"

	# Check for a non-empty root if no '-d -' option. 
	if [[ "$filetype" != "existing" ]]; then
		cnt=$(ls $ZONEROOT | wc -l)
		if (( $cnt != 0 )); then
			fatal "$e_root_full" "$ZONEROOT"
		fi
	fi

	fstmpfile=$(/usr/bin/mktemp -t -p /var/tmp)
	if [[ -z "$fstmpfile" ]]; then
		fatal "$e_tmpfile"
	fi

	# Make sure we always have the files holding the directories to filter
	# out when extracting from a CPIO or PAX archive.  We'll add the fs
	# entries to these files in get_fs_info()
	fscpiofile=$(/usr/bin/mktemp -t -p /var/tmp fs.cpio.XXXXXX)
	if [[ -z "$fscpiofile" ]]; then
		rm -f $fstmpfile
		fatal "$e_tmpfile"
	fi

	# Filter out these directories.
	echo 'dev/*' >>$fscpiofile
	echo 'devices/*' >>$fscpiofile
	echo 'devices' >>$fscpiofile
	echo 'proc/*' >>$fscpiofile
	echo 'tmp/*' >>$fscpiofile
	echo 'var/run/*' >>$fscpiofile
	echo 'system/contract/*' >>$fscpiofile
	echo 'system/object/*' >>$fscpiofile

	fspaxfile=$(/usr/bin/mktemp -t -p /var/tmp fs.pax.XXXXXX)
	if [[ -z "$fspaxfile" ]]; then
		rm -f $fstmpfile $fscpiofile
		fatal "$e_tmpfile"
	fi

	printf "%s " \
	    "dev devices proc tmp var/run system/contract system/object" \
	    >>$fspaxfile

	# Set up any fs mounts so the archive will install into the correct
	# locations.
	get_fs_info
	mnt_fs
	if (( $? != 0 )); then
		umnt_fs >/dev/null 2>&1
		rm -f $fstmpfile $fscpiofile $fspaxfile
		fatal "$mount_failed"
	fi

	if [[ "$filetype" == "existing" ]]; then
		log "$no_installing"
	else
		log "$installing"
	fi

	#
	# Install the image into the zonepath.
	#
	unpack_result=0
	stage1="cat"
	if [[ "$filetype" == "gzip" ]]; then
		stage1="gzcat"
		filetype="cpio"
	elif [[ "$filetype" == "bzip2" ]]; then
		stage1="bzcat"
		filetype="cpio"
	fi

	if [[ "$filetype" == "cpio" ]]; then
		install_cpio "$stage1" "$insrc"
		unpack_result=$?

	elif [[ "$filetype" == "flar" ]]; then
		( cd "$ZONEROOT" && $stage1 $insrc | install_flar )
		unpack_result=$?

	elif [[ "$filetype" == "xustar" ]]; then
		install_pax "$insrc"
		unpack_result=$?

	elif [[ "$filetype" = "tar" ]]; then
		vlog "cd \"$ZONEROOT\" && tar -xf \"$insrc\""
		# Ignore errors from tar since we expect some errors depending
		# on how the archive was made.
		( cd "$ZONEROOT" && tar -xf "$insrc" )
		unpack_result=0
		post_unpack

	elif [[ "$filetype" == "ufsdump" ]]; then
		install_ufsdump "$insrc"
		unpack_result=$?

	elif [[ "$filetype" == "directory" ]]; then
		install_dir "$insrc"
		unpack_result=$?

	elif [[ "$filetype" == "zfs" ]]; then
		#
		# Given a 'zfs send' stream file, receive the snapshot into
		# the zone's dataset.  We're getting the original system's
		# zonepath dataset.  Destroy the existing dataset created
		# above since this recreates it.
		#
		if [[ -z "$DATASET" ]]; then
			fatal "$f_nodataset"
		fi
		/usr/sbin/zfs destroy "$DATASET"
		if (( $? != 0 )); then
			log "$f_zfsdestroy" "$DATASET"
		fi

		vlog "$stage1 $insrc | zfs receive -F $DATASET"
		( $stage1 $insrc | /usr/sbin/zfs receive -F $DATASET )
		unpack_result=$?
	fi

	# Clean up any fs mounts used during unpacking.
	umnt_fs
	rm -f $fstmpfile $fscpiofile $fspaxfile

	chmod 700 $zonepath

	(( $unpack_result != 0 )) && fatal "$f_unpack_failed"

	# Verify this is a valid image.
	sanity_check $ZONEROOT

	return 0
}

e_cannot_wrap="%s: error: wrapper file already exists"
e_baddir="Invalid '%s' directory within the zone"
e_badfile="Invalid '%s' file within the zone"
e_path_abs="Pathname specified to -a '%s' must be absolute."
e_not_found="%s: error: file or directory not found."
e_install_abort="Installation aborted."
e_not_readable="Cannot read directory '%s'"
e_not_dir="Error: must be a directory"
e_unknown_archive="Error: Unknown archive format. Must be a flash archive, a cpio archive (can also be gzipped or bzipped), a pax XUSTAR archive, or a level 0 ufsdump archive."
e_absolute_archive="Error: archive contains absolute paths instead of relative paths."
e_mismatch_archive="Error: the archive top-level directory (%s) does not match the zonepath (%s)."
e_tmpfile="Unable to create temporary file"
e_root_full="Zonepath root %s exists and contains data; remove or move aside prior to install."
f_mkdir="Unable to create directory %s."
f_chmod="Unable to chmod directory %s."
f_chown="Unable to chown directory %s."
f_hwcap_info="HWCAP: %s\n"
f_sanity_hwcap="The image was created with an incompatible libc.so.1 hwcap lofs mount.\n"\
"       The zone will not boot on this platform.  See the zone's\n"\
"       documentation for the recommended way to create the archive."

m_analyse_archive="Analysing the archive"

not_readable="Cannot read file '%s'"
not_flar="Input is not a flash archive"
bad_flar="Flash archive is a corrupt"
bad_zfs_flar="Flash archive contains a ZFS send stream.\n\tRecreate the flar using the -L option with cpio or pax."
f_unpack_failed="Unpacking the archive failed"
unknown_archiver="Archiver %s is not supported"
cmd_not_exec="Required command '%s' not executable!"

#
# Exit values used by the script, as #defined in <sys/zone.h>
#
#	ZONE_SUBPROC_OK
#	===============
#	Installation was successful
#
#	ZONE_SUBPROC_USAGE
#	==================
#	Improper arguments were passed, so print a usage message before exiting
#
#	ZONE_SUBPROC_NOTCOMPLETE
#	========================
#	Installation did not complete, but another installation attempt can be
#	made without an uninstall
#
#	ZONE_SUBPROC_FATAL
#	==================
#	Installation failed and an uninstall will be required before another
#	install can be attempted
#
ZONE_SUBPROC_OK=0
ZONE_SUBPROC_USAGE=253
ZONE_SUBPROC_NOTCOMPLETE=254
ZONE_SUBPROC_FATAL=255

