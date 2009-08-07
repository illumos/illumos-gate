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

# Validate that the directory is safe.
safe_dir()
{
	typeset dir="$1"

	if [[ -h $ZONEROOT/$dir || ! -d $ZONEROOT/$dir ]]; then
		fatal "$e_baddir" "$dir"
	fi
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

#
# Read zonecfg ipd and fs entries and save the relevant data, one entry per
# line.
# This assumes the properties from the zonecfg output, e.g.:
#	inherit-pkg-dir:
#		dir: /usr
#	fs:
#		dir: /opt
#		special: /opt
#		raw not specified
#		type: lofs
#		options: [noexec,ro,noatime]
#
# and it assumes the order of the fs properties as above.  This also saves the
# inherit-pkg-dir patterns into the ipd.{cpio|pax} temporary files for
# filtering while extracting the image into the zonepath.  We have to save the
# IPD patterns in the appropriate format for filtering with the different
# archivers and we don't know what format we'll get until after the flash
# archive is unpacked.
#
get_fs_info()
{
	zonecfg -z $zonename info inherit-pkg-dir | \
	    nawk -v ipdcpiof=$ipdcpiofile -v ipdpaxf=$ipdpaxfile '{
		if ($1 == "dir:") {
			dir=$2;
			printf("%s lofs %s ro\n", dir, dir);

			if (substr(dir, 1, 1) == "/") {
				printf("%s\n", substr(dir, 2)) >> ipdcpiof
				printf("%s/*\n", substr(dir, 2)) >> ipdcpiof
			} else {
				printf("%s\n", dir) >> ipdcpiof
				printf("%s/*\n", dir) >> ipdcpiof
			}

			if (substr(dir, 1, 1) == "/") {
				printf("%s ", substr(dir, 2)) >> ipdpaxf
			} else {
				printf("%s ", dir) >> ipdpaxf
			}
		}
	}' >> $fstmpfile

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

#
# Perform any cleanup in the zoneroot after unpacking the archive.
#
post_unpack()
{
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

	# Get the information needed to unpack the archive.
	archiver=$(get_archiver identification)
	if [[ $archiver == "pax" ]]; then
		# pax archiver specified
		archiver_command="/usr/bin/pax"
		if [[ -s $ipdpaxfile ]]; then
			archiver_arguments="-r -p e -c \
			    $(/usr/bin/cat $ipdpaxfile)"
		else
			archiver_arguments="-r -p e"
		fi
	elif [[ $archiver == "cpio" || -z $archiver ]]; then
		# cpio archived specified OR no archiver specified - use default
		archiver_command="/usr/bin/cpio"
		archiver_arguments="-icdumfE $ipdcpiofile"
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
# Unpack cpio archive into zoneroot.
#
install_cpio()
{
	stage1=$1
	archive=$2

	# Check the first few members of the archive for an absolute path.
	for i in `$stage1 "$archive" | cpio -it | head | cut -b1`
	do
		if [[ "$i" == "/" ]]; then
			umnt_fs
			fatal "$e_absolute_archive"
		fi
	done

	cpioopts="-idmfE $ipdcpiofile"

	vlog "cd \"$ZONEROOT\" && $stage1 \"$archive\" | cpio $cpioopts"

	( cd "$ZONEROOT" && $stage1 "$archive" | cpio $cpioopts )
	result=$?

	post_unpack

	return $result
}

#
# Unpack pax archive into zoneroot.
#
install_pax()
{
	archive=$1

	# Check the first few members of the archive for an absolute path.
	for i in `pax -f "$archive" | head | cut -b1`
	do
		if [[ "$i" == "/" ]]; then
			umnt_fs
			fatal "$e_absolute_archive"
		fi
	done

	if [[ -s $ipdpaxfile ]]; then
		filtopt="-c $(/usr/bin/cat $ipdpaxfile)"
	fi

	vlog "cd \"$ZONEROOT\" && pax -r -f \"$archive\" $filtopt"

	( cd "$ZONEROOT" && pax -r -f "$archive" $filtopt )
	result=$?

	post_unpack

	return $result
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
	# Note that there is no way to filter inherit-pkg-dirs for a full
	# restore so there will be warnings in the log file.
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
	filt=$(for i in $(cat $ipdpaxfile)
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

	( cd "$source_dir" && find $flist $findopts | \
	    cpio $cpioopts "$ZONEROOT" )
	result=$?

	post_unpack

	return $result
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
	# entries to these files in get_fs_info() (there may be no IPDs for
	# some brands but thats ok).
	ipdcpiofile=$(/usr/bin/mktemp -t -p /var/tmp ipd.cpio.XXXXXX)
	if [[ -z "$ipdcpiofile" ]]; then
		rm -f $fstmpfile
		fatal "$e_tmpfile"
	fi

	# In addition to the IPDs, also filter out these directories.
	echo 'dev/*' >>$ipdcpiofile
	echo 'devices/*' >>$ipdcpiofile
	echo 'devices' >>$ipdcpiofile
	echo 'proc/*' >>$ipdcpiofile
	echo 'tmp/*' >>$ipdcpiofile
	echo 'var/run/*' >>$ipdcpiofile
	echo 'system/contract/*' >>$ipdcpiofile
	echo 'system/object/*' >>$ipdcpiofile

	ipdpaxfile=$(/usr/bin/mktemp -t -p /var/tmp ipd.pax.XXXXXX)
	if [[ -z "$ipdpaxfile" ]]; then
		rm -f $fstmpfile $ipdcpiofile
		fatal "$e_tmpfile"
	fi

	printf "%s " \
	    "dev devices proc tmp var/run system/contract system/object" \
	    >>$ipdpaxfile

	# Set up any fs mounts so the archive will install into the correct
	# locations.
	get_fs_info
	mnt_fs
	if (( $? != 0 )); then
		umnt_fs >/dev/null 2>&1
		rm -f $fstmpfile $ipdcpiofile $ipdpaxfile
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
		( cd "$ZONEROOT" && tar -xf "$insrc" )
		unpack_result=$?
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

	vlog "$unpack_done" $unpack_result

	# Clean up any fs mounts used during unpacking.
	umnt_fs
	rm -f $fstmpfile $ipdcpiofile $ipdpaxfile

	#
	# If the archive was of a zone then the archive might have been made
	# of the zonepath (single dir), inside the zonepath (dev, root, etc.,
	# or just even just root) or inside the zonepath root (all the top
	# level dirs).  Try to normalize these possibilities.
	#
	dirsize=$(ls $ZONEROOT | wc -l)
	if [[ -d $ZONEROOT/root && -d $ZONEROOT/root/etc && \
	    -d $ZONEROOT/root/var ]]; then
		# The archive was made of the zoneroot.
		mkdir -m 0755 $ZONEPATH/.attach_root
		mv $ZONEROOT/root/* $ZONEPATH/.attach_root
		mv $ZONEROOT/root/.[a-zA-Z]* $ZONEPATH/.attach_root \
		    >/dev/null 2>&1
		rm -rf $ZONEROOT
		mv $ZONEPATH/.attach_root $ZONEROOT

	elif (( $dirsize == 1 )); then
		# The archive was made of the the zonepath.

		dir=$(ls $ZONEROOT)

		if [[ -d $ZONEROOT/$dir/root ]]; then
			mkdir -m 0755 $ZONEPATH/.attach_root
			mv $ZONEROOT/$dir/root/* $ZONEPATH/.attach_root
			mv $ZONEROOT/$dir/root/.[a-zA-Z]* \
			    $ZONEPATH/.attach_root >/dev/null 2>&1
			rm -rf $ZONEROOT
			mv $ZONEPATH/.attach_root $ZONEROOT
		else
			# We don't know where this archive was made.
			fatal "$e_bad_zone_layout"
		fi

	elif [[ ! -d $ZONEROOT/etc ]]; then
		# We were expecting that the archive was made inside the
		# zoneroot but there's no etc dir, so we don't know where
		# this archive was made.
		fatal "$e_bad_zone_layout"
	fi

	chmod 700 $zonepath

	# Verify this is a valid image.
	sanity_check $ZONEROOT

	return 0
}

# Setup i18n output
TEXTDOMAIN="SUNW_OST_OSCMD"
export TEXTDOMAIN

e_baddir=$(gettext "Invalid '%s' directory within the zone")
e_badfile=$(gettext "Invalid '%s' file within the zone")
e_bad_zone_layout=$(gettext "Unexpected zone layout.")
e_path_abs=$(gettext "Pathname specified to -a '%s' must be absolute.")
e_not_found=$(gettext "%s: error: file or directory not found.")
e_install_abort=$(gettext "Installation aborted.")
e_not_readable=$(gettext "Cannot read directory '%s'")
e_not_dir=$(gettext "Error: must be a directory")
e_unknown_archive=$(gettext "Error: Unknown archive format. Must be a flash archive, a cpio archive (can also be gzipped or bzipped), a pax XUSTAR archive, or a level 0 ufsdump archive.")
e_absolute_archive=$(gettext "Error: archive contains absolute paths instead of relative paths.")
e_tmpfile=$(gettext "Unable to create temporary file")
e_root_full=$(gettext "Zonepath root %s exists and contains data; remove or move aside prior to install.")


not_readable=$(gettext "Cannot read file '%s'")
not_flar=$(gettext "Input is not a flash archive")
bad_flar=$(gettext "Flash archive is a corrupt")
unknown_archiver=$(gettext "Archiver %s is not supported")
cmd_not_exec=$(gettext "Required command '%s' not executable!")

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

