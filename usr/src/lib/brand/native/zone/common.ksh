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

	vlog "cd $ZONEROOT && do_flar < \"$install_archive\""

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
		/usr/bin/zcat | ppriv -e -s A=all,-sys_devices \
		    $archiver_command $archiver_arguments 2>/dev/null
	else
		ppriv -e -s A=all,-sys_devices \
		    $archiver_command $archiver_arguments 2>/dev/null
	fi
	result=$?

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

	cpioopts="-idmfE $ipdcpiofile"

	vlog "cd \"$ZONEROOT\" && $stage1 \"$archive\" | "
	vlog "ppriv -e -s A=all,-sys_devices cpio $cpioopts"

	( cd "$ZONEROOT" && $stage1 "$archive" | \
	     ppriv -e -s A=all,-sys_devices cpio $cpioopts )
}

#
# Unpack pax archive into zoneroot.
#
install_pax()
{
	archive=$1

	if [[ -s $ipdpaxfile ]]; then
		filtopt="-c $(/usr/bin/cat $ipdpaxfile)"
	fi

	vlog "cd \"$ZONEROOT\" && "
	vlog "ppriv -e -s A=all,-sys_devices pax -r -f \"$archive\" $filtopt"

	( cd "$ZONEROOT" && ppriv -e -s A=all,-sys_devices \
	    pax -r -f "$archive" $filtopt )
}

#
# Unpack UFS dump into zoneroot.
#
install_ufsdump()
{
	archive=$1

	vlog "cd \"$ZONEROOT\" && "
	vlog "ppriv -e -s A=all,-sys_devices ufsrestore rf \"$archive\""

	#
	# ufsrestore goes interactive if you ^C it.  To prevent that,
	# we make sure its stdin is not a terminal.
	# Note that there is no way to filter inherit-pkg-dirs for a full
	# restore so there will be warnings in the log file.
	#
	( cd "$ZONEROOT" && ppriv -e -s A=all,-sys_devices \
	    ufsrestore rf "$archive" < /dev/null )
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
	vlog "ppriv -e -s A=all,-sys_devices cpio $cpioopts \"$ZONEROOT\""

	( cd "$source_dir" && find $flist $findopts | \
	    ppriv -e -s A=all,-sys_devices cpio $cpioopts "$ZONEROOT" )
}

# Setup i18n output
TEXTDOMAIN="SUNW_OST_OSCMD"
export TEXTDOMAIN

e_baddir=$(gettext "Invalid '%s' directory within the zone")
e_badfile=$(gettext "Invalid '%s' file within the zone")

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

