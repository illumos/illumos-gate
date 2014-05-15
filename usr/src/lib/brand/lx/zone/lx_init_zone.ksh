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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Copyright 2014 Joyent, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# This script contains various routines used to post-process a zone for use
# with BrandZ after it has been installed from RPM media or a tar image.
#
# Briefly, there are three main jobs we need to do:
#
# 1) Create any needed directories and symlinks BrandZ needs but that the
#    Linux install may not create
#
# 2) Modify rc scripts to shut off services that don't apply to a zone
#    or that wish to access hardware directly
#
# 3) Modify various Linux system files for use within a zone environment
#

#
# Restrict executables to /bin and /usr/bin
#
PATH=/bin:/usr/bin
export PATH

#
# Sends output to a log file via redirection of stderr.
#
# This script assumes its caller has already performed the redirection to the
# logfile.
#
log()
{
        echo "$@" >&2
}

#
# Setup i18n output
#
TEXTDOMAIN="SUNW_OST_OSCMD"
export TEXTDOMAIN

cmd_failed=$(gettext "%s failed!  Aborting installation...")
cmd2_failed=$(gettext "%s of '%s' to '%s' failed!")
create_failed=$(gettext "Could not create new file '%s'!")
disable_failed=$(gettext "Attempt to disable entries in '%s' failed!")
install_aborted=$(gettext "Aborting installation...")
install_noroot=$(gettext "Installation root directory '%s' does not exist.")
ln_fail=$(gettext "Unable to symlink '%s' to '%s'!")
mkdir_fail=$(gettext "Unable to create the directory '%s'")
mod_failed=$(gettext -n "Attempt to modify entries in '%s' failed!")

usage=$(gettext "usage: %s <zonename> <install_root> [mini]")

#
# Output an internationalized string followed by a carriage return
#
i18n_echo()
{
	typeset fmt="$1"
	shift

	printf "$fmt\n" "$@"
}

#
# Routine to make a full path out of a supplied path
#
fullpath()
{
	typeset path="$1"

	echo $path | egrep -s "^/" || path="${PWD:=$(pwd)}/$path"
	echo $path
}

#
# Routine to create directories and handle errors
#
makedir()
{
	typeset dirname=$(fullpath "$1")
	typeset mode=""

	[[ $# -eq 2 ]] && mode="-m $2"

	[[ -d "$dirname" ]] && return

	if ! mkdir $mode -p "$dirname"; then
		log "Unable to create the directory \"$dirname\"!"
		i18n_echo "$mkdir_fail" "$dirname"
		echo $(gettext "Aborting installation...")
		exit 1
	fi
}

#
# Routine to create initial symlinks and handle errors
#
symlink()
{
	typeset src="$1"
	typeset dst=$(fullpath "$2")

	[[ -e "$dst" || -h "$dst" ]] && rm -f "$dst"
	
	if ! ln -s "$src" "$dst"; then
		log "Unable to symlink \"$src\" to \"$dst\"!"
		i18n_echo "$ln_fail" "$src" "$dst"
		echo $(gettext "Aborting installation...")
		exit 1
	fi
}

#
# Install a file using "ln -s"
#
# Returns 0 on success, 1 on failure.
#
install_ln()
{
	typeset source="$1"
	typeset target=$(fullpath "$2")

	log "    Installing \"$target\""

	mv -f "$target" "$target.$tag" 2>/dev/null

	if ! ln -s "$source" "$target"; then
		log ""
		log "Attempt to install $target FAILED."
		return 1
	fi

	return 0
}

#
# The main script starts here.
#
# The syntax is:
#
#     lx_init_zone <zonename> <rootdir> [mini]
#
# Where:
#	<zonename> is the name of the zone to be modified
#	<rootdir> is the root of the zone directory to be modified
#
#	[mini]	is an optional third argument that signifies whether this is
#		to be a miniroot install; if it is, NFS services are not enabled
#		in the processed zone
#
unset is_miniroot
unset install_root

zonename="$1"
install_root="$2"

tag="lxsave_$(date +%m.%d.%Y@%T)"

if (($# < 2 || $# > 3)); then
	i18n_echo "$usage" "$0"
	exit 1
fi

(($# == 3)) && is_miniroot=1

if [[ ! -d "$install_root" ]]; then
	i18n_echo "$install_noroot" "$install_root"
	echo $(gettext "** Installation aborted **")
	exit 1
fi

cd "$install_root"

log ""
log "Initial lx_brand environment modification started `date`"
log "Making needed directories in \"$install_root\"."
echo $(gettext "Setting up the initial lx brand environment.")

#
# Make various directories in /native that are needed to boot an lx branded
# zone.
#
makedir native/dev
makedir native/etc/default
makedir native/etc/svc/volatile
makedir native/lib
makedir native/proc
makedir native/tmp 1777
makedir native/usr
makedir native/var

#
# Make various other directories needed for the lx brand
#
makedir mnt
makedir opt
makedir usr/local/bin
makedir usr/local/include
makedir usr/local/lib
makedir usr/local/sbin
makedir usr/local/share
makedir usr/local/src

makedir dev 0755
makedir tmp 1777
makedir proc 0555
makedir boot 0755

#
# zlogin requires that these utilities live in places other than their
# Linux defaults, so create appropriate links for them here.
#
# XX - The need for these links may go away in the future if zlogin is
#      appropriately modified
#
symlink /bin/sh sbin/sh
symlink /bin/su usr/bin/su
symlink /native/usr/lib/ld.so.1 usr/lib/ld.so.1

libpam_so="$(echo lib/libpam.so.0.*)"
libpam_misc="$(echo lib/libpam_misc.so.0.*)"
libpamc_so="$(echo lib/libpamc.so.0.*)"

symlink "/$libpam_so" lib/libpam.so.0
symlink "/$libpam_misc" lib/libpam_misc.so.0
symlink "/$libpamc_so" lib/libpamc.so.0

log ""
log "Modifying system configuration in \"$install_root\""

#
# Create a /var/ld/ld.config that will point to /native/lib for our Solaris
# libraries.
#
log "Creating \"$install_root/var/ld/ld.config\"..."

makedir var/ld

if ! crle -c var/ld/ld.config -l /native/lib:/native/usr/lib \
     -s /native/lib/secure:/native/usr/lib/secure; then
	log "\tCreation of \"$install_root/var/ld/ld.config\" failed!"
	i18n_echo "$cmd_failed" "crle"
	exit 1
fi

log ""
log "Modifying \"$install_root/etc/fstab\"..."

mv -f etc/fstab etc/fstab.$tag 2>/dev/null

cat > etc/fstab <<- EOF
	none		/			zfs	defaults	1 1
	proc		/proc			proc	defaults	0 0
EOF

if [[ $? -ne 0 ]]; then
	log "Could not create new \"$install_root/etc/fstab\"!"
	i18n_echo "$create_failed" "$install_root/etc/fstab"
	exit 1
fi

if [[ ! -e "$install_root/etc/hosts" ]]; then
	log ""
	log "Creating: \"$install_root/etc/hosts\"..."

	cat > "$install_root/etc/hosts" <<-_EOF_
		127.0.0.1		localhost
	_EOF_
fi

#
# Perform distribution-specific changes.
#
distro=""
if [[ -f etc/redhat-release ]]; then
	distro="redhat"
elif [[ -f etc/lsb-release ]]; then
	if egrep -s Ubuntu etc/lsb-release; then
		distro="ubuntu"
	elif [[ -f etc/debian_version ]]; then
		distro="debian"
	fi
elif [[ -f etc/debian_version ]]; then
	distro="debian"
fi

if [[ -z $distro ]]; then
	log ""
	log "NOTE: Unsupported distribution!"
	i18n_echo "NOTE: Unsupported distribution!"
	exit 1
fi

i18n_echo "Customizing for $distro"
. $(dirname $0)/lx_init_zone_${distro}

log ""
log "System configuration modifications complete `date`"
log ""
i18n_echo "System configuration modifications complete."
exit 0
