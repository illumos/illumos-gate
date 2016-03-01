#!/bin/ksh -p
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# Copyright 2016 Joyent, Inc.  All rights reserved.
#

#
# This is only an example install script. It is not currently used for anything.
#

PATH=/bin:/usr/bin:/usr/sbin
export PATH

fullpath()
{
	typeset path="$1"

	echo $path | egrep -s "^/" || path="${PWD:=$(pwd)}/$path"
	echo $path
}

makedir()
{
	typeset dirname=$(fullpath "$1")
	typeset mode=""

	[[ $# -eq 2 ]] && mode="-m $2"

	[[ -d "$dirname" ]] && return

	if ! mkdir $mode -p "$dirname"; then
		echo $(gettext "Aborting installation...")
		exit 255
	fi
}

symlink()
{
	typeset src="$1"
	typeset dst=$(fullpath "$2")

	[[ -e "$dst" || -h "$dst" ]] && rm -f "$dst"
	
	if ! ln -s "$src" "$dst"; then
		echo $(gettext "Aborting installation...")
		exit 255
	fi
}

install_ln()
{
	typeset source="$1"
	typeset target=$(fullpath "$2")

	log "    Installing \"$target\""

	mv -f "$target" "$target.$tag" 2>/dev/null

	if ! ln -s "$source" "$target"; then
		return 1
	fi

	return 0
}

# If we weren't passed 3 arguments, exit now.
[[ $# -lt 3 ]] && exit 254

# Extract the brand directory name from the path.
branddir=$(dirname "$0")
zonename="$1"
zoneroot="$2"
install_src="3"
install_root="$zoneroot/root"
ZPOOL=`df $ZONEROOT | awk -F '[()]' '{split($2, field, "/"); print field[1]; }'`
if [ -z "$ZPOOL" ]; then
	ROOTDEV="none"
else
	ROOTDEV="/dev/$ZPOOL"
fi

if [[ ! -f "$install_src" ]]; then
	echo "$install_src: file not found\n"
	exit 254
fi

if [[ ! -d "$install_root" ]]; then
	if ! mkdir -p "$install_root" 2>/dev/null; then
		echo "Could not create install directory $install_root"
		exit 254
	fi
fi

if ! ( cd "$install_root" && gtar -xzf "$install_src" ) ; then
	echo "Error: extraction from tar archive failed"
	exit 255
fi

tag="lxsave_$(date +%m.%d.%Y@%T)"

if [[ ! -d "$install_root" ]]; then
	exit 255
fi

cd "$install_root"

makedir native/dev
makedir native/etc/default
makedir native/etc/svc/volatile
makedir native/lib
makedir native/proc
makedir native/tmp 1777
makedir native/usr
makedir native/var

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

symlink /bin/sh sbin/sh
symlink /bin/su usr/bin/su
symlink /native/usr/lib/ld.so.1 usr/lib/ld.so.1

libpam_so="$(echo lib/libpam.so.0.*)"
libpam_misc="$(echo lib/libpam_misc.so.0.*)"
libpamc_so="$(echo lib/libpamc.so.0.*)"

symlink "/$libpam_so" lib/libpam.so.0
symlink "/$libpam_misc" lib/libpam_misc.so.0
symlink "/$libpamc_so" lib/libpamc.so.0

makedir var/ld

if ! crle -c var/ld/ld.config -l /native/lib:/native/usr/lib \
     -s /native/lib/secure:/native/usr/lib/secure; then
	exit 255
fi

mv -f etc/fstab etc/fstab.$tag 2>/dev/null

cat > etc/fstab <<- EOF
	$ROOTDEV	/			zfs	defaults	1 1
	proc		/proc			proc	defaults	0 0
EOF

if [[ $? -ne 0 ]]; then
	exit 255
fi

if [[ ! -e "$install_root/etc/hosts" ]]; then
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
	exit 255
fi

exit 0
