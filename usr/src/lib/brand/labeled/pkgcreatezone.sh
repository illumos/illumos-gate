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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

ZONE_SUBPROC_OK=0
ZONE_SUBPROC_USAGE=253
ZONE_SUBPROC_NOTCOMPLETE=254
ZONE_SUBPROC_FATAL=255

f_img=$(gettext "failed to create image")
f_pkg=$(gettext "failed to install package")
f_interrupted=$(gettext "Installation cancelled due to interrupt.")

m_image=$(gettext     "      Image: Preparing at %s ...")
m_catalog=$(gettext   "    Catalog: Retrieving from %s ...")
m_core=$(gettext      " Installing: (output follows)\n")
m_smf=$(gettext	      "Postinstall: Copying SMF seed repository ...")
m_brokenness=$(gettext "Postinstall: Working around http://defect.opensolaris.org/bz/show_bug.cgi?id=681")
m_mannote=$(gettext   "       Note: Man pages can be obtained by installing SUNWman")
m_complete=$(gettext  "       Done: Installation completed in %s seconds.")
m_postnote=$(gettext  " Next Steps: Boot the zone, then log into the zone console")

m_done=$(gettext      " done.")


fail_incomplete() {
	print -u2 "$1"
	exit $ZONE_SUBPROC_NOTCOMPLETE
}

fail_fatal() {
	print -u2 "$1"
	exit $ZONE_SUBPROC_FATAL
}


fail_usage() {
	print "Usage: $0 [-h] [-a <authority>]"
	exit $ZONE_SUBPROC_USAGE
}

trap_cleanup() {
	print "$f_interrupted"
	exit $int_code
}

int_code=$ZONE_SUBPROC_NOTCOMPLETE

trap trap_cleanup INT

zonename=""
zonepath=""

#
# If there's a preferred authority set for the system, set that as our
# default.  Otherwise use opensolaris.org.
#
authority="opensolaris.org=http://pkg.opensolaris.org"
if [[ -x /usr/bin/pkg ]]; then
	sysauth=`LC_ALL=C /usr/bin/pkg authority | grep preferred | awk '{printf "%s=%s", $1, $3}'`
	if [[ $? -eq 0 && -n "$sysauth" ]]; then
		authority=$sysauth
	fi
fi

# Setup i18n output
TEXTDOMAIN="SUNW_OST_OSCMD"
export TEXTDOMAIN


while getopts "a:z:R:h" opt; do
	case $opt in
		h)	fail_usage ;;
		R)	zonepath="$OPTARG" ;;
		z)	zonename="$OPTARG" ;;
		a)	authority="$OPTARG" ;;
		*)	fail_usage ;;
	esac
done
shift $((OPTIND-1))

if [[ -z $zonepath || -z $zonename ]]; then
	print -u2 "Brand error: No zone path or name"
	exit $ZONE_SUBPROC_USAGE
fi

#
# Temporary pre-Opensolaris hack:
# If we don't appear to be on Opensolaris, fallback to old way of
# zone install.
#
if [[ ! -x /usr/bin/pkg ]]; then
	/usr/lib/brand/native/sw_support install $zonename $zonepath
	exit $?
fi

zoneroot=$zonepath/root

printf "\n$m_image" $zoneroot
pkg image-create -z -F -a "$authority" $zoneroot || fail_fatal $f_img
printf "$m_done\n"

PKG_IMAGE="$zoneroot"
export PKG_IMAGE

printf "$m_catalog" `echo $authority | cut -d= -f 2`
pkg refresh > /dev/null 2>&1 || fail_fatal "$f_refresh"
if [[ $? -ne 0 ]]; then
	print "Failed to retrieve catalog"
	exit 1
fi
printf "$m_done\n"

printf "$m_core\n"
pkg install -q SUNWcsd || fail_incomplete "$f_pkg"

pkglist=""
pkglist="$pkglist SUNWcnetr SUNWesu SUNWadmr SUNWadmap SUNWbzip SUNWgzip"

#
# Workaround: in our test repo, SUNWipkg has no dependencies
# so we must supply it python.
#
pkglist="$pkglist SUNWPython SUNWipkg"

#
# Get some diagnostic tools, truss, dtrace, etc.
#
pkglist="$pkglist SUNWtoo SUNWdtrc SUNWrcmdc SUNWbip"

#
# Get at least one sensible shell, and vi
#
pkglist="$pkglist SUNWbash SUNWvim"

#
# Get ssh and sshd.
#
pkglist="$pkglist SUNWsshcu SUNWssh SUNWsshd"

#
# Get some name services.
#
pkglist="$pkglist SUNWnis SUNWlldap"

#
# Get nfs client and autofs; it's a pain not to have them.
#
pkglist="$pkglist SUNWnfsc SUNWatfs"

#
# Get opengl initialization
#
pkglist="$pkglist SUNWxwplr"
#
# Get D-Bus
#
pkglist="$pkglist SUNWdbus"


#
# Get man(1) but not the man pages
#
pkglist="$pkglist SUNWdoc"

# Do the install
pkg install $pkglist || fail_incomplete "$f_pkg"


# This was formerly done in SUNWcsr/postinstall
printf "$m_smf"
ln -s ns_files.xml $zoneroot/var/svc/profile/name_service.xml
ln -s generic_limited_net.xml $zoneroot/var/svc/profile/generic.xml
ln -s inetd_generic.xml $zoneroot/var/svc/profile/inetd_services.xml
ln -s platform_none.xml $zoneroot/var/svc/profile/platform.xml

# This was formerly done in i.manifest
cp $zoneroot/lib/svc/seed/nonglobal.db $zoneroot/etc/svc/repository.db
printf "$m_done\n"


printf "$m_brokenness\n"
#
# Remove "jack" user.
#
sed '/^jack:.*Default\ User.*$/D' $zoneroot/etc/passwd \
        > $zoneroot/etc/passwd.new && \
    mv -f $zoneroot/etc/passwd.new $zoneroot/etc/passwd


#
# Set root from a role back to... not a role.  Grr.
#
sed 's/^root::::type=role;/root::::/' $zoneroot/etc/user_attr \
	> $zoneroot/etc/user_attr.new && \
    mv -f $zoneroot/etc/user_attr.new $zoneroot/etc/user_attr

printf "$m_complete\n\n" ${SECONDS}
printf "$m_postnote\n"

exit $ZONE_SUBPROC_OK
