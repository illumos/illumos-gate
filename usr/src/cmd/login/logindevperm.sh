#! /usr/bin/sh
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
# Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
#
#
# This is the script that generates the logindevperm file. It is
# architecture-aware, and dumps different stuff for x86 and sparc.
# There is a lot of common entries, which are dumped first.
#
# the SID of this script, and the SID of the dumped script are
# always the same.
#

cat <<EOM
#
# Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
#
# /etc/logindevperm - login-based device permissions
#
# If the user is logging in on a device specified in the "console" field
# of any entry in this file, the owner/group of the devices listed in the
# "devices" field will be set to that of the user.  Similarly, the mode
# will be set to the mode specified in the "mode" field.
#
# If the "console" is "/dev/vt/console_user" which is a symlink to the current
# active virtual console (/dev/console, or /dev/vt/#), then the first
# user to log into any virtual console will get ownership of all the
# devices until they log out.
#
# "devices" is a colon-separated list of device names.  A device name
# ending in "/*", such as "/dev/fbs/*", specifies all entries (except "."
# and "..") in a directory.  A '#' begins a comment and may appear
# anywhere in an entry.
# In addition, regular expressions may be used. Refer to logindevperm(4)
# man page.
# Note that any changes in this file should be made when logged in as
# root as devfs provides persistence on minor node attributes.
#
# console	mode	devices
#
/dev/vt/console_user	0600	/dev/mouse:/dev/kbd
/dev/vt/console_user	0600	/dev/sound/*		# audio devices
/dev/vt/console_user	0600	/dev/fbs/*		# frame buffers
/dev/vt/console_user	0600	/dev/dri/*		# dri devices
/dev/vt/console_user	0400	/dev/removable-media/dsk/*	# removable media
/dev/vt/console_user	0400	/dev/removable-media/rdsk/*	# removable media
/dev/vt/console_user	0400	/dev/hotpluggable/dsk/*		# hotpluggable storage
/dev/vt/console_user	0400	/dev/hotpluggable/rdsk/*	# hotpluggable storage
/dev/vt/console_user	0600	/dev/video[0-9]+	# video devices
/dev/vt/console_user	0600	/dev/usb/hid[0-9]+	# hid devices should have the same permission with conskbd and consms
/dev/vt/console_user	0600	/dev/usb/[0-9a-f]+[.][0-9a-f]+/[0-9]+/* driver=scsa2usb,usb_mid,usbprn,ugen	#libusb/ugen devices
EOM

case "$MACH" in
    "i386" )
	# 
	# These are the x86 specific entries
	# It depends on the build machine being an x86
	#
	cat <<-EOM
	EOM
	;;
    "sparc" )
	# 
	# These are the sparc specific entries
	# It depends on the build machine being a sparc
	#
	cat <<-EOM
	EOM
	;;
    "ppc" )
	# 
	# These are the ppc specific entries
	# It depends on the build machine being a ppc
	#
	cat <<-EOM
	EOM
	;;
    * )
	echo "Unknown Architecture"
		exit 1
	;;
esac
