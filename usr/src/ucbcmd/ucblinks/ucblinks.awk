#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# This awk-script is the rule-base used in previous release for creating
# compatibility-mode names.
#
#	WARNING: these rules are no longer used by default.  ucblinks
#	is now a binary, not a script.  This rule-base can still
#	be used, however, by running ucblinks with the option
#	"-e /usr/ucblib/ucblinks.awk".  See the ucblinks(1B) man
#	page for more information.
#
# The idea is to create the names as symbolic links to their SunOS5
# counterparts by preference.  If no counterpart exists a direct link to the
# devfs "/devices" directory is made.
#
# It does this base on input of the existing devices in the system.
# The format of the input file is:
#
# driver-name \t minor number \t [b|c] \t /devices-name \t first-minor-component
#
# That is,
#
#	$1	driver-name
#	$2	minor number
#	$3	b(lock) or c(haracter) device
#	$4	devices-directory name; relative to /dev (../devices/xxx)
#	$5	first minor component name (string between ':' and nextr ','
#		in last path-component of the /devices-name)
#
# and these are referred to throughout the script.
#
# The output of the script-rules are lines of the form:
#
# devname["device-link-fullname"] = "compatname";
# devdir["device-link-fullname"] = "compatdir";
#
# The device-link-fullname should be relative to the directory in which the
# SunOS5 link is expected to be found.  'compatdir' is that directory name,
# FOLLOWED BY A SLASH.  'compatname' is the compatability name that should be
# generated.
#

#---------------------------------------------------------------------------
# DATABASE:  Only modify below this line!
#
#
#
# The following devices need no changes, since the 4.x and 5.x names
# are the same:
#
# console tty mem kmem null zero drum mouse klog kbd dump tcp udp
# mbmem mbio 
#
# nit vd eeprom openprom des pp* vp* vpc* 

$3 == "b" && $1 == "fd" {
        if ($5 == "c")
            out(sprintf("%s%d%s", $1, $2/8, $5), "./",
        	sprintf("%s%d", $1, $2/8));
	else
            out(sprintf("%s%d%s", $1, $2/8, $5), "./");
        }
$3 == "c" && $1 == "fd" {
        if ($5 == "c")
            out(sprintf("r%s%d%s", $1, $2/8, $5), "./",
        	sprintf("r%s%d", $1, $2/8));
	else
            out(sprintf("r%s%d%s", $1, $2/8, $5), "./");
        }


#
# Standard disks (all bar IPI)
#
# Note special 'cddev' array test to make sure device is not a CD device
# in the case of a SCSI disk
#
$3 == "b" && (($1 == "sd" && !cddev[$4]) || $1 == "xd" || $1 == "xy")	{
	if ($2 < 8)
		out(sprintf("%s%d%s", $1, 3, $5), "dsk/");
	else if ($2 >= 24 && $2 < 32)
		out(sprintf("%s%d%s", $1, 0, $5), "dsk/");
	else
		out(sprintf("%s%d%s", $1, $2/8, $5), "dsk/");
	}
$3 == "c" && (($1 == "sd" && !cddev[$4]) || $1 == "xd" || $1 == "xy")	{
	if ($2 < 8)
		out(sprintf("r%s%d%s", $1, 3, $5), "rdsk/");
	else if ($2 >= 24 && $2 < 32)
		out(sprintf("r%s%d%s", $1, 0, $5), "rdsk/");
	else
		out(sprintf("r%s%d%s", $1, $2/8, $5), "rdsk/");
	}
#
# SCSI CD drive
#
$1 == "sd" && cddev[$4] && $5 == "c"	{
	if (cdnum[$2] "" == "") cdnum[$2] = cdno++;
	if ($3 == "c") pfx = "r"; else pfx = "";
	out(pfx "sr" cdnum[$2], pfx "dsk/");
	}
#
# Next assumes IPI unit number entirely within minor
# (that is, 5.0 numbering rather than 4.1 numbering)
#
$3 == "b" && $1 == "id"	{
	out(sprintf("id%x%s", $2, $5), "dsk/");
	}
$3 == "c" && $1 == "id"	{
	out(sprintf("rid%x%s", $2, $5), "rdsk/");
	}
#
# Tape drives
#
# SCSI and XT Tape Drives
#
($1 == "st" || $1 == "xt") && NF == 5 && $5 !~ /^[bn]/	{
	if (($2 % 128) < 64) break;	# Not BSD-flavour
	drive = ($2%4) + ((int($2/128)%32) * 4);
	den = int($2/8) % 4;
	if ($1 == "xt") $1 == "mt";	# xt drives appear as mt devices
	if ($5 ~ /n$/) pfx = "nr"; else pfx = "r";
	link = pfx $1 ((den * 8) + drive);
	if (tapelink[link] "" == "") {
		out(link, "rmt/");
		tapelink[link] = 1;
		}
	}
#
# Obsolete drive entries
#
$1 == "mt"	{
	if (($2 % 8) >= 4) {
		link = "rmt" $2;
		if (tapelink[link] "" == "") {
			out(link, "rmt/", "nrmt" ($2 - 4));
			tapelink[link] = 1;
			}
		}
	else {
		link = "rmt" $2;
		if (tapelink[link] "" == "") {
			out(link, "rmt/");
			tapelink[link] = 1;
			}
		}
	}

#
# Wierd Archive tape stuff
#
$1 == "ar" && NF == 5 && $5 !~ /n$/	{
	link = "rar" ($2/4);
	if (tapelink[link] "" == "") {
		out(link, "rmt/");
		tapelink[link] = 1;
		}
	}
$1 == "ar" && NF == 5 && $5 ~ /n$/	{
	link = "nrar" (($2-16)/4);
	if (tapelink[link] "" == "") {
		out(link, "rmt/");
		tapelink[link] = 1;
		}
	}
#
# Screen-buffers are easy
#
$1 == "bwtwo" || $1 == "cgthree" || $1 == "cgsix" || $1 == "cgfour" || $1 == "cgfourteen" || $1 == "cgeight" || $1 == "cgnine" || $1 == "cgtwelve"	{
	out("" $5, "fbs/");
	}
#
# This catches the on-board ports, the 1st and second SCSI-board uarts,
# as well as the newer fast-serial "se" ports.
# Depends on the driver creating the right names.
#
($1 == "zs" || $1 == "se" || $1 == "su") && $4 !~ /,cu$/ && ttbeenhere != 1 {
	ttbeenhere = 1;
	system("x=`ls term`; for i in $x ; do rm -f tty$i; ln -s term/$i tty$i ; done");
	}
#
# XXX Bus device support yet to go in, so the following are TBD:
#
# sbus vme16d16 vme24d16 vme32d16 vme32d32
#
#
# XXX Other device support to be added as drivers are added:
#
# mcp oct mti
#
