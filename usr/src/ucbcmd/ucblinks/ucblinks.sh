#!/bin/sh
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

# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

PATH=/sbin:/usr/sbin:/usr/bin:/etc
export PATH

RULEBASE=/usr/ucblib/ucblinks.awk

# Name of device-type list produced by "devlinks"
DEVTYPES=/etc/.obp_devices

USAGE="Usage: `basename $0` [-r rootdir] [-e rulebase] [-d]"
DOIT_CMD="sh -s"

while getopts 'de:r:' flag
do
	case $flag in
	d)	DOIT_CMD="cat -"
		;;
	e)
		RULEBASE=$OPTARG;
		case "$RULEBASE" in
		/*)	;;
		*)	RULEBASE="`pwd`/$RULEBASE";;
		esac
		;;
	r)	ROOTDIR=$OPTARG;
		;;
	\?)	echo "$USAGE" >&2
		exit 2;
		;;
	esac
done

shift `expr $OPTIND - 1`

#
# The rest of this script looks a mess.  But in fact underneath all the
# 'sed's and 'awk's it is quite simple.
#
# First it creates a list of all the device nodes in the /devices directory
# (by cd'ing to /dev, then doing a 'find' of all special files in ../devices
# doing an 'ls -l' of these files, and sedding the output to produce a list
# of the form 'major minor type name').
#
# As an added wrinkle it changes 'major' from a number to a driver-name using
# sed rules produced from the "/etc/name_to_major file.
#
# Then it runs the awk rules in the rule-base on this list to produce a list
# of compatability-links that must be created.  However, this does not produce
# the links themselves because of the next stage:
#
# Finally this list of compatability-links is inspected and where possible links
# to the SunOS5 names are created instead of links directly to the /devices
# directory
# (by 'find'ing all the symbolic links under /dev, ancomparing the
# subdirectory they occur in, and the file to which they point, to
# the comaptability-link information built above. If a match is found
# a command to make a link to the 5.0 link, rather than to the /devices
# entry, is created.  If not, a direct link is created)
# And then the list of link command is executed by a shell, or printed on stdout
# (in debugging mode)
#
# See -- not so complicated!  However the syntax of all these rules makes
# the code below nearly incomprehensible.  Fear not; the only part you need
# to change for extra devices is located in the 'RULEBASE' file.

cd $ROOTDIR/dev

GENSED=/tmp/mkcompat.sed$$
GENAWK=/tmp/mkcompat.awk$$
GENRULE=/tmp/mkcompat.rule$$

rm -f $GENSED $GENAWK $GENRULE

trap "rm -f $GENSED $GENAWK $GENRULE" 0

#
# First generate full rulebase.  This is done to keep common functions
# out of the rulebase


cat - >$GENRULE <<\!EOD
function out(dev, dir, extraname)	{
	c = split(dir, junk, "/") - 1;

	if (junk[1] == ".")
		c--;

	fulldevfs = "";

	while ( c > 0) {
		fulldevfs = "../" fulldevfs;
		c--;
	}
	fulldevfs = fulldevfs $4;

	printf "devname[\"" fulldevfs "\"] = \"" dev "\";";

	if (length(dir) > 0)
		printf " devdir[\"" fulldevfs "\"] = \"" dir "\";";

	if (length(extraname) > 0)
		printf " devextra[\"" fulldevfs "\"] = \"" extraname "\";";
	printf "\n";
	} 

!EOD

#
# Now see if we need to do CD drive special handling.  The SCSI CD and disk
# drivers have been merged in SunOS5, so we cannot do the normal differentiation
# on major number with these devices.  However the "disks" program does write
# a list of all OBP cd device names in a pecial file; by massaging this file
# we are able to construct rules which correctly differentiate between sd and sr
# devices.

if [ -s $DEVTYPES ]
then
	echo "BEGIN	{" >>$GENRULE
	sed -ne '/^ddi_block:cdrom[:	]/s-^[^	 ]*[ 	]\{1,\}\(.*\)$-	cddev["../devices/\1"] = 1;-p' <$DEVTYPES >>$GENRULE
	echo "	}" >>$GENRULE
fi

cat $RULEBASE >>$GENRULE


#
#----------------------------------------------------------------------
#
# Construct sedscr ... a script to massage the output of an 'ls -l'
# of all the special files in the '../devices' directory.
#
# First 3 lines of scr change line to format "maj	min	[b|c]	name
#
cat <<\!EOD >$GENSED
1,$s/^\(.\).*[ 	]\([0-9][0-9]*\), *\([0-9][0-9]*\)[ 	].*[ 	]\([^ 	][^ 	]*\)$/\2	\3	\1	\4/
/:[^	,][^ 	,]*$/s/^\(.*\):\([^	,]*\)$/\1:\2	\2/
/:[^	,][^	,]*,[^ ]*$/s/^\(.*\):\([^	,]*\),\([^ ]*\)$/\1:\2,\3	\2/
!EOD

# Next lines are generated from the "/etc/name_to_major file; they change the
# "major number" field into its corresponding 'name'.  This is so that
# the difference in major-numbers among different machines can be hidden.
#
nawk -v del='#' '$1 !~ /^#|^$/ { \
    num = split($2, maj, del); \
    if (num > 1) { printf("/^%s\t/ s/^%s\t/%s\t/\n", maj[1], maj[1], $1) } \
    else { printf("/^%s\t/ s/^%s\t/%s\t/\n", $2, $2, $1) } \
} ' /etc/name_to_major >> $GENSED

#
#----------------------------------------------------------------------
#
# Have finished generating sedscr.  Now we generate 'nawkscr'; first we insert
# the header ...

cat >$GENAWK <<\!EOD
BEGIN	{
!EOD

# and then we find all the symbolic-links under /dev, massage the output of
# an 'ls -l' with the sed script we generated above, and then 'nawk' the output
# using the actual link data table script.  This generates the heart of our
# link-creating 'nawk' script.

echo "Scanning /devices/ directory tree..." >&2

ls -l `find ../devices \( -type b -o -type c \) -print` |  sed -f $GENSED |\
sort -b +0 -1 +1n -2 +4 -5 | nawk -f $GENRULE >>$GENAWK

cat >>$GENAWK <<\!EOD
	}
$2 in devname	{
	if (length(devdir[$2]) <= 0)
		next;
	if (devdir[$2] == "./") {
		if ($1 == devname[$2])
			next;
	}
	else if (match($1, "^" devdir[$2] "[^/]*$") == 0)
		next;

	printf "rm -f %s; ln -s %s %s\n", devname[$2], $1, devname[$2];
	if (length(devextra[$2]) > 0) {
		printf "rm -f %s; ln -s %s %s\n", devextra[$2],
			devname[$2], devextra[$2];
		delete devextra[$2];
	}
	delete devname[$2];
	delete devdir[$2];
	}
END	{
	for (dev in devname) {
		printf "rm -f %s; ln -s %s %s\n", devname[dev],
		   substr(dev, match(dev, "\.\./devices/"), 999),
		   devname[dev];
		if (length(devextra[dev]) > 0)
			printf "rm -f %s; ln -s %s %s\n", devextra[dev],
				devname[dev], devextra[dev];
	}
	}
!EOD

#
#----------------------------------------------------------------------
#
echo "Scanning /dev/ directory tree..." >&2

ls -l `find . -type l -print` |\
	sed -e '1,$s/^.* \.\/\([^ ][^ ]*\) -> \([^ ][^ ]*\)$/\1	\2/' |\
	nawk -f $GENAWK |\
	$DOIT_CMD
