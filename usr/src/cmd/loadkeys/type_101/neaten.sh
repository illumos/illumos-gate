#! /usr/bin/sh
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
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1999 by Sun Microsystems, Inc.
# All rights reserved.
#

sccsid=`echo '#pragma ident	"@Z@@M@	@I@	@E@ SMI"' | sed 's/@/%/g'`


markrow()
{
	# markrow file begin end label
	file="$1"
	begin="$2"
	end="$3"
	label="$4"

	awk -f - $file <<-EOT > $file.$$
	    \$2 >= $begin && \$2 <= $end && done == 0	{
			print "";
			print "# $label";
			done = 1;
		}
		{
			print \$0;
		}
	EOT
	mv -f $file.$$ $file
}

header=/tmp/header.$$
sorted=/tmp/sorted.$$

for i
do
	echo "#" > $header
	echo "$sccsid" >> $header
	echo "#" >> $header
	echo "# Copyright (c) `date +%Y` by Sun Microsystems, Inc." >> $header
	echo "# All rights reserved." >> $header
	echo "#" >> $header
	sed -n						\
		-e '/^[^#]/q'				\
		-e '/^[ 	]*$/q'			\
		-e '/%\Z%/d'				\
		-e '/@(#)/d'				\
		-e '/Copyright/d'			\
		-e '/[aA]ll [rR]ights [rR]eserved/d'	\
		-e '/^#[ 	]*$/d'			\
		-e p					\
		$i >> $header
	echo '#' >> $header
	grep -v '^#' $i |
	grep -v '^[ 	]*$' |
	sed -e 's/[ 	][ 	]*/ /g' |
	sort -n +1 -o $sorted
	# The following are specific to PC keyboards, but similar
	# schemes should work for many other types.
	markrow $sorted 0 0 "??? Unknown keys ???"
	markrow $sorted 1 15 "Main Pad Row 1:  digits, Backspace"
	markrow $sorted 16 29 "Main Pad Row 2:  Tab, QWERTY..."
	markrow $sorted 30 43 "Main Pad Row 3:  CapsLock, ASDFGH..., Enter"
	markrow $sorted 44 57 "Main Pad Row 4:  Shift, ZXCVBN..., Shift"
	markrow $sorted 58 65 "Main Pad Row 5:  Ctrl, Alt, Space, ..."
	markrow $sorted 66 74 "??? Unknown keys ???"
	markrow $sorted 75 89 "Arrow Pad"
	markrow $sorted 90 108 "Numeric Pad"
	markrow $sorted 109 109 "??? Unknown keys ???"
	markrow $sorted 110 126 "Esc, Function Keys, PrintScreen/ScrollLock/Pause"
	markrow $sorted 127 130 "??? Unknown keys ???"
	markrow $sorted 131 133 "Japanese Keys"
	markrow $sorted 134 149 "??? Unknown keys ???"
	markrow $sorted 150 151 "Korean Keys"
	markrow $sorted 152 99999 "??? Unknown keys ???"
	cat $header $sorted > $i.neat
	rm -f $header $sorted

	echo "Neaten $i -> $i.neat"
done
