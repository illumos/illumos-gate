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
#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved

#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/

title=HELP on $ARG1
lifetime=shortterm

init="$RETVAL"

framemsg="Press the CANCEL function key to cancel."

`test -r $VMSYS/HELP/$ARG2 && set -l RETVAL=true || set -l RETVAL=false; 
 regex -e -v "$RETVAL" 
	'^false$' '`message "No HELP text is available for this item."`'`

text="`readfile $VMSYS/HELP/$ARG2`"
columns=`longline | set -l LL;
if [ "${LL}" -gt "${DISPLAYW}" ];
then
	echo ${DISPLAYW};
else
	echo ${LL};
fi`

name=""
button=1
action=nop

name="CONTENTS"
button=8
action=OPEN MENU OBJECTS/Menu.h0.toc
