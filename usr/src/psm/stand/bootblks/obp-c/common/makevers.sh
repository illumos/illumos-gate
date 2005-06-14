#!/bin/sh
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
# Copyright 1991-2000, 2003 Sun Microsystems, Inc.
# All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

ECHO=$1
BOOTER=$2
FILENAME=$3

BANNER="${BOOTER} 1.0 #"

test -f ${BOOTER}.version || echo 0 > ${BOOTER}.version
read OLDVERS < ${BOOTER}.version; export OLDVERS
VERS=`expr ${OLDVERS} + 1`
echo $VERS > ${BOOTER}.version

(
	SCCSSTRING="@(#)${FILENAME}\tDERIVED\t%E% SMI"
	${ECHO} "/*" ; \
	${ECHO} " * This file is derived by makevers.sh" ; \
	${ECHO} " */\n" ; \
	${ECHO} "#pragma\tident\t\"${SCCSSTRING}\"\n" ; \
	${ECHO} "char ident[] = \"@(#)${BANNER}${VERS} %G%\\\n\";" 
) > ${FILENAME}
