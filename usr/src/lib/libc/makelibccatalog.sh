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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
#

XGETTEXT=xgettext
MSGDIR=$1

#
# Change Directory
#
	cd ./port/gen
	rm -f *.po

#
#	get list of files
#
FILES=`grep gettext *.c | sed "s/:.*//" | sort | sed "s/\.c//" | uniq`


#
#	Create po files
#		No need for options for xgettext
#
for	i in ${FILES}
do
	cat ${i}.c | sed "s/_libc_gettext/gettext/" > ${i}.i
	${XGETTEXT} ${i}.i
	cat messages.po | sed "/^domain/d" > ${i}.po
	rm -f ${i}.i messages.po
done

#
#	Create po files
#		Use -a
#

# First, create errlst.c, if it doesn't exist.
# new_list.c is created as a side effect
if [ ! -f errlst.c ]; then
	awk -f errlist.awk errlist
	rmerr="errlst.c new_list.c"
else
	rmerr=
fi

for	i in siglist errlst
do
	cat ${i}.c | sed "s/_libc_gettext/gettext/" > ${i}.i
	${XGETTEXT} -a  ${i}.i
	cat messages.po | sed "/^domain/d" > ${i}.po
	rm -f ${i}.i messages.po
done

#
# 	Copy .po files
#
	cp *.po		${MSGDIR}

#
#	And remove them
#
	rm -f *.po ${rmerr}

#
# Change Directory
#
	cd ../regex
	rm -f messages.po regerror.po

	${XGETTEXT} -a regerror.c
	cat messages.po | sed "/^domain/d" > regerror.po
	rm -f regerror.i messages.po
	
#
# Copy .po file
#
	cp regerror.po ${MSGDIR}

# And remove it		

	rm -f regerror.po
