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

#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

TOOLDIR="${SRC}/cmd/sgs/tools/"

#
# remove the temporary files
#
rm -f CATA_MSG_INTL_LIST CATA_MSG_ORIG_LIST
rm -f MSG_INTL_LIST MSG_ORIG_LIST

while getopts "m:" Arg
do
	case $Arg in
	m)	nawk -f ${TOOLDIR}/catalog.awk $OPTARG ;;
	\?)	echo "usage: chkmsg -m msgfile source-files" ; exit 1 ;;
	esac
done
shift `expr $OPTIND - 1`

if [ $# -eq 0 ]; then
	echo "usage: chkmsg -m msgfile source-files"
	exit 1
fi

#
# Sort the MSG_INTL() and MSG_ORIG() entries.  Note, messages can come in _32
# and _64 flavors - if so strip the suffix and uniquify the output.
#
if [ -s CATA_MSG_INTL_LIST ] ; then
	sed -e "s/_32$//" -e "s/_64$//" CATA_MSG_INTL_LIST | sort | uniq > _TMP
	mv _TMP CATA_MSG_INTL_LIST
fi
if [ -s CATA_MSG_ORIG_LIST ] ; then
	sed -e "s/_32$//" -e "s/_64$//" CATA_MSG_ORIG_LIST | sort | uniq > _TMP
	mv _TMP CATA_MSG_ORIG_LIST
fi

#
# Generate the lists for the source files and sort them
#
nawk -f  ${TOOLDIR}/getmessage.awk	$*

if [ -s MSG_INTL_LIST ] ; then
	sed -e "s/_32$//" -e "s/_64$//" MSG_INTL_LIST | sort | uniq > _TMP
	mv _TMP MSG_INTL_LIST
fi
if [ -s MSG_ORIG_LIST ] ; then
	sed -e "s/_32$//" -e "s/_64$//" MSG_ORIG_LIST | sort | uniq > _TMP
	mv _TMP MSG_ORIG_LIST
fi

#
# Start checking
#
Error=0

#
# Check MESG_INTL message
#
comm -23 CATA_MSG_INTL_LIST MSG_INTL_LIST > _TMP 2> /dev/null
if [ -s _TMP ]; then
    echo
    echo "messages exist between _START_ and _END_ but do not use MSG_INTL()"
    cat _TMP | sed "s/^/	/"
    Error=1
fi
rm -f _TMP

comm -13 CATA_MSG_INTL_LIST MSG_INTL_LIST > _TMP 2> /dev/null
if [ -s _TMP ]; then
    echo
    echo "use of MSG_INTL() but messages do not exist between _START_ and _END_"
    cat _TMP | sed "s/^/	/"
    Error=1
fi
rm -f _TMP

#
# Check MESG_ORIG message
#
comm -23 CATA_MSG_ORIG_LIST MSG_ORIG_LIST > _TMP 2> /dev/null
if [ -s _TMP ]; then
    echo
    echo "messages exist after _END_ but do not use MSG_ORIG()"
    cat _TMP | sed "s/^/	/"
    Error=1
fi
rm -f _TMP

comm -13 CATA_MSG_ORIG_LIST MSG_ORIG_LIST > _TMP 2> /dev/null
if [ -s _TMP ]; then
    echo
    echo "use of MSG_ORIG() but messages do not exist after _END_"
    cat _TMP | sed "s/^/	/"
    Error=1
fi
rm -f _TMP

#
# remove the temporary files
#
rm -f CATA_MSG_INTL_LIST CATA_MSG_ORIG_LIST
rm -f MSG_INTL_LIST MSG_ORIG_LIST

exit $Error
