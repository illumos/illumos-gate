#! /usr/bin/ksh
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

usage()
{
	echo "usage: bld_vernote -R <revision> -r <release> -o <outfile.s>"
}

pad_notestring()
{
	extra=$1
	len=$(( ${#notestring} + $extra ))
	padlen=$(( $len % 4 ))
	while [[ $(( $len % 4)) != 0 ]]
	do
		notestring="${notestring}\0"
		len=$(( $len + 1 ))
	done
}


build_sparcnote()
{
	notestring="Solaris Link Editors: $release-$revision (illumos)\0"
	#
	# The 'adjustment' is for the '\0'
	#
	pad_notestring -1

cat > $notefile <<EOF
	.section	".note"

#include <sgs.h>

	.align	4
	.word	.endname - .startname	/* note name size */
	.word	0			/* note desc size */
	.word	0			/* note type */
.startname:
	.ascii	"$notestring"
.endname:

	.section	".rodata", #alloc
	.global		link_ver_string
link_ver_string:
	.type		link_ver_string, #object
	.ascii	"${release}-${revision} (illumos)\0"
	.size	link_ver_string, .-link_ver_string
EOF
}

build_i386note()
{
	notestring="Solaris Link Editors: $release-$revision (illumos)"
	#
	# The 'adjustment' is for the the fact that the x86/amd64
	# assembler automatically append a '\0' at the end of a string.
	#
	pad_notestring -1
cat > $notefile <<EOF
	.section	.note

#include <sgs.h>

	.align	4
	.long	.endname - .startname	/* note name size */
	.long	0			/* note desc size */
	.long	0			/* note type */
.startname:
	.string	"$notestring"
.endname:

	.section	.rodata, "a"
	.globl		link_ver_string
link_ver_string:
	.type	link_ver_string,@object
	.string	"${release}-${revision} (illumos)\0"
	.size	link_ver_string, .-link_ver_string
EOF
}


notefile=""
release=""
revision=""

while getopts R:o:r: c
do
	case $c in
	o)
		notefile=$OPTARG
		;;
	r)
		release=$OPTARG
		;;
	R)
		revision=$OPTARG
		;;
	\?)
		usage
		exit 1
		;;
	esac
done

if [[ ( -z $notefile ) || ( -z $release ) || ( -z $revision ) ]]; then
	usage
	exit 1
fi


if [[ $MACH = "sparc" ]]; then
	build_sparcnote
elif [[ $MACH = "i386" ]]; then
	build_i386note
else
	echo "I don't know how to build a vernote.s for ${MACH}, so sorry"
	exit 1
fi
