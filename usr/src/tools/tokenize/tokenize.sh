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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Creates "tokenized" FCode programs from Forth source code.
#
# Usage:  tokenize xxx.fth
#
# xxx.fth is the name of the source file, which must end in ".fth"
# The output file will be named xxx.fcode .  It will have an a.out header
# so that it can be downloaded to a PROM burner with "pburn"

#
# Get tokenizer.exe and forth_preload.so.1
# from same directory that this command is in.
#
mypath=`dirname $0`

infile=/tmp/$$
echo 'fcode-version1' > $infile
cat $1 >> $infile
echo 'end0' >> $infile
outfile=`basename $1 .fth`.fcode
(
	unset LD_PRELOAD_32 LD_PRELOAD_64
	unset LD_BIND_NOW_32 LD_BIND_NOW_64
	set -x
	LD_PRELOAD=${mypath}/forth_preload.so.1 LD_BIND_NOW=1 \
	${mypath}/forth ${mypath}/tokenize.exe \
	-s "aout-header? off silent? on tokenize $infile $outfile" < /dev/null
)
rm $infile
