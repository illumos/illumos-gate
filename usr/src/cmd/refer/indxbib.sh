#!/usr/bin/sh
#	Copyright 1988 Sun Microsystems, Inc. All rights reserved.
#	Use is subject to license terms.

#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	All Rights Reserved

#	Copyright (c) 1980 Regents of the University of California.
#	All rights reserved. The Berkeley software License Agreement
#	specifies the terms and conditions for redistribution.

#! /usr/bin/sh

#pragma ident	"%Z%%M%	%I%	%E% SMI" 
#
#	indxbib sh script
#
if test $1
	then /usr/lib/refer/mkey $* | /usr/lib/refer/inv _$1
	mv _$1.ia $1.ia
	mv _$1.ib $1.ib
	mv _$1.ic $1.ic
else
	echo 'Usage:  indxbib database [ ... ]
	first argument is the basename for indexes
	indexes will be called database.{ia,ib,ic}'
fi
