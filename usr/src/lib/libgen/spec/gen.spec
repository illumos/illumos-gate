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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libgen/spec/gen.spec

function	bgets
include		<libgen.h>
declaration	char *bgets(char *buffer, size_t count, FILE  *stream, \
			char *breakstring)
version		SUNW_1.1
exception	$return == NULL
end

function	bufsplit
include		<libgen.h>
declaration	size_t bufsplit(char *buf, size_t n, char **a)
version		SUNW_1.1
exception	$return == 0
end

function	copylist
include		<libgen.h>
declaration	char *copylist(const char *filenm, off_t *szptr)
version		SUNW_1.1
exception	$return == NULL
end

function	copylist64 extends libgen/spec/gen.spec copylist
include		<libgen.h>
declaration	char *copylist64(const char *filenm, off64_t *szptr)
arch		sparc i386
version		sparc=SUNW_1.1 i386=SUNW_1.1
end

function	gmatch
include		<libgen.h>
declaration	int gmatch(const char *str, const char *pattern)
version		SUNW_1.1
exception	$return == 0
end

function	isencrypt
include		<libgen.h>
declaration	int isencrypt(const char *fbuf, size_t ninbuf)
version		SUNW_1.1
end

function	mkdirp
include		<libgen.h>
declaration	int mkdirp(const char *path, mode_t mode)
version		SUNW_1.1
exception	$return == -1
end

function	rmdirp
include		<libgen.h>
declaration	int rmdirp(char *dir, char *dir1)
version		SUNW_1.1
exception	$return == -1
end

function	p2open
include		<libgen.h>
declaration	int p2open(const char *cmd, FILE *fp[2])
version		SUNW_1.1
exception	$return == -1
end

function	p2close
include		<libgen.h>
declaration	int p2close(FILE *fp[2])
version		SUNW_1.1
exception	$return == -1
end

function	pathfind
include		<libgen.h>
declaration	char *pathfind(const char *path, const char *name, \
			const char *mode)
version		SUNW_1.1
exception	$return == NULL
end

function	compile
include		<regexpr.h>
declaration	char *compile(const char *instring, char *expbuf, \
			char *endbuf)
version		SUNW_1.1
end

function	step
include		<regexpr.h>
declaration	int step(const char *string, const char *expbuf)
version		SUNW_1.1
end

function	advance
include		<regexpr.h>
declaration	int advance(const char *string, const char *expbuf)
version		SUNW_1.1
end

data		locs
version		SUNW_1.1
end

data		loc1
version		SUNW_1.1
end

data		loc2
version		SUNW_1.1
end

data		___loc1
version		SUNW_1.1
end

data		___loc2
version		SUNW_1.1
end

data		___locs
version		SUNW_1.1
end

data		reglength
version		SUNW_1.1
end

data		___reglength
version		SUNW_1.1
end

data		regerrno
version		SUNW_1.1
end

data		___regerrno
version		SUNW_1.1
end

data		nbra
version		SUNW_1.1
end

data		___nbra
version		SUNW_1.1
end

data		braelist
version		SUNW_1.1
end

data		braslist
version		SUNW_1.1
end

data		___braelist
version		SUNW_1.1
end

data		___braslist
version		SUNW_1.1
end

function	strccpy
include		<libgen.h>
declaration	char *strccpy(char *output, const char *input)
version		SUNW_1.1
end

function	strcadd
include		<libgen.h>
declaration	char *strcadd(char *output, const char *input)
version		SUNW_1.1
end

function	strecpy
include		<libgen.h>
declaration	char *strecpy(char *output, const char *input, \
			const char *exceptions)
version		SUNW_1.1
end

function	streadd
include		<libgen.h>
declaration	char *streadd(char *output, const char *input, \
			const char *exceptions)
version		SUNW_1.1
end

function	strfind
include		<libgen.h>
declaration	int strfind(const char *as1, const char *as2)
version		SUNW_1.1
end

function	strrspn
include		<libgen.h>
declaration	char *strrspn(const char *string, const char *tc)
version		SUNW_1.1
end

function	strtrns
include		<libgen.h>
declaration	char * strtrns(const char *string, const char *old, \
			const char *new, char *result)
version		SUNW_1.1
end

function	eaccess
version		SUNW_1.1
end
