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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/watchmalloc/spec/watchmalloc.spec

function	_cfree
version		SUNW_1.1
binding		nodirect
end		

function	_mallinfo
version		SUNW_1.1
binding		nodirect
end		

function	_mallopt
version		SUNW_1.1
binding		nodirect
end		

function	_memalign
version		SUNW_1.1
binding		nodirect
end		

function	_valloc
version		SUNW_1.1
binding		nodirect
end		

function	calloc
include		<stdlib.h>
declaration	void *calloc(size_t nelem, size_t elsize)
version		SUNW_1.1
binding		nodirect
end		

function	cfree
include		<stdlib.h>
declaration	void cfree(void *ptr, size_t nelem, size_t elsize)
version		SUNW_1.1
binding		nodirect
end		

function	free
include		<stdlib.h>
declaration	void free(void *ptr)
version		SUNW_1.1
binding		nodirect
end		

function	mallinfo
include		<malloc.h>
declaration	struct mallinfo mallinfo(void)
version		SUNW_1.1
binding		nodirect
end		

function	malloc
include		<stdlib.h>
declaration	void *malloc(size_t size)
version		SUNW_1.1
binding		nodirect
end		

function	mallopt
include		<malloc.h>
declaration	int mallopt(int cmd, int value)
version		SUNW_1.1
binding		nodirect
end		

function	memalign
include		<stdlib.h>
declaration	void *memalign(size_t alignment, size_t size)
version		SUNW_1.1
binding		nodirect
end		

function	realloc
include		<stdlib.h>
declaration	void *realloc(void *ptr, size_t size)
version		SUNW_1.1
binding		nodirect
end		

function	valloc
include		<stdlib.h>
declaration	void *valloc(size_t size)
version		SUNW_1.1
binding		nodirect
end		
