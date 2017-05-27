/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018, Joyent, Inc.
 */

#include	<stdio.h>
#include	<demangle-sys.h>
#include	"_conv.h"
#include	"demangle_msg.h"

/*
 * Demangle C++ symbols.
 *
 * This routine acts as a generic routine for use by liblddbg (and hence tools
 * like elfdump(1) and pvs(1)), ld(1) and ld.so.1(1).
 *
 * The C++ ABI-2 places no limits on symbol names, thus when demangling a name
 * it's possible the buffer won't be big enough (DEMANGLE_ESPACE) so here we
 * try to allocate bigger buffers.  However, we place a limit on this buffer
 * size for fear of a C++ error sending us into an infinit loop.
 *
 * NOTE. we create and use a common buffer for use by cplus_demangle(), thus
 * each call to this routine will override the contents of any existing call.
 * Normally this is sufficient for typical error diagnostics referencing one
 * symbol.  For those diagnostics using more than one symbol name, all but the
 * last name must be copied to a temporary buffer (regardless of whether
 * demangling occurred, as the process of attempting to demangle may damage the
 * buffer).  One model is:
 *
 *	if ((_name1 = demangle(name1)) != name1) {
 *		char *	__name1 = strdupa(_name1);
 *		name1 = (const char *)__name1;
 *	}
 *	name2 = demangle(name2);
 *	eprintf(format, name1, name2);
 */
#define	SYM_MAX	1000

const char *
conv_demangle_name(const char *name)
{
	static char	*(*fptr)() = 0;
	static volatile int loading = 0;
	char *d;

	if (loading)
		return (name);

	/*
	 * If we haven't located the demangler yet try now (we do this rather
	 * than maintain a static dependency on libdemangle as it's part of an
	 * optional package).  Null the str element out to reject any other
	 * callers until this operation is complete - under ld.so.1 we can get
	 * into serious recursion without this.
	 */
	if (fptr == 0) {
		void	*hdl;

		loading = 1;
		if (!(hdl = dlopen(MSG_ORIG(MSG_DEM_LIB), RTLD_LAZY)) ||
		    !(fptr = (char *(*)())dlsym(hdl, MSG_ORIG(MSG_DEM_SYM))))
			return (name);
		loading = 0;
	}

	if ((d = fptr(name, SYSDEM_LANG_AUTO, NULL)) == NULL)
		return (name);

	return (d);
}
