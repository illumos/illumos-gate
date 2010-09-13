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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <limits.h>
#include <strings.h>
#include "_conv.h"

/*
 * Isalist(1) expansion.
 *
 * Obtain the native instruction sets executable on this platform and unpack
 * each element into the isalist descriptor.
 */
Isa_desc *
conv_isalist(void)
{
	char		info[SYS_NMLN], * list, * ptr, * optr;
	Isa_desc *	desc;
	Isa_opt *	opt;
	long		size;
	int		no;

	if ((desc = calloc(1, sizeof (Isa_desc))) == 0)
		return (0);

	/*
	 * If we can't get the isalist() perhaps we've gone back to a release
	 * too old to support it - silently ignore.
	 */
	if ((size = sysinfo(SI_ISALIST, info, SYS_NMLN)) == -1)
		return (desc);
	desc->isa_listsz = (size_t)size;

	/*
	 * Duplicate the isalist string in preparation for breaking it up.
	 */
	if ((list = strdup(info)) == 0)
		return (desc);
	desc->isa_list = list;

	/*
	 * Determine the number of instruction sets and use this to size the
	 * isalist option table.
	 */
	for (no = 1, ptr = list; *ptr; ptr++) {
		if (*ptr == ' ')
			no++;
	}
	if ((opt = malloc(no * sizeof (Isa_opt))) == 0)
		return (desc);
	desc->isa_opt = opt;
	desc->isa_optno = no;

	/*
	 * Unpack the instruction set list.
	 */
	for (optr = ptr = list; *ptr; ptr++) {
		if (*ptr != ' ')
			continue;

		opt->isa_name = optr;
		opt->isa_namesz = ptr - optr;
		opt++;

		*ptr = '\0';
		optr = ptr + 1;
	}
	opt->isa_name = optr;
	opt->isa_namesz = ptr - optr;

	return (desc);
}

/*
 * uname(2) expansion.
 *
 * Obtain the information that identifies the current operating system and
 * unpack those elements we're interested in (presently name and release).
 */
Uts_desc *
conv_uts(void)
{
	struct utsname	utsname;
	Uts_desc *	desc;
	size_t		size;

	if ((desc = calloc(1, sizeof (Uts_desc))) == 0)
		return (0);

	/*
	 * If we can't get the uname(2) silently ignore.
	 */
	if (uname(&utsname) == -1)
		return (desc);

	/*
	 * Duplicate the operating system name and release components.
	 */
	size = strlen(utsname.sysname);
	if ((desc->uts_osname = malloc(size + 1)) == 0)
		return (desc);
	desc->uts_osnamesz = size;
	(void) strncpy(desc->uts_osname, utsname.sysname, size);

	size = strlen(utsname.release);
	if ((desc->uts_osrel = malloc(size + 1)) == 0)
		return (0);
	desc->uts_osrelsz = size;
	(void) strncpy(desc->uts_osrel, utsname.release, size);

	return (desc);
}
