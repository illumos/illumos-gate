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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#include <ar.h>
#include "libelf.h"
#include "decl.h"


off_t
elf_getbase(Elf *elf)
{
	off_t	rc;
	if (elf == NULL)
		return (-1);
	ELFRLOCK(elf)
	rc = elf->ed_baseoff;
	ELFUNLOCK(elf)
	return (rc);
}

/*
 * Private function to obtain the offset of the archive header for
 * this archive member. The header directly precedes the base offset,
 * which is available via elf_getbase(), but we wish to isolate the
 * caller from implementation details that might change.
 *
 * Returns the offset on success, and -1 on failure.
 */
off_t
_elf_getarhdrbase(Elf *elf)
{
	off_t	rc;
	if (elf == NULL)
		return (-1);
	ELFRLOCK(elf)
	if (elf->ed_parent == NULL) {
		_elf_seterr(EREQ_AR, 0);
		ELFUNLOCK(elf);
		return (-1);
	}
	rc = elf->ed_baseoff - sizeof (struct ar_hdr);
	ELFUNLOCK(elf)
	return (rc);
}
