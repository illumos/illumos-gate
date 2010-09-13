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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ar.h>
#include "libelf.h"
#include "decl.h"
#include "member.h"
#include "msg.h"


Elf_Arhdr *
elf_getarhdr(Elf * elf)
{
	Member *	mh;
	Elf_Arhdr *	rc;

	if (elf == 0)
		return (0);
	ELFRLOCK(elf)
	if ((mh = elf->ed_armem) == 0) {
		ELFUNLOCK(elf)
		_elf_seterr(EREQ_AR, 0);
		return (0);
	}
	if (mh->m_err != 0) {
		ELFUNLOCK(elf);
		/*LINTED*/
		_elf_seterr((Msg)mh->m_err, 0);
		return (0);
	}
	rc = &elf->ed_armem->m_hdr;
	ELFUNLOCK(elf)
	return (rc);
}
