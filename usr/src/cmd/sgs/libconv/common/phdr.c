/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * String conversion routines for program header attributes.
 */
#include	<string.h>
#include	<sys/elf_amd64.h>
#include	<_conv.h>
#include	<phdr_msg.h>

static const Msg phdrs[] = {
	MSG_PT_NULL,		MSG_PT_LOAD,		MSG_PT_DYNAMIC,
	MSG_PT_INTERP,		MSG_PT_NOTE,		MSG_PT_SHLIB,
	MSG_PT_PHDR,		MSG_PT_TLS
};

static const Msg uphdrs[] = {
	MSG_PT_SUNWBSS,		MSG_PT_SUNWSTACK,	MSG_PT_SUNWDTRACE,
	MSG_PT_SUNWCAP
};

const char *
/* ARGSUSED 1 */
conv_phdrtyp_str(ushort_t mach, uint_t phdr)
{
	static char	string[STRSIZE] = { '\0' };

	if (phdr < PT_NUM)
		return (MSG_ORIG(phdrs[phdr]));
	else if ((phdr >= PT_SUNWBSS) && (phdr <= PT_HISUNW))
		return (MSG_ORIG(uphdrs[phdr - PT_SUNWBSS]));
	else if ((phdr == PT_SUNW_UNWIND) && (mach == EM_AMD64))
		return (MSG_ORIG(MSG_PT_SUNW_UNWIND));
	else
		return (conv_invalid_str(string, STRSIZE, phdr, 0));
}

#define	PHDRSZ	MSG_GBL_OSQBRKT_SIZE + \
		MSG_PF_X_SIZE + \
		MSG_PF_W_SIZE + \
		MSG_PF_R_SIZE + \
		MSG_GBL_CSQBRKT_SIZE

const char *
conv_phdrflg_str(uint_t flags)
{
	static	char	string[PHDRSZ] = { '\0' };

	if (flags == 0)
		return (MSG_ORIG(MSG_GBL_ZERO));
	else {
		(void) strcpy(string, MSG_ORIG(MSG_GBL_OSQBRKT));
		if (flags & PF_X)
			(void) strcat(string, MSG_ORIG(MSG_PF_X));
		if (flags & PF_W)
			(void) strcat(string, MSG_ORIG(MSG_PF_W));
		if (flags & PF_R)
			(void) strcat(string, MSG_ORIG(MSG_PF_R));
		if (flags & PF_SUNW_FAILURE)
			(void) strcat(string, MSG_ORIG(MSG_PF_SUNW_FAILURE));
		(void) strcat(string, MSG_ORIG(MSG_GBL_CSQBRKT));

		return ((const char *)string);
	}
}
