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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Joshua M. Clulow <josh@sysmgr.org>
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#include <libdisasm.h>

#include "dis_tables.h"
#include "libdisasm_impl.h"

typedef struct dis_handle_i386 {
	int		dhx_mode;
	dis86_t		dhx_dis;
	uint64_t	dhx_end;
} dis_handle_i386_t;

/*
 * Returns true if we are near the end of a function.  This is a cheap hack at
 * detecting NULL padding between functions.  If we're within a few bytes of the
 * next function, or past the start, then return true.
 */
static int
check_func(void *data)
{
	dis_handle_t *dhp = data;
	uint64_t start;
	size_t len;

	if (dhp->dh_lookup(dhp->dh_data, dhp->dh_addr, NULL, 0, &start, &len)
	    != 0)
		return (0);

	if (start < dhp->dh_addr)
		return (dhp->dh_addr > start + len - 0x10);

	return (1);
}

static int
get_byte(void *data)
{
	uchar_t byte;
	dis_handle_t *dhp = data;

	if (dhp->dh_read(dhp->dh_data, dhp->dh_addr, &byte, sizeof (byte)) !=
	    sizeof (byte))
		return (-1);

	dhp->dh_addr++;

	return ((int)byte);
}

static int
do_lookup(void *data, uint64_t addr, char *buf, size_t buflen)
{
	dis_handle_t *dhp = data;

	return (dhp->dh_lookup(dhp->dh_data, addr, buf, buflen, NULL, NULL));
}

static void
dis_i386_handle_detach(dis_handle_t *dhp)
{
	dis_free(dhp->dh_arch_private, sizeof (dis_handle_i386_t));
	dhp->dh_arch_private = NULL;
}

static int
dis_i386_handle_attach(dis_handle_t *dhp)
{
	dis_handle_i386_t *dhx;

	/*
	 * Validate architecture flags
	 */
	if (dhp->dh_flags & ~(DIS_X86_SIZE16 | DIS_X86_SIZE32 | DIS_X86_SIZE64 |
	    DIS_OCTAL | DIS_NOIMMSYM)) {
		(void) dis_seterrno(E_DIS_INVALFLAG);
		return (-1);
	}

	/*
	 * Create and initialize the internal structure
	 */
	if ((dhx = dis_zalloc(sizeof (dis_handle_i386_t))) == NULL) {
		(void) dis_seterrno(E_DIS_NOMEM);
		return (-1);
	}
	dhp->dh_arch_private = dhx;

	/*
	 * Initialize x86-specific architecture structure
	 */
	if (dhp->dh_flags & DIS_X86_SIZE16)
		dhx->dhx_mode = SIZE16;
	else if (dhp->dh_flags & DIS_X86_SIZE64)
		dhx->dhx_mode = SIZE64;
	else
		dhx->dhx_mode = SIZE32;

	if (dhp->dh_flags & DIS_OCTAL)
		dhx->dhx_dis.d86_flags = DIS_F_OCTAL;

	dhx->dhx_dis.d86_sprintf_func = dis_snprintf;
	dhx->dhx_dis.d86_get_byte = get_byte;
	dhx->dhx_dis.d86_sym_lookup = do_lookup;
	dhx->dhx_dis.d86_check_func = check_func;

	dhx->dhx_dis.d86_data = dhp;

	return (0);
}

static int
dis_i386_disassemble(dis_handle_t *dhp, uint64_t addr, char *buf,
    size_t buflen)
{
	dis_handle_i386_t *dhx = dhp->dh_arch_private;
	dhp->dh_addr = addr;

	/* DIS_NOIMMSYM might not be set until now, so update */
	if (dhp->dh_flags & DIS_NOIMMSYM)
		dhx->dhx_dis.d86_flags |= DIS_F_NOIMMSYM;
	else
		dhx->dhx_dis.d86_flags &= ~DIS_F_NOIMMSYM;

	if (dtrace_disx86(&dhx->dhx_dis, dhx->dhx_mode) != 0)
		return (-1);

	if (buf != NULL)
		dtrace_disx86_str(&dhx->dhx_dis, dhx->dhx_mode, addr, buf,
		    buflen);

	return (0);
}

/* ARGSUSED */
static int
dis_i386_max_instrlen(dis_handle_t *dhp)
{
	return (15);
}

/* ARGSUSED */
static int
dis_i386_min_instrlen(dis_handle_t *dhp)
{
	return (1);
}

static int
dis_i386_supports_flags(int flags)
{
	int archflags = flags & DIS_ARCH_MASK;

	if (archflags == DIS_X86_SIZE16 || archflags == DIS_X86_SIZE32 ||
	    archflags == DIS_X86_SIZE64)
		return (1);

	return (0);
}

static int
dis_i386_instrlen(dis_handle_t *dhp, uint64_t pc)
{
	if (dis_disassemble(dhp, pc, NULL, 0) != 0)
		return (-1);

	return (dhp->dh_addr - pc);
}

dis_arch_t dis_arch_i386 = {
	.da_supports_flags	= dis_i386_supports_flags,
	.da_handle_attach	= dis_i386_handle_attach,
	.da_handle_detach	= dis_i386_handle_detach,
	.da_disassemble		= dis_i386_disassemble,
	.da_min_instrlen	= dis_i386_min_instrlen,
	.da_max_instrlen	= dis_i386_max_instrlen,
	.da_instrlen		= dis_i386_instrlen,
};
