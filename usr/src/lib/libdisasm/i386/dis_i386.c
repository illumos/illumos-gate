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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libdisasm.h>
#include <stdlib.h>
#include <stdio.h>

#include "dis_tables.h"
#include "libdisasm_impl.h"

struct dis_handle {
	void		*dh_data;
	int		dh_flags;
	dis_lookup_f	dh_lookup;
	dis_read_f	dh_read;
	int		dh_mode;
	dis86_t		dh_dis;
	uint64_t	dh_addr;
	uint64_t	dh_end;
};

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

dis_handle_t *
dis_handle_create(int flags, void *data, dis_lookup_f lookup_func,
    dis_read_f read_func)
{
	dis_handle_t *dhp;

	/*
	 * Validate architecture flags
	 */
	if (flags & ~(DIS_X86_SIZE16 | DIS_X86_SIZE32 | DIS_X86_SIZE64 |
	    DIS_OCTAL | DIS_NOIMMSYM)) {
		(void) dis_seterrno(E_DIS_INVALFLAG);
		return (NULL);
	}

	/*
	 * Create and initialize the internal structure
	 */
	if ((dhp = dis_zalloc(sizeof (struct dis_handle))) == NULL) {
		(void) dis_seterrno(E_DIS_NOMEM);
		return (NULL);
	}

	dhp->dh_lookup = lookup_func;
	dhp->dh_read = read_func;
	dhp->dh_flags = flags;
	dhp->dh_data = data;

	/*
	 * Initialize x86-specific architecture structure
	 */
	if (flags & DIS_X86_SIZE16)
		dhp->dh_mode = SIZE16;
	else if (flags & DIS_X86_SIZE64)
		dhp->dh_mode = SIZE64;
	else
		dhp->dh_mode = SIZE32;

	if (flags & DIS_OCTAL)
		dhp->dh_dis.d86_flags = DIS_F_OCTAL;

	dhp->dh_dis.d86_sprintf_func = snprintf;
	dhp->dh_dis.d86_get_byte = get_byte;
	dhp->dh_dis.d86_sym_lookup = do_lookup;
	dhp->dh_dis.d86_check_func = check_func;

	dhp->dh_dis.d86_data = dhp;

	return (dhp);
}

int
dis_disassemble(dis_handle_t *dhp, uint64_t addr, char *buf, size_t buflen)
{
	dhp->dh_addr = addr;

	/* DIS_NOIMMSYM might not be set until now, so update */
	if (dhp->dh_flags & DIS_NOIMMSYM)
		dhp->dh_dis.d86_flags |= DIS_F_NOIMMSYM;
	else
		dhp->dh_dis.d86_flags &= ~DIS_F_NOIMMSYM;

	if (dtrace_disx86(&dhp->dh_dis, dhp->dh_mode) != 0)
		return (-1);

	if (buf != NULL)
		dtrace_disx86_str(&dhp->dh_dis, dhp->dh_mode, addr, buf,
		    buflen);

	return (0);
}

void
dis_handle_destroy(dis_handle_t *dhp)
{
	dis_free(dhp, sizeof (dis_handle_t));
}

void
dis_set_data(dis_handle_t *dhp, void *data)
{
	dhp->dh_data = data;
}

void
dis_flags_set(dis_handle_t *dhp, int f)
{
	dhp->dh_flags |= f;
}

void
dis_flags_clear(dis_handle_t *dhp, int f)
{
	dhp->dh_flags &= ~f;
}


/* ARGSUSED */
int
dis_max_instrlen(dis_handle_t *dhp)
{
	return (15);
}

#define	MIN(a, b)	((a) < (b) ? (a) : (b))

/*
 * Return the previous instruction.  On x86, we have no choice except to
 * disassemble everything from the start of the symbol, and stop when we have
 * reached our instruction address.  If we're not in the middle of a known
 * symbol, then we return the same address to indicate failure.
 */
uint64_t
dis_previnstr(dis_handle_t *dhp, uint64_t pc, int n)
{
	uint64_t *hist, addr, start;
	int cur, nseen;
	uint64_t res = pc;

	if (n <= 0)
		return (pc);

	if (dhp->dh_lookup(dhp->dh_data, pc, NULL, 0, &start, NULL) != 0 ||
	    start == pc)
		return (res);

	hist = dis_zalloc(sizeof (uint64_t) * n);

	for (cur = 0, nseen = 0, addr = start; addr < pc; addr = dhp->dh_addr) {
		hist[cur] = addr;
		cur = (cur + 1) % n;
		nseen++;

		/* if we cannot make forward progress, give up */
		if (dis_disassemble(dhp, addr, NULL, 0) != 0)
			goto done;
	}

	if (addr != pc) {
		/*
		 * We scanned past %pc, but didn't find an instruction that
		 * started at %pc.  This means that either the caller specified
		 * an invalid address, or we ran into something other than code
		 * during our scan.  Virtually any combination of bytes can be
		 * construed as a valid Intel instruction, so any non-code bytes
		 * we encounter will have thrown off the scan.
		 */
		goto done;
	}

	res = hist[(cur + n - MIN(n, nseen)) % n];

done:
	dis_free(hist, sizeof (uint64_t) * n);
	return (res);
}
