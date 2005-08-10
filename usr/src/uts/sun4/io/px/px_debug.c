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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PCI nexus driver general debug support
 */
#include <sys/async.h>
#include <sys/sunddi.h>		/* dev_info_t */
#include <sys/ddi_impldefs.h>
#include <sys/disp.h>
#include "px_debug.h"

/*LINTLIBRARY*/

#ifdef	DEBUG
uint64_t px_debug_flags = 0;

static char *px_debug_sym [] = {	/* same sequence as px_debug_bit */
	/*  0 */ "attach",
	/*  1 */ "detach",
	/*  2 */ "map",
	/*  3 */ "nex-ctlops",

	/*  4 */ "introps",
	/*  5 */ "intx-add",
	/*  6 */ "intx-rem",
	/*  7 */ "intx-intr",

	/*  8 */ "msiq",
	/*  9 */ "msiq-intr",
	/* 10 */ "msg",
	/* 11 */ "msg-intr",

	/* 12 */ "msix-add",
	/* 13 */ "msix-rem",
	/* 14 */ "msix-intr",
	/* 15 */ "err",

	/* 16 */ "dma-alloc",
	/* 17 */ "dma-free",
	/* 18 */ "dma-bind",
	/* 19 */ "dma-unbind",

	/* 20 */ "chk-dma-mode",
	/* 21 */ "bypass-dma",
	/* 22 */ "fast-dvma",
	/* 23 */ "init_child",

	/* 24 */ "dma-map",
	/* 25 */ "dma-win",
	/* 26 */ "map-win",
	/* 27 */ "unmap-win",

	/* 28 */ "dma-ctl",
	/* 29 */ "dma-sync",
	/* 30 */ NULL,
	/* 31 */ NULL,

	/* 32 */ "ib",
	/* 33 */ "cb",
	/* 34 */ "dmc",
	/* 35 */ "pec",

	/* 36 */ "ilu",
	/* 37 */ "tlu",
	/* 38 */ "lpu",
	/* 39 */ NULL,

	/* 40 */ "open",
	/* 41 */ "close",
	/* 42 */ "ioctl",
	/* 43 */ "pwr",

	/* 44 */ "lib-cfg",
	/* 45 */ "lib-intr",
	/* 46 */ "lib-dma",
	/* 47 */ "lib-msiq",

	/* 48 */ "lib-msi",
	/* 49 */ "lib-msg",
	/* 50 */ "NULL",
	/* 51 */ "NULL",

	/* 52 */ "tools",
	/* 53 */ "phys_acc",
	/* LAST */ "unknown"
};

void
px_dbg(px_debug_bit_t bit, dev_info_t *dip, char *fmt, ...)
{
	int cont = bit >> DBG_BITS;
	va_list ap;

	bit &= DBG_MASK;
	if (bit >= sizeof (px_debug_sym) / sizeof (char *))
		return;
	if (!(1ull << bit & px_debug_flags))
		return;
	if (cont)
		goto body;

	if (dip)
		prom_printf("%s(%d): %s: ", ddi_driver_name(dip),
		    ddi_get_instance(dip), px_debug_sym[bit]);
	else
		prom_printf("px: %s: ", px_debug_sym[bit]);
body:
	va_start(ap, fmt);
	prom_vprintf(fmt, ap);
	va_end(ap);
}
#endif	/* DEBUG */
