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

#ifndef _SYS_XPV_PANIC_H
#define	_SYS_XPV_PANIC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

extern void xpv_panic_sti();
extern void xpv_panic_halt();
extern void xpv_panic_getcrs(ulong_t *);
extern void xpv_panic_setcr3(ulong_t);
extern void xpv_panic_reload_cr3();
extern ulong_t xpv_panic_resetgs();
extern void xpv_panic_init();
extern void xpv_panic_hdlr();
extern void *xpv_traceback(void *);

extern void xpv_div0trap(), xpv_dbgtrap(), xpv_nmiint(), xpv_brktrap();
extern void xpv_ovflotrap(), xpv_boundstrap(), xpv_invoptrap();
extern void xpv_ndptrap(), xpv_syserrtrap(), xpv_invaltrap();
extern void xpv_invtsstrap(), xpv_segnptrap(), xpv_stktrap();
extern void xpv_gptrap(), xpv_pftrap(), xpv_ndperr();
extern void xpv_overrun(), xpv_resvtrap();
extern void xpv_achktrap(), xpv_mcetrap();
extern void xpv_xmtrap(), xpv_timer_trap(), xpv_surprise_intr();

extern int dump_xpv_addr();
extern void dump_xpv_pfn();
extern int dump_xpv_data(void *);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_XPV_PANIC_H */
