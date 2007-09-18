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

#ifndef	_DBOOT_XBOOT_H
#define	_DBOOT_XBOOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mach_mmu.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/note.h>

/*
 * Stack used by xboot
 */
#define	STACK_SIZE	0x8000

#ifndef _ASM

extern paddr_t ktext_phys;
extern struct xboot_info *bi;

/*
 * Debugging macros
 */
extern uint_t prom_debug;

#define	DBG_MSG(s)	do { if (prom_debug)	\
	dboot_printf(s);			\
	_NOTE(CONSTANTCONDITION)		\
	} while (0)

#define	DBG(x)	do { if (prom_debug) {					\
	dboot_printf("%s is 0x%" PRIx64 "\n", #x, (uint64_t)(x));	\
	_NOTE(CONSTANTCONDITION)					\
	} } while (0)

extern void dboot_halt(void);
extern void *mem_alloc(uint32_t size);

#define	RNDUP(x, y)	((x) + ((y) - 1ul) & ~((y) - 1ul))

#endif /* _ASM */


#ifdef	__cplusplus
}
#endif

#endif	/* _DBOOT_XBOOT_H */
