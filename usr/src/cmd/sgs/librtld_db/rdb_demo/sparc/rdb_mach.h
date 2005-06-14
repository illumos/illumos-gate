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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _RDB_MACH_H
#define	_RDB_MACH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/psw.h>
#include <procfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ERRBIT	PSR_C

struct ps_prochandle;

/*
 * BreakPoint instruction
 */
typedef	unsigned	bptinstr_t;

#define	BPINSTR		0x91d02001	/* ta   ST_BREAKPOINT */

/*
 * PLT section type
 */
#define	PLTSECTT	SHT_PROGBITS

extern void		display_in_regs(struct ps_prochandle *,
				pstatus_t *);
extern void		display_local_regs(struct ps_prochandle *,
				pstatus_t *);
extern void		display_out_regs(struct ps_prochandle *,
				pstatus_t *);
extern void		display_special_regs(struct ps_prochandle *,
				pstatus_t *);
extern void		display_global_regs(struct ps_prochandle *,
				pstatus_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _RDB_MACH_H */
