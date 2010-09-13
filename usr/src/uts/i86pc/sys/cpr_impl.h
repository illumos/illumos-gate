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

#ifndef	_SYS_CPR_IMPL_H
#define	_SYS_CPR_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#ifndef _ASM

#include <sys/processor.h>
#include <sys/machparam.h>
#include <sys/vnode.h>
#include <sys/pte.h>

/*
 * This file contains machine dependent information for CPR
 */
#define	CPR_MACHTYPE_X86	0x5856		/* 'X'0t86 */
typedef uint64_t cpr_ptr;
typedef uint64_t cpr_ext;


/*
 * processor info
 */
struct i86pc_cpu_info {
	pnode_t node;
	processorid_t cpu_id;
};

extern void i_cpr_machdep_setup(void);
extern void i_cpr_enable_intr(void);
extern void i_cpr_stop_intr(void);
extern void i_cpr_handle_xc(int);
extern int i_cpr_check_cprinfo(void);
extern int i_cpr_reusable_supported(void);

#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CPR_IMPL_H */
