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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_CPU_MODULE_H
#define	_SYS_CPU_MODULE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cpuvar.h>
#include <sys/nvpair.h>
#include <sys/mc.h>

#ifdef __cplusplus
extern "C" {
#endif

struct regs;
struct cmi_mc_ops;

typedef struct cmi_mca_regs {
	uint_t cmr_msrnum;
	uint64_t cmr_msrval;
} cmi_mca_regs_t;

extern void cmi_init(void);
extern void cmi_post_init(void);
extern void cmi_post_mpstartup(void);

extern void cmi_faulted_enter(struct cpu *);
extern void cmi_faulted_exit(struct cpu *);
extern int cmi_scrubber_enable(struct cpu *, uint64_t, uint64_t);

extern void cmi_mca_init(void);
extern int cmi_mca_inject(cmi_mca_regs_t *, uint_t);
extern void cmi_mca_poke(void);

extern void cmi_mc_register(struct cpu *, const struct cmi_mc_ops *, void *);
extern int cmi_mc_patounum(uint64_t, uint32_t, int, mc_unum_t *);
extern int cmi_mc_unumtopa(mc_unum_t *, nvlist_t *, uint64_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_CPU_MODULE_H */
