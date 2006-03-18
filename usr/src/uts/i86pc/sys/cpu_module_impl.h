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

#ifndef _SYS_CPU_MODULE_IMPL_H
#define	_SYS_CPU_MODULE_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/cpu_module.h>
#include <sys/cpuvar.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cmi_mc_ops {
	int (*cmi_mc_patounum)(void *, uint64_t, uint32_t, int, mc_unum_t *);
	int (*cmi_mc_unumtopa)(void *, mc_unum_t *, nvlist_t *, uint64_t *);
} cmi_mc_ops_t;

typedef struct cmi_ops {
	int (*cmi_init)(cpu_t *, void **);
	void (*cmi_post_init)(void *);
	void (*cmi_post_mpstartup)(void *);
	void (*cmi_fini)(void *);
	void (*cmi_faulted_enter)(void *);
	void (*cmi_faulted_exit)(void *);
	int (*cmi_scrubber_enable)(void *, uint64_t, uint64_t);
	void (*cmi_mca_init)(void *);
	int (*cmi_mca_trap)(void *, struct regs *);
	int (*cmi_mca_inject)(void *, cmi_mca_regs_t *, uint_t);
	void (*cmi_mca_poke)(void *);
	void (*cmi_mc_register)(void *, const cmi_mc_ops_t *, void *);
	const struct cmi_mc_ops *(*cmi_mc_getops)(void *);
} cmi_ops_t;

typedef struct cmi {
	struct cmi *cmi_next;
	const cmi_ops_t *cmi_ops;
	struct modctl *cmi_modp;
	uint_t cmi_refcnt;
} cmi_t;

extern int cmi_panic_on_uncorrectable_error;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_CPU_MODULE_IMPL_H */
